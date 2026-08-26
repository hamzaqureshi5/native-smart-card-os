/* SPDX-License-Identifier: MIT
 *
 * kernel.c -- Command execution and the card's main loop.
 */
#include "os/kernel.h"

#include "apdu/apdu.h"
#include "apdu/dispatch.h"
#include "apdu/sw.h"
#include "filesystem/fs.h"
#include "os/os_mem.h"

scos_status scos_init(scos_kernel *k)
{
    if (k == NULL) {
        return SCOS_ERR_PARAM;
    }
    os_memset(k, 0, sizeof(*k));
    k->lifecycle = SCOS_LC_INITIALISING;

    /*
     * Mount the filesystem, personalising a blank chip.
     *
     * A card whose filesystem is corrupt or of an unknown layout version comes
     * up in FS_ERROR and answers 6581 to everything. It does NOT auto-format:
     * that would destroy the data most worth recovering, and would give an
     * attacker who can corrupt a single byte a reliable way to wipe the card.
     * Coming up dead and saying so is the safe failure.
     */
    const fs_status fst = fs_init();
    if (fst != FS_OK) {
        k->lifecycle = SCOS_LC_FS_ERROR;
        return SCOS_ERR_STATE;
    }

    fs_selection_reset(&k->sel);
    k->lifecycle = SCOS_LC_OPERATIONAL;
    return SCOS_OK;
}

void scos_reset(scos_kernel *k)
{
    if (k == NULL) {
        return;
    }
    const uint32_t resets = k->reset_count;

    /* A reset must clear ALL volatile security state. Today that is only the
     * current selection; from Milestone 3 it also drops PIN authentication,
     * and from Milestone 4 it rolls back any transaction that was open.
     * Zeroing the whole struct is the safe default: a new subsystem that adds
     * a member gets correct reset behaviour without anyone remembering to
     * update this function. */
    os_memset(k, 0, sizeof(*k));
    k->reset_count = resets + 1u;

    /* Back to the MF with no current EF. From M3 this also drops PIN
     * authentication -- so a reset can never be used to keep a privileged
     * selection while clearing a failure counter. */
    fs_selection_reset(&k->sel);
    k->lifecycle = SCOS_LC_OPERATIONAL;
}

scos_status scos_process(scos_kernel *k,
                         const uint8_t *cmd, uint16_t cmd_len,
                         uint8_t *rsp, uint16_t rsp_cap, uint16_t *rsp_len)
{
    if (k == NULL || rsp == NULL || rsp_len == NULL || rsp_cap < 2u) {
        /* Without two bytes we cannot answer at all; that is a platform bug,
         * not a protocol error. */
        return SCOS_ERR_PARAM;
    }
    *rsp_len = 0u;

    apdu_response r;
    apdu_rsp_init(&r, rsp, rsp_cap);

    if (k->lifecycle == SCOS_LC_TERMINATED) {
        /* A terminated card is a brick by design. It must still answer, so a
         * reader can tell "terminated" apart from "broken". */
        *rsp_len = apdu_rsp_finish(&r, SW_CONDITIONS_NOT_SATISFIED);
        return SCOS_OK;
    }
    if (k->lifecycle == SCOS_LC_FS_ERROR) {
        /* The card is intact but its filesystem is not. 6581 "memory failure"
         * distinguishes this from a policy refusal, which matters when
         * diagnosing a card in the field. */
        *rsp_len = apdu_rsp_finish(&r, SW_MEMORY_FAILURE);
        return SCOS_OK;
    }
    if (k->lifecycle != SCOS_LC_OPERATIONAL) {
        *rsp_len = apdu_rsp_finish(&r, SW_CONDITIONS_NOT_SATISFIED);
        return SCOS_OK;
    }

    /* --- 1. structural parse ------------------------------------------- */
    apdu_command c;
    const apdu_parse_status pst = apdu_parse(cmd, cmd_len, &c);
    if (pst != APDU_PARSE_OK) {
        *rsp_len = apdu_rsp_finish(&r, apdu_parse_status_sw(pst));
        return SCOS_OK;
    }

    /* --- 2. class check ------------------------------------------------ */
    const apdu_cla_status cst = apdu_check_cla(c.cla);
    if (cst != APDU_CLA_OK) {
        *rsp_len = apdu_rsp_finish(&r, apdu_cla_status_sw(cst));
        return SCOS_OK;
    }

    /* --- 3. dispatch --------------------------------------------------- */
    /* Order matters and is not arbitrary: structure, then class, then
     * instruction, then parameters, then security, then execution. A card that
     * checks security before structure can be probed with malformed APDUs; a
     * card that reports "INS not supported" before validating CLA leaks which
     * instructions exist in classes it does not serve. */
    const uint16_t sw = scos_dispatch(k, &c, &r);

    *rsp_len = apdu_rsp_finish(&r, sw);
    return SCOS_OK;
}
