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

/* ------------------------------------------------- pending response data -- */

void scos_pending_clear(scos_kernel *k)
{
    if (k == NULL) {
        return;
    }
    /* Zeroed, not merely marked empty. The buffer can hold file contents, and
     * from M5 it can hold key-derived material; leaving it in RAM after it has
     * been collected costs nothing to avoid. */
    os_memset(k->pending, 0, sizeof(k->pending));
    k->pending_len = 0u;
    k->pending_pos = 0u;
}

uint16_t scos_pending_remaining(const scos_kernel *k)
{
    if (k == NULL || k->pending_pos >= k->pending_len) {
        return 0u;
    }
    return (uint16_t)(k->pending_len - k->pending_pos);
}

uint16_t scos_stage_response(scos_kernel *k, const uint8_t *data, uint16_t n)
{
    if (k == NULL || data == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }
    if (n == 0u || n > (uint16_t)SCOS_PENDING_MAX) {
        /* A caller asking to stage nothing, or more than 61XX can announce, is
         * an OS bug. Reporting it as a protocol error would blame the reader
         * for something it did not do. */
        return SW_NO_PRECISE_DIAGNOSIS;
    }
    scos_pending_clear(k);
    if (!os_memcpy_checked(k->pending, (uint16_t)sizeof(k->pending), data, n)) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }
    k->pending_len = n;
    k->pending_pos = 0u;

    /* 61XX, where SW2 is the byte count and 00 means 256 -- so a full 256-byte
     * response is announced as 6100, not 6200. */
    return SW_MORE_DATA(n & 0xFFu);
}

scos_status scos_process(scos_kernel *k, const uint8_t *cmd, uint16_t cmd_len,
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
    apdu_command            c;
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

    /* --- 2b. drop any pending response --------------------------------- */
    /*
     * ISO/IEC 7816-4 requires GET RESPONSE to be the command IMMEDIATELY
     * following the 61XX that announced the data. Enforced here, in one place,
     * rather than in each handler -- a handler that forgot would leave an
     * earlier command's output collectable by a later one, possibly across a
     * change of selection or (from M3) of authentication state.
     *
     * Note this runs AFTER the parse and class checks, so a malformed frame or
     * a wrong CLA does not destroy pending data. Those never reached a command
     * handler, so from the reader's point of view no command intervened. A
     * card that dropped the data on a line error would make GET RESPONSE
     * unusable on a noisy link.
     */
    if (c.ins != INS_GET_RESPONSE) {
        scos_pending_clear(k);
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
