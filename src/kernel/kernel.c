/* SPDX-License-Identifier: MIT
 *
 * kernel.c -- Command execution and the card's main loop.
 */
#include "os/kernel.h"
#include "os/journal.h"
#include "security/pin.h"

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
    /*
     * RECOVERY FIRST, before anything reads a filesystem structure.
     *
     * If power went mid-transaction, the descriptor table and the superblock
     * may disagree with each other right now. Mounting first would mean
     * fs_init() validating a state that recovery is about to change -- and, in
     * the worst case, deciding the card is corrupt and refusing to come up,
     * when the card was recoverable all along.
     *
     * A recovery failure is reported the same way a filesystem failure is: the
     * card comes up answering 6581 and does NOT silently proceed. A card that
     * could not undo an interrupted transaction has data of unknown
     * consistency, and the one thing it must not do is behave as though it
     * does not.
     */
    if (scos_txn_recover() != SCOS_TXN_OK) {
        k->lifecycle = SCOS_LC_FS_ERROR;
        return SCOS_ERR_STATE;
    }

    const fs_status fst = fs_init();
    if (fst != FS_OK) {
        k->lifecycle = SCOS_LC_FS_ERROR;
        return SCOS_ERR_STATE;
    }

    /*
     * Mount the security store, formatting a blank one.
     *
     * AFTER the filesystem and reported the same way: a card whose PIN records
     * are corrupt is not a card that should answer commands as if they were
     * fine. It comes up in FS_ERROR -- the name is now slightly narrow, but
     * the behaviour is right: 6581 to everything, no silent reformat. Silently
     * re-formatting the security store would reset a blocked PIN to unset,
     * which is an attacker's preferred outcome.
     */
    const pin_status pst = pin_init();
    if (pst != PIN_OK) {
        k->lifecycle = SCOS_LC_FS_ERROR;
        return SCOS_ERR_STATE;
    }

    fs_selection_reset(&k->sel);
    k->auth      = 0u;
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
    /*
     * THE COMMAND IS THE UNIT OF ATOMICITY.
     *
     * Every command runs inside a transaction, so a command that writes several
     * NVM structures either writes all of them or none. CREATE FILE is the
     * clearest case: it writes a descriptor AND updates the superblock's
     * allocation pointer, and a card that lost power between them would come
     * back with a file pointing at bytes belonging to nobody and every later
     * allocation wrong.
     *
     * Wrapped HERE, once, rather than inside each fs_* function. A handler
     * cannot forget to open a transaction it never opens, and the alternative
     * -- per-function transactions -- also makes nesting inevitable the first
     * time one command calls two of them.
     *
     * A failure to begin is NOT ignored. Running the command unprotected
     * because the journal was unavailable would give a caller success for an
     * operation a power cut can now corrupt, which is the outcome this whole
     * milestone exists to prevent.
     */
    const bool txn = (scos_txn_begin() == SCOS_TXN_OK);
    if (!txn) {
        *rsp_len = apdu_rsp_finish(&r, SW_MEMORY_FAILURE);
        return SCOS_OK;
    }

    const uint16_t sw = scos_dispatch(k, &c, &r);

    /*
     * Commit or roll back, decided by ISO's own categorisation of SW1 rather
     * than by a per-handler flag that a handler could set wrongly:
     *
     *   90, 61      success
     *   62, 63      WARNING -- the command executed. 6282 "end of file" and
     *               63CX "tries remaining" both describe work that happened,
     *               and rolling either back would be wrong: 63CX in particular
     *               would restore a spent PIN attempt.
     *   everything  error. Nothing should have been written, and if something
     *   else        was -- a multi-write that failed half way -- this is what
     *               undoes it.
     *
     * The PIN retry counter is deliberately OUTSIDE this: commit_tally() in
     * src/security/pin.c writes with hal_nvm_write() directly, bypassing the
     * journal. That was originally about keeping the decrement to a single
     * atomic byte, and it is now load-bearing for a second reason -- a failed
     * VERIFY returns 63CX or 6983, and if the counter were journaled at
     * command scope the abort path would hand the attempt back. That is
     * exactly the attack M3 was built to stop, reintroduced by an unrelated
     * mechanism. The 62/63 rule above means a journaled counter would survive
     * 63CX but NOT 6983, which is worse than either: the last attempt would be
     * the one restored.
     */
    const uint8_t sw1 = (uint8_t)(sw >> 8);
    const bool    executed =
        (sw1 == 0x90u) || (sw1 == 0x61u) || (sw1 == 0x62u) || (sw1 == 0x63u);

    uint16_t final = sw;
    if (executed) {
        /*
         * A FAILED COMMIT MUST NOT REPORT SUCCESS.
         *
         * The first version discarded this result, and the two-dimensional
         * interruption sweep caught it: a write cut during commit left the
         * transaction OPEN -- so the next boot would roll the whole command
         * back -- while the card answered 9000. The caller would believe a file
         * had been created that vanished at the next power-on, which is the
         * worst kind of failure this milestone can produce, because nothing
         * anywhere records that it happened.
         *
         * 6581: the card failed, not the caller. The data is not lost -- it is
         * exactly as durable as the journal says, and recovery will make the
         * card consistent -- but the operation did not happen.
         */
        if (scos_txn_commit() != SCOS_TXN_OK) {
            final = SW_MEMORY_FAILURE;
        }
    } else {
        /*
         * The handler already failed, so `sw` is diagnostic and kept. But if
         * the rollback ALSO failed, the card's data is of unknown consistency
         * and the caller should be told that rather than the original,
         * narrower error -- and the journal deliberately stays open so the
         * next boot retries.
         */
        if (scos_txn_abort() != SCOS_TXN_OK) {
            final = SW_MEMORY_FAILURE;
        }
    }

    *rsp_len = apdu_rsp_finish(&r, final);
    return SCOS_OK;
}
