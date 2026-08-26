/* SPDX-License-Identifier: MIT
 *
 * cmd_binary.c -- READ BINARY (B0) and UPDATE BINARY (D6),
 *                 ISO/IEC 7816-4 s.11.2.1 / s.11.2.2.
 *
 * These are the first commands that operate on "the current EF" rather than on
 * something named in the APDU. That statefulness is the essence of a smart
 * card: the reader establishes context with SELECT, then issues commands
 * against it. It is also why the selection rules in fs.c matter so much -- a
 * bug there silently redirects every read and write.
 *
 * THE P1-P2 ENCODING, which is easy to get wrong
 * ----------------------------------------------
 * ISO overloads P1/P2 with two different meanings, chosen by the top bit of P1:
 *
 *   b8 of P1 == 0:  P1||P2 is a 15-bit OFFSET into the current EF (0..32767).
 *                   Requires a current EF, else 6986.
 *
 *   b8 of P1 == 1:  b7 b6 must be 0, b5..b1 are a SHORT EF IDENTIFIER (1..30),
 *                   and P2 alone is the offset (0..255).
 *                   This selects the EF *implicitly* -- one APDU instead of a
 *                   SELECT followed by a READ. It is why files carry an SFI.
 *
 * Note the asymmetry that follows from the encoding: the SFI form can only
 * address the first 256 bytes of a file. That is ISO's constraint, not ours.
 */
#include "apdu/dispatch.h"
#include "apdu/sw.h"
#include "filesystem/fs.h"
#include "os/os_mem.h"

#define P1_SFI_FLAG 0x80u
#define P1_SFI_MASK 0x1Fu
#define P1_SFI_RFU  0x60u /* b7 b6: must be zero when the SFI form is used */

/*
 * Resolve which EF the command addresses, and the offset within it.
 * Returns SW_OK on success, or the status word to answer with.
 */
static uint16_t resolve_target(const scos_kernel *k, uint8_t p1, uint8_t p2,
                               uint16_t *out_index, uint16_t *out_offset)
{
    *out_index  = FS_INVALID_INDEX;
    *out_offset = 0u;

    if ((p1 & P1_SFI_FLAG) != 0u) {
        /* --- short EF identifier form --- */
        if ((p1 & P1_SFI_RFU) != 0u) {
            return SW_INCORRECT_P1P2; /* reserved bits must be zero */
        }
        const uint8_t sfi = (uint8_t)(p1 & P1_SFI_MASK);
        if (sfi == 0u) {
            /* SFI 0 is not a file reference; ISO reserves it to mean "the
             * current EF", which the offset form already covers. */
            return SW_INCORRECT_P1P2;
        }

        uint16_t index = FS_INVALID_INDEX;
        /* SFIs are scoped to the current DF, not global -- which is what stops
         * one application reaching another's files by short identifier. */
        const fs_status st = fs_find_by_sfi(k->sel.cur_df, sfi, &index);
        if (st != FS_OK) {
            return scos_fs_error_to_sw(st);
        }
        *out_index  = index;
        *out_offset = (uint16_t)p2;
        return SW_OK;
    }

    /* --- offset form: needs a current EF --- */
    if (k->sel.cur_ef == FS_INVALID_INDEX) {
        /* 6986 says exactly this: "command not allowed, no current EF". A
         * reader that gets it knows to issue a SELECT first. */
        return SW_COMMAND_NOT_ALLOWED_NO_EF;
    }
    *out_index  = k->sel.cur_ef;
    *out_offset = (uint16_t)(((uint16_t)p1 << 8) | (uint16_t)p2);
    return SW_OK;
}

uint16_t scos_cmd_read_binary(scos_kernel *k, const apdu_command *cmd,
                              apdu_response *rsp)
{
    if (k == NULL || cmd == NULL || rsp == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }

    /* READ BINARY carries no command data: it is Case 2 (header + Le). */
    if (cmd->lc != 0u) {
        return SW_LC_INCONSISTENT_P1P2; /* 6A87 */
    }
    if (!cmd->le_present) {
        /* Without Le the card does not know how much to return, and under T=0
         * the reader is not expecting data at all. */
        return SW_WRONG_LENGTH; /* 6700 */
    }

    uint16_t index  = FS_INVALID_INDEX;
    uint16_t offset = 0u;
    const uint16_t rsw = resolve_target(k, cmd->p1, cmd->p2, &index, &offset);
    if (rsw != SW_OK) {
        return rsw;
    }

    /* Le is 1..256, and the response buffer is sized for the maximum, so the
     * read cannot overflow it. Asserted rather than assumed. */
    uint8_t  buf[APDU_SHORT_LE_MAX];
    if (cmd->le > sizeof(buf)) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }

    uint16_t got = 0u;
    const fs_status st =
        fs_ef_read(index, offset, cmd->le, buf, &got);
    if (st != FS_OK) {
        return scos_fs_error_to_sw(st);
    }

    if (!apdu_rsp_put(rsp, buf, got)) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }

    /*
     * Short read. ISO/IEC 7816-4: when fewer bytes are available than Le, the
     * card returns what it has together with 6282, "end of file reached before
     * reading Le bytes". A warning, not an error -- the data in the response is
     * valid and the caller should use it.
     *
     * Returning 9000 here instead would be a small lie that a client cannot
     * detect, since it has no other way to learn the file was shorter.
     */
    if (got < cmd->le) {
        return SW_NVM_UNCHANGED_EOF; /* 6282 */
    }
    return SW_OK;
}

uint16_t scos_cmd_update_binary(scos_kernel *k, const apdu_command *cmd,
                                apdu_response *rsp)
{
    if (k == NULL || cmd == NULL || rsp == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }

    /* UPDATE BINARY is Case 3: header + Lc + data, and no response data. */
    if (cmd->lc == 0u || cmd->data == NULL) {
        return SW_WRONG_LENGTH; /* 6700 */
    }
    if (cmd->le_present) {
        /* An Le on a command that returns nothing is a caller error worth
         * reporting rather than ignoring. */
        return SW_WRONG_LENGTH;
    }

    uint16_t index  = FS_INVALID_INDEX;
    uint16_t offset = 0u;
    const uint16_t rsw = resolve_target(k, cmd->p1, cmd->p2, &index, &offset);
    if (rsw != SW_OK) {
        return rsw;
    }

    /*
     * ACCESS CONTROL IS NOT YET ENFORCED.
     *
     * Any reader that can reach this command can write any file. The
     * descriptor already carries ac_read/ac_update, and M3 enforces them here
     * and in READ BINARY. Until then this card protects nothing, which is
     * stated plainly in docs/filesystem.md and docs/threat-model.md rather
     * than left for someone to discover.
     */

    /* fs_ef_write() refuses a partial write outright: without transactions
     * there is no way to undo half of one. */
    const fs_status st = fs_ef_write(index, offset, cmd->lc, cmd->data);
    if (st != FS_OK) {
        return scos_fs_error_to_sw(st);
    }
    return SW_OK;
}
