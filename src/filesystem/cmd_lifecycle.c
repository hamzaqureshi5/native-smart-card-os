/* SPDX-License-Identifier: MIT
 *
 * cmd_lifecycle.c -- ACTIVATE FILE (44) and DEACTIVATE FILE (04).
 *
 * ISO/IEC 7816-9. These are the commands that make a file's life cycle state
 * something a reader can change, rather than something only CREATE FILE could
 * set once and never revisit.
 *
 * WHAT THEY ARE FOR
 *
 * DEACTIVATE takes a file out of service without destroying it: reads and
 * writes are refused, the file and its contents remain. It is the reversible
 * half of the pair, which is exactly what makes it useful -- an application
 * can be suspended and resumed, where TERMINATED is one-way.
 *
 * THE SCOPE IMPLEMENTED, AND WHY IT IS A SUBSET
 *
 * P1 = 00, P2 = 00, no command data: act on the CURRENTLY SELECTED file.
 *
 * ISO/IEC 7816-9 also defines path- and identifier-based addressing for these
 * commands. Those are not implemented here and are refused with 6A86 rather
 * than guessed at, because the exact encoding of the data field is something
 * this project would be inventing rather than following -- the same rule that
 * keeps SELECT's P1 values a documented subset.
 *
 * "The currently selected file" means the current EF if one is selected, and
 * the current DF otherwise. That is the ISO reading and it is also the only
 * one that lets a DF be deactivated at all, since selecting a DF clears the
 * current EF.
 *
 * WHY THIS COMMAND FORCED A CHANGE ELSEWHERE
 *
 * Acting on the selected file requires that a deactivated file can BE
 * selected. Before this, fs.c refused to select anything not ACTIVATED, so
 * deactivation was a one-way door -- reachable by APDU, reversible only by
 * rewriting the descriptor from inside the OS. See resolve_selectable() in
 * src/filesystem/fs.c, which now separates "may be navigated to" from "may be
 * read and written", and ancestors_usable(), which makes deactivating a DF
 * genuinely block its subtree instead of only itself.
 *
 * NO ACCESS CONTROL. On a real card these are administrative commands behind
 * authentication. Here anyone holding the reader can deactivate any file.
 * Tracked in docs/threat-model.md against M3.
 */
#include "apdu/dispatch.h"
#include "apdu/sw.h"
#include "filesystem/fs.h"
#include "os/kernel.h"

/* Shared body. The two commands differ only in the target state, so they are
 * one function with a parameter rather than two near-copies that can drift. */
static uint16_t set_lifecycle(scos_kernel *k, const apdu_command *cmd,
                              fs_lifecycle want)
{
    if (k == NULL || cmd == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }
    if (k->lifecycle == SCOS_LC_FS_ERROR) {
        return SW_MEMORY_FAILURE;
    }

    /*
     * Only the "currently selected file" form. P1 or P2 non-zero means the
     * reader asked for path or identifier addressing, which this card does not
     * implement -- 6A86 "incorrect P1-P2" says so precisely, where a blanket
     * 6D00 would falsely claim the instruction itself is unknown.
     */
    if (cmd->p1 != 0x00u || cmd->p2 != 0x00u) {
        return SW_INCORRECT_P1P2; /* 6A86 */
    }

    /*
     * No command data. With P1-P2 both zero the target is the selection, so a
     * data field would be a file identifier the card is not reading -- and
     * accepting it silently would let a reader believe it had deactivated a
     * DIFFERENT file from the one that actually changed. That is the worst
     * possible failure for this command, so the data field is refused rather
     * than ignored.
     */
    if (cmd->lc != 0u) {
        return SW_LC_INCONSISTENT_P1P2; /* 6A87 */
    }
    if (cmd->le_present) {
        /* Neither command returns data. */
        return SW_WRONG_LENGTH; /* 6700 */
    }

    /* The current EF if there is one, else the current DF. */
    const uint16_t target =
        (k->sel.cur_ef != FS_INVALID_INDEX) ? k->sel.cur_ef : k->sel.cur_df;

    const fs_status st = fs_set_lifecycle(target, want);
    if (st != FS_OK) {
        return scos_fs_error_to_sw(st);
    }

    /*
     * The selection is NOT changed, and in particular a file just deactivated
     * stays selected.
     *
     * Clearing it would be the tempting tidy-up and it would break the pair:
     * the reader would have to re-select the file to reactivate it, and
     * selection of a deactivated file is precisely the thing that was broken
     * before this command existed. Leaving it selected makes
     * DEACTIVATE-then-ACTIVATE work without an intervening SELECT, which is
     * the sequence an administrator actually sends.
     */
    return SW_OK;
}

uint16_t scos_cmd_activate_file(scos_kernel *k, const apdu_command *cmd,
                                apdu_response *rsp)
{
    (void)rsp; /* no response data */
    return set_lifecycle(k, cmd, FS_LC_ACTIVATED);
}

uint16_t scos_cmd_deactivate_file(scos_kernel *k, const apdu_command *cmd,
                                  apdu_response *rsp)
{
    (void)rsp;
    return set_lifecycle(k, cmd, FS_LC_DEACTIVATED);
}
