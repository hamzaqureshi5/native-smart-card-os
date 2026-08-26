/* SPDX-License-Identifier: MIT
 *
 * cmd_select.c -- SELECT (INS A4), ISO/IEC 7816-4 s.11.1.1.
 *
 * Now filesystem-backed. Compare with M1, where this file compared against one
 * hardcoded constant: the VALIDATION structure below is unchanged, and only
 * "resolve the target" grew a real implementation. That is the shape a
 * well-layered command handler is supposed to have.
 */
#include "apdu/dispatch.h"
#include "apdu/sw.h"
#include "filesystem/fs.h"
#include "os/os_mem.h"

/* --- P1: selection method (ISO 7816-4 table 39) -------------------------- */
#define SEL_BY_FID          0x00u
#define SEL_CHILD_DF        0x01u
#define SEL_CHILD_EF        0x02u
#define SEL_PARENT_DF       0x03u
#define SEL_BY_DF_NAME      0x04u /* by AID -- deferred to M7 (Card Manager) */
#define SEL_BY_PATH_FROM_MF 0x08u
#define SEL_BY_PATH_FROM_DF 0x09u

/* --- P2: occurrence (b2b1) and response template (b4b3) ------------------ */
#define SEL_OCC_MASK  0x03u
#define SEL_OCC_FIRST 0x00u
#define SEL_RET_MASK  0x0Cu
#define SEL_RET_FCI   0x00u /* FCI, template 6F  */
#define SEL_RET_FCP   0x04u /* FCP, template 62  */
#define SEL_RET_FMD   0x08u /* FMD, template 64  */
#define SEL_RET_NONE  0x0Cu /* no response data  */

/*
 * Map a filesystem error onto an ISO status word.
 *
 * DESIGN DECISION, revisit in M3: "not found" (6A82) and "not usable" (6985)
 * are DISTINGUISHABLE. Merging them would hide whether a deactivated file
 * exists, which is friendlier to an attacker mapping the card and much harder
 * to debug against. Real cards ship both ways; we choose diagnosable, and
 * revisit when access conditions arrive and the trade-off becomes real.
 */
static uint16_t fs_error_to_sw(fs_status st)
{
    switch (st) {
    case FS_OK:                   return SW_OK;
    case FS_ERR_NOT_FOUND:        return SW_FILE_NOT_FOUND;             /* 6A82 */
    case FS_ERR_NOT_USABLE:       return SW_CONDITIONS_NOT_SATISFIED;   /* 6985 */
    case FS_ERR_WRONG_TYPE:       return SW_CMD_INCOMPATIBLE_FILE;      /* 6981 */
    case FS_ERR_RANGE:            return SW_WRONG_P1P2;                 /* 6B00 */
    case FS_ERR_PARAM:            return SW_INCORRECT_P1P2;             /* 6A86 */
    case FS_ERR_NO_SPACE:         return SW_NOT_ENOUGH_SPACE;           /* 6A84 */
    case FS_ERR_EXISTS:           return SW_FILE_ALREADY_EXISTS;        /* 6A89 */
    case FS_ERR_CORRUPT:
    case FS_ERR_VERSION:
    case FS_ERR_NOT_FORMATTED:
        /* A structurally broken card. 6581 ("memory failure") is the honest
         * answer: the command did not fail because of anything the caller did. */
        return SW_MEMORY_FAILURE;                                       /* 6581 */
    case FS_ERR_NVM:              return SW_MEMORY_FAILURE;             /* 6581 */
    default:                      return SW_NO_PRECISE_DIAGNOSIS;       /* 6F00 */
    }
}

uint16_t scos_fs_error_to_sw(fs_status st) { return fs_error_to_sw(st); }

/* Append the selected file's control information, wrapped in the template the
 * caller asked for. */
static uint16_t emit_fci(const apdu_command *cmd, apdu_response *rsp,
                         uint16_t index, uint8_t ret_opt)
{
    if (ret_opt == SEL_RET_NONE) {
        return SW_OK;
    }
    if (ret_opt == SEL_RET_FMD) {
        /* File Management Data is issuer-specific and we hold none. Returning
         * an empty 64 template would assert "this file has no management data"
         * rather than "this card does not implement FMD". */
        return SW_FUNC_NOT_SUPPORTED; /* 6A81 */
    }

    fs_descriptor d;
    const fs_status st = fs_get(index, &d);
    if (st != FS_OK) {
        return fs_error_to_sw(st);
    }

    uint8_t  body[32];
    const uint16_t body_len = fs_build_fcp(&d, body, (uint16_t)sizeof(body));
    if (body_len == 0u) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }

    const uint8_t template_tag = (ret_opt == SEL_RET_FCP) ? 0x62u : 0x6Fu;

    /*
     * Le handling.
     *
     * With no Le (a Case 3 SELECT) the card cannot return data at all: under
     * T=0 the reader is not expecting any. ISO's mechanism for that is to
     * answer 61XX and let the reader fetch it with GET RESPONSE -- which is
     * M2b. Until then a Case 3 SELECT succeeds with no data, which is
     * well-defined and is what the M1 test expects.
     */
    if (!cmd->le_present) {
        return SW_OK;
    }

    const uint16_t total = (uint16_t)(body_len + 2u); /* tag + length byte */
    if (cmd->le < total) {
        /* ISO: tell the caller the exact length it should have asked for.
         * 6CXX is far more useful than truncating or refusing outright. */
        return SW_WRONG_LE(total);
    }

    if (!apdu_rsp_put_u8(rsp, template_tag) ||
        !apdu_rsp_put_u8(rsp, (uint8_t)body_len) ||
        !apdu_rsp_put(rsp, body, body_len)) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }
    return SW_OK;
}

uint16_t scos_cmd_select(scos_kernel *k, const apdu_command *cmd,
                         apdu_response *rsp)
{
    if (k == NULL || cmd == NULL || rsp == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }

    /* --- validate P2 before doing any work ------------------------------- */
    if ((cmd->p2 & 0xF0u) != 0x00u) {
        return SW_INCORRECT_P1P2; /* b8..b5 reserved, must be zero */
    }
    if ((cmd->p2 & SEL_OCC_MASK) != SEL_OCC_FIRST) {
        /* "next occurrence" needs duplicate identifiers to iterate over. Our
         * tree cannot contain two children of one DF with the same FID, so
         * there is never a second occurrence to find. */
        return SW_FUNC_NOT_SUPPORTED;
    }
    const uint8_t ret_opt = cmd->p2 & SEL_RET_MASK;

    /*
     * Work on a COPY of the selection and commit only on success.
     *
     * ISO requires a failed SELECT to leave the current selection intact, and
     * there is a security reason beyond conformance: a card that cleared its
     * selection on a failed lookup would let an attacker reset the security
     * context with a garbage APDU. The path forms make this essential rather
     * than merely tidy -- they can fail half way through a walk.
     */
    fs_selection sel = k->sel;
    fs_status    st  = FS_ERR_PARAM;

    switch (cmd->p1) {
    case SEL_BY_FID: {
        if (cmd->lc == 0u) {
            /* Absent data field with P1=00 means "select the MF". */
            st = fs_select_by_fid(&sel, FS_FID_MF);
        } else if (cmd->lc == 2u) {
            if (cmd->data == NULL) {
                return SW_NO_PRECISE_DIAGNOSIS;
            }
            const uint16_t fid =
                (uint16_t)(((uint16_t)cmd->data[0] << 8) | cmd->data[1]);
            st = fs_select_by_fid(&sel, fid);
        } else {
            return SW_LC_INCONSISTENT_P1P2; /* 6A87 */
        }
        break;
    }

    case SEL_CHILD_DF:
    case SEL_CHILD_EF: {
        if (cmd->lc != 2u || cmd->data == NULL) {
            return SW_LC_INCONSISTENT_P1P2;
        }
        const uint16_t fid =
            (uint16_t)(((uint16_t)cmd->data[0] << 8) | cmd->data[1]);
        st = (cmd->p1 == SEL_CHILD_DF) ? fs_select_child_df(&sel, fid)
                                       : fs_select_child_ef(&sel, fid);
        break;
    }

    case SEL_PARENT_DF: {
        if (cmd->lc != 0u) {
            /* Selecting the parent needs no operand; data would be meaningless
             * and accepting it silently would hide a caller's mistake. */
            return SW_LC_INCONSISTENT_P1P2;
        }
        st = fs_select_parent(&sel);
        break;
    }

    case SEL_BY_PATH_FROM_MF:
    case SEL_BY_PATH_FROM_DF: {
        if (cmd->lc == 0u || cmd->data == NULL) {
            return SW_LC_INCONSISTENT_P1P2;
        }
        if ((cmd->lc % 2u) != 0u) {
            /* A path is a whole number of 2-byte identifiers. */
            return SW_WRONG_DATA; /* 6A80 */
        }
        st = fs_select_by_path(&sel, cmd->data, cmd->lc,
                              cmd->p1 == SEL_BY_PATH_FROM_MF);
        break;
    }

    case SEL_BY_DF_NAME:
        /* Selection by application identifier (AID). AIDs are registered by
         * the Card Manager, which does not exist yet -- so there is nothing to
         * search. Deferred to M7 rather than faked. */
        return SW_FUNC_NOT_SUPPORTED; /* 6A81 */

    default:
        return SW_INCORRECT_P1P2; /* 6A86 */
    }

    if (st != FS_OK) {
        return fs_error_to_sw(st);
    }

    /* Build the response BEFORE committing: if the caller's Le is too small we
     * return 6CXX, and ISO treats that as a command that did not execute, so
     * the selection must not have moved. */
    const uint16_t index = fs_selected_index(&sel);
    const uint16_t sw    = emit_fci(cmd, rsp, index, ret_opt);
    if (sw != SW_OK) {
        return sw;
    }

    k->sel = sel; /* commit */
    return SW_OK;
}
