/* SPDX-License-Identifier: MIT
 *
 * cmd_create.c -- CREATE FILE (INS E0) and DELETE FILE (INS E4),
 *                 ISO/IEC 7816-9 s.11.1 and s.11.3.
 *
 * ============================================================================
 * NEITHER COMMAND IS ACCESS-CONTROLLED.
 *
 * On a real card these are administrative commands, reachable only after
 * authenticating -- a PIN, or far more usually a secure channel to a security
 * domain that is allowed to manage the file tree. Here, anyone holding the
 * reader can create files and delete them. That is the boot loader's hole one
 * layer up, and it is tracked in docs/threat-model.md.
 *
 * Every refusal below is a STRUCTURAL INTEGRITY check -- "this would make the
 * tree inconsistent" -- not a security check. The distinction matters: an
 * integrity check protects the card from a confused client, and does nothing
 * whatsoever against a hostile one.
 * ============================================================================
 *
 * WHY THIS IS THE FIRST COMMAND THAT PARSES A TEMPLATE
 *
 * Everything before it consumed fixed-shape data: two bytes of file
 * identifier, a length and an offset. CREATE FILE consumes a BER-TLV FCP
 * template, which is variable-length, nested, and entirely attacker-chosen.
 * That is why src/apdu/tlv.c was written first and swept exhaustively over
 * every possible three-byte input before anything called it.
 *
 * The one rule that shapes this file: UNKNOWN TAGS ARE REJECTED, not ignored.
 * Ignoring them is the friendlier-looking choice and it is the wrong one --
 * tag 86 and tag 8C carry security attributes, so a card that ignores what it
 * does not understand would happily accept "create this file, PIN-protected"
 * and create an unprotected file while answering 9000. Refusing with 6A80
 * tells the client the truth.
 */
#include "apdu/dispatch.h"
#include "apdu/sw.h"
#include "apdu/tlv.h"
#include "filesystem/fs.h"
#include "security/ac.h"
#include "os/os_mem.h"

/* --- FCP tags we accept (ISO/IEC 7816-4 table 12) ------------------------- */
#define TAG_FCP_TEMPLATE 0x62u /* the wrapper                                */
#define TAG_FILE_DESC    0x82u /* file descriptor byte                       */
#define TAG_FILE_ID      0x83u /* file identifier                            */
#define TAG_DATA_BYTES   0x80u /* number of data bytes, EF only              */
#define TAG_LIFE_CYCLE   0x8Au /* life cycle status byte                     */
#define TAG_SFI          0x88u /* short EF identifier                        */
#define TAG_SEC_PROP     0x86u /* security attributes, PROPRIETARY format     */
#define TAG_SEC_COMPACT  0x8Cu /* security attributes, ISO compact format     */

/* --- file descriptor byte fields (ISO/IEC 7816-4 s.5.3.3) ----------------- */
#define FDB_RFU_BIT      0x80u /* b8, must be 0                              */
#define FDB_SHAREABLE    0x40u /* b7                                         */
#define FDB_TYPE_MASK    0x38u /* b6 b5 b4                                   */
#define FDB_TYPE_WORKING 0x00u /*   000 working EF                           */
#define FDB_TYPE_DF      0x38u /*   111 DF                                   */
#define FDB_STRUCT_MASK  0x07u /* b3 b2 b1                                   */
#define FDB_STRUCT_NONE  0x00u /*   000 no information                       */
#define FDB_STRUCT_TRANS 0x01u /*   001 transparent                          */

/*
 * Decode the file descriptor byte into our internal type.
 *
 * The inverse of fs_iso_descriptor_byte(), and deliberately stricter than it:
 * that function only ever emits the two encodings we support, whereas this one
 * is handed arbitrary bytes. Anything we cannot implement is refused rather
 * than approximated -- creating a linear-fixed EF as a transparent one because
 * transparent is all we have would be a silent lie about the file's structure.
 */
typedef enum {
    FDB_ACCEPTED = 0,
    FDB_MALFORMED,  /* violates the encoding: answer 6A80          */
    FDB_UNSUPPORTED /* a valid ISO type we do not implement: 6A81  */
} fdb_result;

static fdb_result decode_fdb(uint8_t fdb, fs_file_type *out_type)
{
    /* b8 is reserved and must be 0. That is a malformed byte, not a file type
     * we happen to lack -- and the difference is worth reporting, because a
     * client that gets 6A81 will go looking for a card that supports the
     * feature, whereas 6A80 tells it to look at its own encoding. */
    if ((fdb & FDB_RFU_BIT) != 0u) {
        return FDB_MALFORMED;
    }
    /* Shareability is accepted and then ignored: it only means anything once
     * more than one logical channel or applet exists, and neither does yet.
     * Ignoring it is safe in a way that ignoring a security tag is not -- the
     * conservative reading (not shareable) is what a single-channel card
     * already enforces by construction. */
    const uint8_t type = fdb & FDB_TYPE_MASK;
    const uint8_t stru = fdb & FDB_STRUCT_MASK;

    if (type == FDB_TYPE_DF) {
        if (stru != FDB_STRUCT_NONE) {
            /* A DF carrying an EF structure is self-contradictory, not
             * something ISO defines and we lack. */
            return FDB_MALFORMED;
        }
        *out_type = FS_TYPE_DF;
        return FDB_ACCEPTED;
    }
    if (type == FDB_TYPE_WORKING && stru == FDB_STRUCT_TRANS) {
        *out_type = FS_TYPE_EF_TRANSPARENT;
        return FDB_ACCEPTED;
    }
    /* Internal EFs (001), and every record-structured EF, are real ISO file
     * types we simply do not implement. */
    return FDB_UNSUPPORTED;
}

/*
 * Parse an FCP into a descriptor request.
 *
 * Returns the status word to answer with, or 0x9000 on success. `req` is
 * fully initialised on success and untouched-but-zeroed otherwise.
 */
static uint16_t parse_fcp(const uint8_t *body, uint16_t body_len,
                          fs_descriptor *req)
{
    os_memset(req, 0, sizeof(*req));
    req->parent    = FS_NO_PARENT;
    req->sfi       = FS_NO_SFI;
    req->lifecycle = FS_LC_ACTIVATED; /* default if tag 8A is absent */

    /*
     * Default access conditions when tag 86 is absent: ALWAYS.
     *
     * This is the permissive default and it deserves saying out loud. A file
     * created without a security attribute is unprotected, which is what every
     * file on this card was before access conditions existed -- so the default
     * preserves existing behaviour rather than silently locking out callers
     * that never asked for protection.
     *
     * The safer-looking default, NEVER, would make every file created without
     * an 86 template permanently unreachable, including by the caller that
     * just made it. A card that refuses to read a file it was told nothing
     * about is not more secure, it is broken -- and it would push callers
     * toward whatever incantation made the refusal stop, which is how a
     * protection mechanism gets routed around.
     *
     * The honest mitigation is that an issuer sets conditions explicitly, and
     * that the ones on the factory files are set in fs_personalise().
     */
    req->ac_read     = FS_AC_ALWAYS;
    req->ac_update   = FS_AC_ALWAYS;
    req->ac_admin    = FS_AC_ALWAYS;
    req->data_offset = 0u;

    /*
     * The FCP may arrive wrapped in tag 62 or bare. ISO/IEC 7816-9 specifies
     * the wrapper; accepting both is not laxity -- real cards and real tools
     * differ here, and the inner content is validated identically either way,
     * so the wrapper's presence changes nothing about what we will accept.
     */
    const uint8_t *inner     = body;
    uint16_t       inner_len = body_len;

    tlv_reader outer;
    tlv_object obj;
    tlv_reader_init(&outer, body, body_len);
    if (tlv_next(&outer, &obj) == TLV_OK && obj.tag == TAG_FCP_TEMPLATE) {
        if (!tlv_reader_done(&outer)) {
            /* Something follows the template. We would not know which one to
             * honour, so we honour neither. */
            return SW_WRONG_DATA;
        }
        inner     = obj.value;
        inner_len = obj.length;
    }
    if (inner_len == 0u) {
        return SW_WRONG_DATA;
    }

    bool         have_fdb  = false;
    bool         have_fid  = false;
    bool         have_size = false;
    fs_file_type type      = FS_TYPE_FREE;

    tlv_reader r;
    tlv_reader_init(&r, inner, inner_len);
    for (;;) {
        const tlv_status ts = tlv_next(&r, &obj);
        if (ts == TLV_END) {
            break;
        }
        if (ts != TLV_OK) {
            return SW_WRONG_DATA;
        }

        /* Every tag we accept appears at most once. A repeated tag is
         * ambiguous -- first or last wins? -- so it is refused rather than
         * resolved by an arbitrary rule. */
        uint32_t v = 0u;
        switch (obj.tag) {
        case TAG_FILE_DESC: {
            if (have_fdb || obj.length != 1u) {
                return SW_WRONG_DATA;
            }
            const fdb_result fr = decode_fdb(obj.value[0], &type);
            if (fr == FDB_MALFORMED) {
                return SW_WRONG_DATA;
            } /* 6A80 */
            if (fr == FDB_UNSUPPORTED) {
                return SW_FUNC_NOT_SUPPORTED;
            } /* 6A81 */
            have_fdb = true;
            break;
        }

        case TAG_FILE_ID:
            if (have_fid || obj.length != 2u) {
                return SW_WRONG_DATA;
            }
            req->file_id =
                (uint16_t)(((uint16_t)obj.value[0] << 8) | obj.value[1]);
            have_fid = true;
            break;

        case TAG_DATA_BYTES:
            if (have_size) {
                return SW_WRONG_DATA;
            }
            if (tlv_get_uint(&obj, &v) != TLV_OK) {
                return SW_WRONG_DATA;
            }
            if (v > FS_MAX_EF_SIZE) {
                /* Distinguished from a malformed template: the request is
                 * well-formed, the card just cannot hold that much. */
                return SW_NOT_ENOUGH_SPACE;
            }
            /* A zero-length EF is refused. ISO does not forbid it, but every
             * read of it would be a short read of nothing and every write out
             * of range, so it can only confuse a client. Caught HERE rather
             * than in fs_create_file() so the answer is 6A80 (bad data field)
             * and not 6A86 (bad P1-P2) -- the fault really is in the data. */
            if (v == 0u) {
                return SW_WRONG_DATA;
            }
            req->size = (uint16_t)v;
            have_size = true;
            break;

        case TAG_LIFE_CYCLE:
            if (obj.length != 1u) {
                return SW_WRONG_DATA;
            }
            switch ((fs_lifecycle)obj.value[0]) {
            case FS_LC_CREATION:
            case FS_LC_INITIALISED:
            case FS_LC_ACTIVATED:
            case FS_LC_DEACTIVATED:
                req->lifecycle = (fs_lifecycle)obj.value[0];
                break;
            case FS_LC_TERMINATED:
                /* Irreversible, and creating something already dead is almost
                 * certainly a client bug. Refuse rather than honour it. */
                return SW_WRONG_DATA;
            default:
                return SW_WRONG_DATA;
            }
            break;

        case TAG_SFI:
            if (obj.length != 1u) {
                return SW_WRONG_DATA;
            }
            /* ISO puts the SFI in b8..b4 of the value byte, so it is shifted
             * left by 3 -- the same encoding fs_build_fcp emits. b3..b1 are
             * reserved and must be 0. */
            if ((obj.value[0] & 0x07u) != 0u) {
                return SW_WRONG_DATA;
            }
            req->sfi = (uint8_t)(obj.value[0] >> 3);
            /* 0 encodes "no SFI", which is legal. 31 is out of the 1..30 range
             * ISO defines and cannot be addressed by READ BINARY's 5-bit
             * field, so it is a data error rather than something to clamp. */
            if (req->sfi > 30u) {
                return SW_WRONG_DATA;
            }
            break;

        case TAG_SEC_PROP:
            /*
             * Security attributes, proprietary format -- and the format is
             * ours, which is exactly what ISO reserves tag 86 for. Three
             * bytes: read, update, admin. See the FS_AC_* block in
             * include/filesystem/fs_types.h for the encoding and for why this
             * tag rather than 8C.
             *
             * Exactly three, not "up to three": a two-byte value would leave
             * ac_admin at its permissive default while looking like it had
             * been configured, which is the kind of near-miss that produces an
             * unprotected file and a satisfied caller.
             */
            if (obj.length != 3u) {
                return SW_WRONG_DATA;
            }
            /*
             * Every byte must be one this card can evaluate, checked BEFORE it
             * reaches NVM. A stored condition the card could not interpret
             * would have to be treated as NEVER -- the only safe reading --
             * and the file would be permanently unreachable for a reason
             * nothing could explain. Refusing at creation turns that into an
             * immediate 6A80 with the template in front of the caller.
             */
            for (unsigned b = 0; b < 3u; b++) {
                if (!fs_ac_is_known(obj.value[b])) {
                    return SW_WRONG_DATA;
                }
            }
            req->ac_read   = obj.value[0];
            req->ac_update = obj.value[1];
            req->ac_admin  = obj.value[2];
            break;

        case TAG_SEC_COMPACT:
            /*
             * ISO's compact format. NOT implemented, and refused with 6A81
             * "function not supported" rather than approximated.
             *
             * Its access-mode byte assigns specific bits to specific
             * operations, and this project does not have the specification
             * text to state those positions precisely. A card that accepted an
             * 8C template while misreading which operation each bit protected
             * would create a file whose protection is not the protection that
             * was requested -- and would answer 9000 while doing it. 6A81 is
             * the truthful answer: the card understands the tag and does not
             * implement it. Use tag 86.
             */
            return SW_FUNC_NOT_SUPPORTED;

        default:
            /* Unknown tags are REFUSED, not ignored. A file created from a
             * template the card only partly understood is a file whose
             * properties are not the ones that were asked for. */
            return SW_WRONG_DATA;
        }
    }

    if (!have_fdb || !have_fid) {
        return SW_WRONG_DATA;
    }
    req->type = type;

    /* Cross-field consistency. fs_create_file() checks these too -- it has to,
     * since it is callable from anywhere -- but checking here lets us answer
     * with a status word that says which field was wrong. */
    if (type == FS_TYPE_EF_TRANSPARENT && !have_size) {
        return SW_WRONG_DATA; /* an EF with no declared size */
    }
    if (type == FS_TYPE_DF && have_size) {
        return SW_WRONG_DATA; /* a DF has no data bytes */
    }
    if (type == FS_TYPE_DF && req->sfi != FS_NO_SFI) {
        return SW_WRONG_DATA; /* an SFI addresses an EF, never a DF */
    }
    return SW_OK;
}

/* ---------------------------------------------------------- CREATE FILE --- */

uint16_t scos_cmd_create_file(scos_kernel *k, const apdu_command *cmd,
                              apdu_response *rsp)
{
    (void)rsp; /* Case 3: no response data. See below. */

    if (k == NULL || cmd == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }
    if (k->lifecycle == SCOS_LC_FS_ERROR) {
        return SW_MEMORY_FAILURE;
    }
    /* ISO/IEC 7816-9 defines P1-P2 = '0000' for CREATE FILE. Other values are
     * reserved, so accepting them would make future meanings unavailable.
     * 6A86 rather than 6B00: both mean "bad P1-P2", but 6A86 is the one ISO
     * pairs with a command that has a data field, and it is what SELECT
     * already returns here, so a client sees one convention. */
    if (cmd->p1 != 0x00u || cmd->p2 != 0x00u) {
        return SW_INCORRECT_P1P2;
    }
    if (cmd->lc == 0u || cmd->data == NULL) {
        return SW_WRONG_LENGTH;
    }

    fs_descriptor  req;
    const uint16_t sw = parse_fcp(cmd->data, cmd->lc, &req);
    if (sw != SW_OK) {
        return sw;
    }

    /*
     * CREATE is gated on the PARENT DF's admin condition, not on anything in
     * the template being created.
     *
     * Creating a file modifies the directory, so the directory is the thing
     * whose protection applies -- and it is the only file that exists at this
     * point to have a condition. Reading it from the template instead would let
     * a caller authorise its own request, which is not a check.
     */
    {
        fs_descriptor   parent;
        const fs_status gst = fs_get(k->sel.cur_df, &parent);
        if (gst != FS_OK) {
            return scos_fs_error_to_sw(gst);
        }
        if (!scos_ac_permits(k->auth, &parent, AC_OP_ADMIN)) {
            return SW_SECURITY_NOT_SATISFIED; /* 6982 */
        }
    }

    uint16_t        index = FS_INVALID_INDEX;
    const fs_status st    = fs_create_file(&k->sel, &req, &index);
    if (st != FS_OK) {
        return scos_fs_error_to_sw(st);
    }

    /*
     * No response data, and the selection is unchanged.
     *
     * ISO/IEC 7816-9 permits a card to select the file it just created. We do
     * not, because a command that quietly moves the current EF turns the
     * client's next UPDATE BINARY into a write to a different file than it
     * thinks. The client can SELECT it explicitly; that costs one APDU and
     * removes a whole class of mistake.
     */
    return SW_OK;
}

/* ---------------------------------------------------------- DELETE FILE --- */

uint16_t scos_cmd_delete_file(scos_kernel *k, const apdu_command *cmd,
                              apdu_response *rsp)
{
    (void)rsp;

    if (k == NULL || cmd == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }
    if (k->lifecycle == SCOS_LC_FS_ERROR) {
        return SW_MEMORY_FAILURE;
    }
    if (cmd->p1 != 0x00u || cmd->p2 != 0x00u) {
        return SW_INCORRECT_P1P2;
    }

    /*
     * The file identifier is REQUIRED in the data field.
     *
     * ISO also allows a form with no data, meaning "delete the currently
     * selected file". We do not accept it. Deletion is irreversible and the
     * current selection is implicit state a client can easily be wrong about;
     * requiring the identifier means a client that has lost track of the
     * selection gets 6A82 instead of destroying the wrong file.
     */
    if (cmd->lc != 2u || cmd->data == NULL) {
        return SW_WRONG_LENGTH;
    }
    const uint16_t fid =
        (uint16_t)(((uint16_t)cmd->data[0] << 8) | cmd->data[1]);

    /*
     * DELETE is gated on the admin condition of the file being DESTROYED, not
     * of its parent.
     *
     * The parent would be the consistent choice with CREATE, and it is the
     * wrong one here: it would mean a single condition on a DF governed the
     * destruction of every file inside it, so a file could be protected
     * against being read and unprotected against being deleted. Destruction
     * should be at least as hard as reading.
     *
     * The file must be resolved before the check, and resolving it is also how
     * a nonexistent identifier answers 6A82 rather than 6982 -- refusing on
     * authorisation grounds would confirm the file exists.
     */
    {
        uint16_t        target = FS_INVALID_INDEX;
        const fs_status fst    = fs_find_child(k->sel.cur_df, fid, &target);
        /*
         * If the identifier does not name a child, FALL THROUGH to
         * fs_delete_file() rather than reporting the lookup failure here.
         *
         * It already knows why: the MF is refused as "not usable" because a
         * card with no root is a brick, and that is a better answer than the
         * 6A82 this lookup would produce -- the MF is not a child of itself,
         * so "not found" is technically true and diagnostically useless. The
         * first version of this check returned 6A82 for DELETE 3F00 and an
         * existing test caught it.
         *
         * Duplicating the existence rules here would also mean two places that
         * can disagree about what exists.
         */
        if (fst == FS_OK) {
            fs_descriptor   d;
            const fs_status gst = fs_get(target, &d);
            if (gst != FS_OK) {
                return scos_fs_error_to_sw(gst);
            }
            if (!scos_ac_permits(k->auth, &d, AC_OP_ADMIN)) {
                return SW_SECURITY_NOT_SATISFIED; /* 6982 */
            }
        }
    }

    const fs_status st = fs_delete_file(&k->sel, fid);
    if (st != FS_OK) {
        return scos_fs_error_to_sw(st);
    }
    return SW_OK;
}
