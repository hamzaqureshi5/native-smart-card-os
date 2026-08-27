/* SPDX-License-Identifier: MIT
 *
 * fs.c -- LOGICAL layer: tree navigation and selection.
 *
 * NO DESCRIPTOR CACHE, ON PURPOSE (for now).
 * Every lookup re-reads from NVM through fs_store. A 32-entry cache would cost
 * ~640 bytes of RAM and buy speed, but it also introduces a coherence problem:
 * two copies of the truth, and a window in which a power failure leaves them
 * disagreeing. Correctness first; the cache is a measured optimisation for
 * later, once transactions define what "coherent" means.
 */
#include "filesystem/fs.h"

#include "filesystem/fs_store.h"
#include "os/os_mem.h"

/* The MF always occupies slot 0. Fixing it means "where is the root" never
 * requires a search, and a corrupt slot 0 is immediately recognisable. */
#define FS_ROOT_INDEX 0u

uint16_t fs_root_index(void) { return FS_ROOT_INDEX; }

/* ------------------------------------------------------------ inspection --- */

fs_status fs_get(uint16_t index, fs_descriptor *out)
{
    return fs_store_read_desc(index, out);
}

fs_status fs_find_child(uint16_t parent, uint16_t file_id, uint16_t *out_index)
{
    if (out_index == NULL) {
        return FS_ERR_PARAM;
    }
    *out_index = FS_INVALID_INDEX;

    const uint16_t n = fs_store_max_files();
    for (uint16_t i = 0; i < n; i++) {
        fs_descriptor d;
        const fs_status st = fs_store_read_desc(i, &d);
        if (st == FS_ERR_NOT_FOUND) {
            continue; /* free slot */
        }
        if (st == FS_ERR_CORRUPT) {
            /* Skip a corrupt entry rather than aborting the whole search: one
             * damaged descriptor must not make the rest of the card
             * unreachable. The corruption is still reported when that file is
             * addressed directly. */
            continue;
        }
        if (st != FS_OK) {
            return st;
        }
        if (d.parent == parent && d.file_id == file_id) {
            *out_index = i;
            return FS_OK;
        }
    }
    return FS_ERR_NOT_FOUND;
}

fs_status fs_find_by_sfi(uint16_t df, uint8_t sfi, uint16_t *out_index)
{
    if (out_index == NULL) {
        return FS_ERR_PARAM;
    }
    *out_index = FS_INVALID_INDEX;
    if (sfi == FS_NO_SFI || sfi > 30u) {
        return FS_ERR_PARAM; /* ISO: short EF identifiers are 1..30 */
    }

    const uint16_t n = fs_store_max_files();
    for (uint16_t i = 0; i < n; i++) {
        fs_descriptor d;
        if (fs_store_read_desc(i, &d) != FS_OK) {
            continue;
        }
        if (d.parent == df && fs_is_ef(&d) && d.sfi == sfi) {
            *out_index = i;
            return FS_OK;
        }
    }
    return FS_ERR_NOT_FOUND;
}

uint16_t fs_child_count(uint16_t parent)
{
    uint16_t count = 0u;
    const uint16_t n = fs_store_max_files();
    for (uint16_t i = 0; i < n; i++) {
        fs_descriptor d;
        if (fs_store_read_desc(i, &d) != FS_OK) {
            continue;
        }
        if (d.parent == parent) {
            count++;
        }
    }
    return count;
}

/* -------------------------------------------------------------- selection -- */

void fs_selection_reset(fs_selection *sel)
{
    if (sel == NULL) {
        return;
    }
    /* A reset returns to the MF with no current EF. This is a SECURITY event:
     * from M3 it also drops PIN authentication, so an attacker cannot use a
     * reset to keep a privileged selection while clearing a failure counter. */
    sel->cur_df = FS_ROOT_INDEX;
    sel->cur_ef = FS_INVALID_INDEX;
}

uint16_t fs_selected_index(const fs_selection *sel)
{
    if (sel == NULL) {
        return FS_INVALID_INDEX;
    }
    return (sel->cur_ef != FS_INVALID_INDEX) ? sel->cur_ef : sel->cur_df;
}

/* Commit a selection. Called only after the target has been resolved AND found
 * usable, so a failed SELECT cannot disturb the current state. */
static void commit(fs_selection *sel, uint16_t index, const fs_descriptor *d)
{
    if (fs_is_df(d)) {
        sel->cur_df = index;
        /* Selecting a DF clears the current EF -- otherwise a later READ BINARY
         * could act on an EF belonging to a different application than the DF
         * now selected. */
        sel->cur_ef = FS_INVALID_INDEX;
    } else {
        sel->cur_ef = index;
        sel->cur_df = d->parent;
    }
}

/* Resolve-and-check helper: load the descriptor and refuse anything not
 * ACTIVATED, so lifecycle state is enforced in exactly one place. */
static fs_status resolve(uint16_t index, fs_descriptor *out)
{
    const fs_status st = fs_store_read_desc(index, out);
    if (st != FS_OK) {
        return st;
    }
    if (!fs_is_usable(out)) {
        return FS_ERR_NOT_USABLE;
    }
    return FS_OK;
}

fs_status fs_select_by_fid(fs_selection *sel, uint16_t file_id)
{
    if (sel == NULL) {
        return FS_ERR_PARAM;
    }

    fs_descriptor d;
    uint16_t      index = FS_INVALID_INDEX;

    /* Search order, fixed and documented in fs.h. Note what is absent: a
     * global search of the tree, which would let one application reach
     * another's files by identifier alone. */

    /* 1. the MF */
    if (file_id == FS_FID_MF) {
        index = FS_ROOT_INDEX;
    }

    /* 2. a direct child of the current DF */
    if (index == FS_INVALID_INDEX) {
        uint16_t found = FS_INVALID_INDEX;
        if (fs_find_child(sel->cur_df, file_id, &found) == FS_OK) {
            index = found;
        }
    }

    /* 3. the current DF itself */
    if (index == FS_INVALID_INDEX) {
        if (fs_store_read_desc(sel->cur_df, &d) == FS_OK &&
            d.file_id == file_id) {
            index = sel->cur_df;
        }
    }

    /* 4. the parent of the current DF */
    if (index == FS_INVALID_INDEX) {
        if (fs_store_read_desc(sel->cur_df, &d) == FS_OK &&
            d.parent != FS_NO_PARENT) {
            fs_descriptor p;
            if (fs_store_read_desc(d.parent, &p) == FS_OK &&
                p.file_id == file_id) {
                index = d.parent;
            }
        }
    }

    if (index == FS_INVALID_INDEX) {
        return FS_ERR_NOT_FOUND;
    }

    const fs_status st = resolve(index, &d);
    if (st != FS_OK) {
        return st;
    }
    commit(sel, index, &d);
    return FS_OK;
}

/* P1=01 / P1=02: select a child, requiring a specific type. Requiring the type
 * makes the caller's intent explicit and turns a wrong-type selection into a
 * clear error instead of a surprising success. */
static fs_status select_child_typed(fs_selection *sel, uint16_t file_id,
                                    bool want_df)
{
    if (sel == NULL) {
        return FS_ERR_PARAM;
    }
    uint16_t index = FS_INVALID_INDEX;
    const fs_status find = fs_find_child(sel->cur_df, file_id, &index);
    if (find != FS_OK) {
        return find;
    }

    fs_descriptor d;
    const fs_status st = resolve(index, &d);
    if (st != FS_OK) {
        return st;
    }
    if (want_df != fs_is_df(&d)) {
        return FS_ERR_WRONG_TYPE;
    }
    commit(sel, index, &d);
    return FS_OK;
}

fs_status fs_select_child_df(fs_selection *sel, uint16_t file_id)
{
    return select_child_typed(sel, file_id, true);
}

fs_status fs_select_child_ef(fs_selection *sel, uint16_t file_id)
{
    return select_child_typed(sel, file_id, false);
}

fs_status fs_select_parent(fs_selection *sel)
{
    if (sel == NULL) {
        return FS_ERR_PARAM;
    }
    fs_descriptor cur;
    const fs_status st = fs_store_read_desc(sel->cur_df, &cur);
    if (st != FS_OK) {
        return st;
    }
    if (cur.parent == FS_NO_PARENT) {
        /* Already at the MF. There is no parent of the root, and inventing one
         * (silently staying put) would hide a caller's logic error. */
        return FS_ERR_NOT_FOUND;
    }

    fs_descriptor parent;
    const fs_status pst = resolve(cur.parent, &parent);
    if (pst != FS_OK) {
        return pst;
    }
    commit(sel, cur.parent, &parent);
    return FS_OK;
}

fs_status fs_select_by_path(fs_selection *sel, const uint8_t *path,
                            uint16_t path_len, bool from_mf)
{
    if (sel == NULL || path == NULL) {
        return FS_ERR_PARAM;
    }
    /* A path is a sequence of 2-byte identifiers, so an odd length is
     * malformed, and an empty path selects nothing. */
    if (path_len == 0u || (path_len % 2u) != 0u) {
        return FS_ERR_PARAM;
    }
    const uint16_t steps = (uint16_t)(path_len / 2u);
    if (steps > FS_MAX_DEPTH) {
        /* Bounded walk. Even though the tree cannot legally contain a cycle, a
         * corrupt parent pointer could create one, and an unbounded walk would
         * then hang the card. */
        return FS_ERR_PARAM;
    }

    /* Walk a SCRATCH selection and commit only on full success: a path that
     * fails half way must leave the real selection untouched, or an attacker
     * could land the card in an intermediate DF of their choosing. */
    fs_selection scratch = *sel;
    if (from_mf) {
        scratch.cur_df = FS_ROOT_INDEX;
        scratch.cur_ef = FS_INVALID_INDEX;
    }

    for (uint16_t s = 0; s < steps; s++) {
        const uint16_t fid =
            (uint16_t)(((uint16_t)path[s * 2u] << 8) | path[(s * 2u) + 1u]);

        /* The first component may name the DF we are already standing on --
         * ISO permits a path beginning with the current DF's own identifier. */
        if (s == 0u) {
            fs_descriptor here;
            if (fs_store_read_desc(scratch.cur_df, &here) == FS_OK &&
                here.file_id == fid) {
                continue;
            }
        }

        uint16_t index = FS_INVALID_INDEX;
        if (fs_find_child(scratch.cur_df, fid, &index) != FS_OK) {
            return FS_ERR_NOT_FOUND;
        }
        fs_descriptor d;
        const fs_status st = resolve(index, &d);
        if (st != FS_OK) {
            return st;
        }

        const bool last = (s + 1u == steps);
        if (!last && !fs_is_df(&d)) {
            /* An interior component must be a DF; an EF has no children. */
            return FS_ERR_WRONG_TYPE;
        }
        commit(&scratch, index, &d);
    }

    *sel = scratch;
    return FS_OK;
}

/* ------------------------------------------------------------ EF data I/O -- */

fs_status fs_ef_read(uint16_t index, uint16_t offset, uint16_t len,
                     uint8_t *dst, uint16_t *out_read)
{
    if (dst == NULL || out_read == NULL) {
        return FS_ERR_PARAM;
    }
    *out_read = 0u;

    fs_descriptor d;
    const fs_status st = resolve(index, &d);
    if (st != FS_OK) {
        return st;
    }
    if (!fs_is_ef(&d)) {
        return FS_ERR_WRONG_TYPE;
    }
    if (offset > d.size) {
        /* offset == size is the legal "at end of file" position, which reads
         * zero bytes; beyond that is a range error. */
        return FS_ERR_RANGE;
    }

    /* Clamp to the file's OWN size, not to FLASH. Bytes past the end of this
     * EF may well exist and belong to another file. */
    const uint16_t available = (uint16_t)(d.size - offset);
    const uint16_t to_read   = (len < available) ? len : available;
    if (to_read == 0u) {
        return FS_OK;
    }

    const fs_status rst =
        fs_store_read_data(d.data_offset + (uint32_t)offset, to_read, dst);
    if (rst != FS_OK) {
        return rst;
    }
    *out_read = to_read;
    return FS_OK;
}

fs_status fs_ef_write(uint16_t index, uint16_t offset, uint16_t len,
                      const uint8_t *src)
{
    if (src == NULL) {
        return FS_ERR_PARAM;
    }
    if (len == 0u) {
        return FS_OK;
    }

    fs_descriptor d;
    const fs_status st = resolve(index, &d);
    if (st != FS_OK) {
        return st;
    }
    if (!fs_is_ef(&d)) {
        return FS_ERR_WRONG_TYPE;
    }

    /* uint32_t so offset + len cannot wrap past the size check. */
    if ((uint32_t)offset + (uint32_t)len > (uint32_t)d.size) {
        /* Refuse the WHOLE write. A partial update would leave the file in a
         * state the caller cannot reason about, and until transactions exist
         * there is no way to undo it. */
        return FS_ERR_RANGE;
    }

    return fs_store_write_data(d.data_offset + (uint32_t)offset, len, src);
}

/* ------------------------------------------------------------ ISO encoding -- */

uint8_t fs_iso_descriptor_byte(const fs_descriptor *desc)
{
    if (desc == NULL) {
        return 0x00u;
    }
    /*
     * ISO/IEC 7816-4 file descriptor byte:
     *   b8    = 0
     *   b7    = shareable
     *   b6b5b4= file type   (000 working EF, 111 DF)
     *   b3b2b1= EF structure(001 transparent)
     */
    switch (desc->type) {
    case FS_TYPE_MF:
    case FS_TYPE_DF:
        return 0x38u; /* 0 0 111 000 : DF */
    case FS_TYPE_EF_TRANSPARENT:
        return 0x01u; /* 0 0 000 001 : working EF, transparent */
    case FS_TYPE_FREE:
    default:
        return 0x00u;
    }
}

uint16_t fs_build_fcp(const fs_descriptor *desc, uint8_t *out, uint16_t cap)
{
    if (desc == NULL || out == NULL) {
        return 0u;
    }

    /* Longest case: 82(3) + 83(4) + 80(4) + 8A(3) + 88(3) = 17 bytes. */
    uint8_t  buf[24];
    uint16_t n = 0u;

    /* Tag 82: file descriptor byte. */
    buf[n++] = 0x82u;
    buf[n++] = 0x01u;
    buf[n++] = fs_iso_descriptor_byte(desc);

    /* Tag 83: file identifier. */
    buf[n++] = 0x83u;
    buf[n++] = 0x02u;
    buf[n++] = (uint8_t)(desc->file_id >> 8);
    buf[n++] = (uint8_t)(desc->file_id & 0xFFu);

    /* Tag 80: number of data bytes, EF only. A DF has no size to report, and
     * emitting 80 00 00 for one would be a false statement rather than a
     * harmless default. */
    if (fs_is_ef(desc)) {
        buf[n++] = 0x80u;
        buf[n++] = 0x02u;
        buf[n++] = (uint8_t)(desc->size >> 8);
        buf[n++] = (uint8_t)(desc->size & 0xFFu);
    }

    /* Tag 8A: life cycle status byte. */
    buf[n++] = 0x8Au;
    buf[n++] = 0x01u;
    buf[n++] = (uint8_t)desc->lifecycle;

    /* Tag 88: short EF identifier, when the file has one. ISO encodes it in
     * bits b8..b4 of the value byte. */
    if (fs_is_ef(desc) && desc->sfi != FS_NO_SFI) {
        buf[n++] = 0x88u;
        buf[n++] = 0x01u;
        buf[n++] = (uint8_t)(desc->sfi << 3);
    }

    if (n > cap) {
        return 0u; /* caller decides what to do; we never truncate a template */
    }
    if (!os_memcpy_checked(out, cap, buf, n)) {
        return 0u;
    }
    return n;
}

/* -------------------------------------------------------------- lifecycle -- */

/*
 * The factory file layout.
 *
 * A real card is PERSONALISED at manufacture: the issuer writes the file
 * structure before the card ever reaches a user, and many cards never allow
 * CREATE FILE at all afterwards. So a fixed factory tree is a faithful
 * intermediate state, not a placeholder -- CREATE FILE / DELETE FILE (M2b) make
 * it dynamic.
 *
 *   MF 3F00
 *    +-- EF 2F00  32 bytes, SFI 1     (an EF directly under the MF)
 *    +-- DF 7F10                      (an "application")
 *         +-- EF 6F01  64 bytes, SFI 1
 *         +-- EF 6F02  16 bytes, SFI 2
 *
 * Note that SFI 1 appears twice: short EF identifiers are scoped to their
 * parent DF, not global. Deliberate, so the tests exercise that scoping.
 */
fs_status fs_personalise(void)
{
    fs_status st = fs_store_format();
    if (st != FS_OK) {
        return st;
    }

    /* --- slot 0: the MF ------------------------------------------------- */
    fs_descriptor mf;
    os_memset(&mf, 0, sizeof(mf));
    mf.file_id   = FS_FID_MF;
    mf.type      = FS_TYPE_MF;
    mf.lifecycle = FS_LC_ACTIVATED;
    mf.parent    = FS_NO_PARENT;
    mf.sfi       = FS_NO_SFI;
    st = fs_store_write_desc(0u, &mf);
    if (st != FS_OK) {
        return st;
    }

    /* Helper-free inline creation: a table plus a loop would be shorter but
     * would obscure the parent indices, which are the part worth reading. */
    struct {
        uint16_t     index;
        uint16_t     file_id;
        fs_file_type type;
        uint16_t     parent;
        uint16_t     size;
        uint8_t      sfi;
    } const layout[] = {
        { 1u, 0x2F00u, FS_TYPE_EF_TRANSPARENT, 0u, 32u, 1u },
        { 2u, 0x7F10u, FS_TYPE_DF,             0u,  0u, 0u },
        { 3u, 0x6F01u, FS_TYPE_EF_TRANSPARENT, 2u, 64u, 1u },
        { 4u, 0x6F02u, FS_TYPE_EF_TRANSPARENT, 2u, 16u, 2u },
    };

    for (unsigned i = 0; i < (sizeof(layout) / sizeof(layout[0])); i++) {
        fs_descriptor d;
        os_memset(&d, 0, sizeof(d));
        d.file_id   = layout[i].file_id;
        d.type      = layout[i].type;
        d.lifecycle = FS_LC_ACTIVATED;
        d.parent    = layout[i].parent;
        d.size      = layout[i].size;
        d.sfi       = layout[i].sfi;

        if (layout[i].type == FS_TYPE_EF_TRANSPARENT) {
            uint32_t offset = 0u;
            st = fs_store_alloc_data(layout[i].size, &offset);
            if (st != FS_OK) {
                return st;
            }
            d.data_offset = offset;

            /* Leave contents in the erased state (0xFF), which is what a real
             * un-personalised EF reads as. Tests rely on it. */
        }

        st = fs_store_write_desc(layout[i].index, &d);
        if (st != FS_OK) {
            return st;
        }
    }
    return FS_OK;
}

fs_status fs_init(void)
{
    const fs_status st = fs_store_mount();

    if (st == FS_OK) {
        /* Mounted an existing image. Sanity-check that slot 0 really is the MF
         * before trusting the tree -- everything navigates from there. */
        fs_descriptor mf;
        const fs_status rst = fs_store_read_desc(FS_ROOT_INDEX, &mf);
        if (rst != FS_OK) {
            return (rst == FS_ERR_NOT_FOUND) ? FS_ERR_CORRUPT : rst;
        }
        if (mf.type != FS_TYPE_MF || mf.file_id != FS_FID_MF) {
            return FS_ERR_CORRUPT;
        }
        return FS_OK;
    }

    if (st == FS_ERR_NOT_FORMATTED) {
        /* A blank chip. Personalising it is the correct action: this is the
         * factory step. */
        return fs_personalise();
    }

    /*
     * Corrupt or unknown-version image. Reported, NOT repaired.
     *
     * Auto-formatting here would destroy the data the user most wants back,
     * and would hand an attacker who can corrupt one byte a reliable way to
     * wipe the card. The card comes up unusable and says so.
     */
    return st;
}

/* ========================================================== create/delete == */

/*
 * Reserved identifiers.
 *
 * 3F00 is the MF by definition and there is exactly one. FFFF is reserved by
 * ISO/IEC 7816-4 to mean "no file", so a file carrying it could never be
 * unambiguously selected.
 */
static bool fid_is_reserved(uint16_t fid)
{
    return fid == FS_FID_MF || fid == 0xFFFFu;
}

fs_status fs_create_file(const fs_selection *sel, const fs_descriptor *req,
                         uint16_t *out_index)
{
    if (sel == NULL || req == NULL) {
        return FS_ERR_PARAM;
    }

    /* The parent must be a DF that is itself usable. Creating inside a
     * deactivated or terminated DF would produce a file reachable only by
     * reactivating its parent, which is a state nothing else in the OS
     * expects. */
    fs_descriptor parent;
    fs_status     st = fs_store_read_desc(sel->cur_df, &parent);
    if (st != FS_OK) {
        return st;
    }
    if (!fs_is_df(&parent)) {
        return FS_ERR_WRONG_TYPE;
    }
    if (!fs_is_usable(&parent)) {
        return FS_ERR_NOT_USABLE;
    }

    if (fid_is_reserved(req->file_id)) {
        return FS_ERR_EXISTS;
    }

    /* Type-specific validation. Done before ANY write, so a rejected request
     * leaves the filesystem exactly as it was. */
    switch (req->type) {
    case FS_TYPE_DF:
        if (req->size != 0u || req->sfi != FS_NO_SFI) {
            return FS_ERR_PARAM;
        }
        break;
    case FS_TYPE_EF_TRANSPARENT:
        /* A zero-length EF is refused rather than created. ISO does not forbid
         * it, but every read of it would be a short read of nothing and every
         * write out of range, so it can do nothing except confuse a client. */
        if (req->size == 0u || req->size > FS_MAX_EF_SIZE) {
            return FS_ERR_PARAM;
        }
        if (req->sfi != FS_NO_SFI && (req->sfi < 1u || req->sfi > 30u)) {
            return FS_ERR_PARAM;
        }
        break;
    case FS_TYPE_MF:
        /* There is exactly one MF and fs_personalise() made it. */
        return FS_ERR_EXISTS;
    case FS_TYPE_FREE:
    default:
        return FS_ERR_PARAM;
    }

    switch (req->lifecycle) {
    case FS_LC_CREATION:
    case FS_LC_INITIALISED:
    case FS_LC_ACTIVATED:
    case FS_LC_DEACTIVATED:
        break;
    case FS_LC_TERMINATED:
        /* Creating something already dead is almost certainly a client bug,
         * and it is irreversible, so refuse rather than honour it. */
        return FS_ERR_PARAM;
    default:
        return FS_ERR_PARAM;
    }

    /* Collision checks against the siblings. */
    uint16_t existing = FS_INVALID_INDEX;
    if (fs_find_child(sel->cur_df, req->file_id, &existing) == FS_OK) {
        return FS_ERR_EXISTS;
    }
    if (req->sfi != FS_NO_SFI &&
        fs_find_by_sfi(sel->cur_df, req->sfi, &existing) == FS_OK) {
        return FS_ERR_EXISTS;
    }

    const uint16_t slot = fs_store_find_free_slot();
    if (slot == FS_INVALID_INDEX) {
        return FS_ERR_NO_SPACE;
    }

    fs_descriptor d;
    os_memset(&d, 0, sizeof(d));
    d.file_id   = req->file_id;
    d.type      = req->type;
    d.lifecycle = req->lifecycle;
    d.parent    = sel->cur_df;
    d.size      = req->size;
    d.sfi       = req->sfi;
    d.ac_read   = req->ac_read;
    d.ac_update = req->ac_update;
    d.flags     = 0u;

    if (req->type == FS_TYPE_EF_TRANSPARENT) {
        uint32_t offset = 0u;
        st = fs_store_alloc_data(req->size, &offset);
        if (st != FS_OK) {
            /* Out of data space. The descriptor slot was never written, so
             * nothing needs undoing -- which is exactly why the allocation
             * happens after every other check and before the only write. */
            return st;
        }
        d.data_offset = offset;
        /* Contents are left in the erased state (0xFF), the same as a
         * factory-fresh EF. Not zeroed: zeroing would be a write of 0x00 over
         * flash that has just been allocated, and on a real part that is a
         * program cycle spent to make the file *less* like blank silicon. */
    }

    st = fs_store_write_desc(slot, &d);
    if (st != FS_OK) {
        return st;
    }
    if (out_index != NULL) {
        *out_index = slot;
    }
    return FS_OK;
}

fs_status fs_delete_file(fs_selection *sel, uint16_t file_id)
{
    if (sel == NULL) {
        return FS_ERR_PARAM;
    }
    if (file_id == FS_FID_MF) {
        /* A card with no root cannot mount. Refusing here rather than in the
         * command handler means no future caller can get it wrong either. */
        return FS_ERR_NOT_USABLE;
    }

    uint16_t  index = FS_INVALID_INDEX;
    fs_status st    = fs_find_child(sel->cur_df, file_id, &index);
    if (st != FS_OK) {
        return st;
    }

    fs_descriptor d;
    st = fs_store_read_desc(index, &d);
    if (st != FS_OK) {
        return st;
    }
    if (d.type == FS_TYPE_MF) {
        return FS_ERR_NOT_USABLE;
    }
    if (fs_is_df(&d) && fs_child_count(index) > 0u) {
        /* Non-empty DF. See the comment in fs.h: a recursive delete cannot be
         * rolled back before M4, and a power cut part way through would leave
         * orphans pointing at a parent slot that gets reused. */
        return FS_ERR_NOT_USABLE;
    }

    st = fs_store_free_desc(index);
    if (st != FS_OK) {
        return st;
    }

    /* Do not leave the selection pointing at a freed slot: the next command
     * would act on whatever is written there next. */
    if (sel->cur_ef == index) {
        sel->cur_ef = FS_INVALID_INDEX;
    }
    if (sel->cur_df == index) {
        /* Cannot happen today -- fs_find_child never returns the DF we are
         * searching within -- but a future caller might delete the current DF
         * from its parent. Falling back to the root is the only selection
         * guaranteed to exist. */
        sel->cur_df = fs_root_index();
        sel->cur_ef = FS_INVALID_INDEX;
    }
    return FS_OK;
}
