/* SPDX-License-Identifier: MIT
 *
 * fs.h -- LOGICAL layer: the file tree and the current selection.
 *
 * Knows about parents, children, paths and selection. Knows NO NVM offsets --
 * everything physical goes through fs_store.
 */
#ifndef SCOS_FS_H
#define SCOS_FS_H

#include "filesystem/fs_types.h"

/*
 * THE CURRENT SELECTION -- the card's most important piece of volatile state.
 *
 * A card is stateful in a way a stateless request/response service is not:
 * READ BINARY does not name a file, it reads "the current EF". So almost every
 * command is implicitly scoped by this struct, and getting its transitions
 * wrong is a security bug rather than a usability one.
 *
 * ISO/IEC 7816-4 rules implemented here:
 *   - selecting a DF makes it the current DF and CLEARS the current EF
 *   - selecting an EF sets the current EF; the current DF becomes its parent
 *   - a reset returns to the MF with no current EF
 *   - a FAILED selection changes nothing
 *
 * Why clearing the EF on a DF selection matters: without it, a command could
 * act on an EF from a different application than the currently selected DF.
 */
typedef struct {
    uint16_t cur_df; /* descriptor index of the current DF; always valid    */
    uint16_t cur_ef; /* descriptor index, or FS_INVALID_INDEX if none       */
} fs_selection;

/* -------------------------------------------------------------- lifecycle -- */

/* Mount the filesystem, formatting and personalising a blank chip.
 *
 * Returns FS_OK when the card is usable. A corrupt or unknown-version image is
 * reported, NOT auto-repaired -- see fs_store_mount().
 */
fs_status fs_init(void);

/* Write the factory file layout. Called by fs_init() on a blank chip; exposed
 * so tests can rebuild a known tree. DESTRUCTIVE. */
fs_status fs_personalise(void);

/* Reset the selection to the MF, no current EF. Called on card reset. */
void fs_selection_reset(fs_selection *sel);

uint16_t fs_root_index(void);

/* ------------------------------------------------------------- inspection -- */

fs_status fs_get(uint16_t index, fs_descriptor *out);

/* Find a direct child of `parent` by file identifier. */
fs_status fs_find_child(uint16_t parent, uint16_t file_id, uint16_t *out_index);

/* Find an EF under `df` by its short EF identifier (1..30). */
fs_status fs_find_by_sfi(uint16_t df, uint8_t sfi, uint16_t *out_index);

/* Number of direct children of a DF. Used to refuse deleting a non-empty DF. */
uint16_t fs_child_count(uint16_t parent);

/* ---------------------------------------------------------- create/delete -- */
/*
 * NO ACCESS CONTROL IS ENFORCED ON EITHER OF THESE YET.
 *
 * On a real card CREATE FILE and DELETE FILE are administrative commands
 * gated behind authentication -- a PIN, or more usually a secure channel to a
 * security domain. Here anyone holding the reader can create and delete files.
 * That is the same hole as the boot loader's, one layer up, and it is tracked
 * as "Unauthorized file access" in docs/threat-model.md against M3. Do not
 * read the checks below as a security boundary; they are structural integrity
 * checks, which is a different thing.
 */

/*
 * Create a file as a child of the current DF.
 *
 * Structural rules, all of them refusals rather than repairs:
 *   - the identifier must not already exist among the current DF's children
 *     (ISO leaves duplicate FIDs undefined; we refuse, because a tree with two
 *     3F01s under one DF makes every later lookup ambiguous)
 *   - 3F00 is reserved for the MF and cannot be created
 *   - FFFF is reserved by ISO as "no file" and cannot be created
 *   - an EF needs a non-zero size within FS_MAX_EF_SIZE; a DF must declare none
 *   - an SFI, if given, must be 1..30 and unused among the DF's children
 *
 * The selection is NOT changed. ISO/IEC 7816-9 permits a card to select a
 * newly created file; we do not, because a command that silently moves the
 * selection is the kind of thing that turns a later UPDATE BINARY into a write
 * to the wrong file.
 */
fs_status fs_create_file(const fs_selection *sel, const fs_descriptor *req,
                         uint16_t *out_index);

/*
 * Delete a child of the current DF, by identifier.
 *
 *   - the MF can never be deleted; a card with no root is a brick
 *   - a DF with children is refused (FS_ERR_NOT_USABLE) rather than deleted
 *     recursively. A recursive delete cannot be rolled back until the
 *     transaction journal exists (M4), so a power cut half way through would
 *     leave orphaned descriptors pointing at a parent slot that has been
 *     reused. Refusing is the honest behaviour until then.
 *   - only a direct child of the current DF, never a global search, for the
 *     same isolation reason fs_select_by_fid has no global search
 *
 * KNOWN LIMITATION: the EF's data bytes are NOT reclaimed. fs_store's data
 * area is a bump allocator, so deleting a file frees its descriptor slot but
 * leaks its data space. Compaction needs a way to move data atomically, which
 * needs M4. fs_store_data_free() therefore only ever decreases.
 *
 * If the deleted file was selected, `sel` is moved back to the containing DF --
 * leaving a selection pointing at a freed slot would let the next command act
 * on whatever is written there later.
 */
fs_status fs_delete_file(fs_selection *sel, uint16_t file_id);

/* ------------------------------------------------------------- life cycle -- */
/*
 * Move a file between ACTIVATED and DEACTIVATED (ISO/IEC 7816-9 ACTIVATE FILE
 * and DEACTIVATE FILE).
 *
 * ONLY those two states, and only between each other. The transitions this
 * REFUSES are the interesting part:
 *
 *   - anything out of TERMINATED. Termination is irreversible by design; a
 *     card that could un-terminate a file would make the state worthless as a
 *     control, and TERMINATED is what a future TERMINATE CARD relies on.
 *   - deactivating the MF. The MF is the only entry point to the tree, so
 *     turning it off is not an administrative action, it is bricking the card
 *     with no way back. Taking a whole card out of service is what TERMINATE
 *     CARD is for, and it is deliberately a different command.
 *   - CREATION and INITIALISED as either endpoint. A file mid-personalisation
 *     is not something the rest of the OS is built to handle, and quietly
 *     dragging it into ACTIVATED would hide an incomplete personalisation.
 *
 * Setting the state a file is already in SUCCEEDS. That is not laxity: if the
 * response to a DEACTIVATE is lost on the link, the reader's only recourse is
 * to send it again, and failing the retry would leave a correct reader unable
 * to finish a correct sequence.
 *
 * NO ACCESS CONTROL, exactly as for create and delete above. Anyone holding
 * the reader can deactivate any file. Tracked against M3.
 */
fs_status fs_set_lifecycle(uint16_t index, fs_lifecycle want);

/* --------------------------------------------------------------- selection -- */

/*
 * SELECT by file identifier, ISO P1=00 semantics.
 *
 * ISO leaves the search order to the card, so ours is DOCUMENTED AND FIXED --
 * an undocumented order becomes an accidental part of the interface that
 * clients depend on:
 *
 *   1. the MF, if file_id is 3F00
 *   2. a direct child of the current DF
 *   3. the current DF itself
 *   4. the parent of the current DF
 *
 * Deliberately absent: a global search of the whole tree. That would let an
 * application reach another application's files by identifier alone, which is
 * exactly the isolation failure the DF hierarchy exists to prevent.
 */
fs_status fs_select_by_fid(fs_selection *sel, uint16_t file_id);

fs_status fs_select_child_df(fs_selection *sel, uint16_t file_id);
fs_status fs_select_child_ef(fs_selection *sel, uint16_t file_id);
fs_status fs_select_parent(fs_selection *sel);

/* SELECT by path: a sequence of 2-byte identifiers, walked from the MF
 * (from_mf) or from the current DF. */
fs_status fs_select_by_path(fs_selection *sel, const uint8_t *path,
                            uint16_t path_len, bool from_mf);

/* The descriptor index the selection resolves to: the current EF if one is
 * selected, otherwise the current DF. This is what SELECT reports an FCI for. */
uint16_t fs_selected_index(const fs_selection *sel);

/* ------------------------------------------------------------ EF data I/O -- */

/*
 * Read from / write to a transparent EF.
 *
 * Bounds are enforced against the EF's declared size, not against FLASH: a
 * file must not be readable past its own end even if the bytes beyond it exist
 * and belong to another file.
 *
 * fs_ef_read() performs a SHORT READ rather than failing when fewer than `len`
 * bytes remain, reporting the count in *out_read. That is what ISO requires:
 * READ BINARY returns the available bytes with SW 6282 rather than refusing.
 */
fs_status fs_ef_read(uint16_t index, uint16_t offset, uint16_t len,
                     uint8_t *dst, uint16_t *out_read);

/* Writes must be complete. A partial UPDATE BINARY would leave the file in a
 * state the caller cannot reason about, so an out-of-range write is refused
 * entirely. */
fs_status fs_ef_write(uint16_t index, uint16_t offset, uint16_t len,
                      const uint8_t *src);

/* ------------------------------------------------------------ ISO encoding -- */

/* Map a filesystem error onto the ISO/IEC 7816-4 status word to answer with.
 * Lives here rather than in each command handler so that one filesystem error
 * always produces the same status word, whichever command hit it. */
uint16_t scos_fs_error_to_sw(fs_status st);

/* The ISO/IEC 7816-4 "file descriptor byte" for tag 82 of an FCP template.
 * Converts our internal type code into the bit-packed wire encoding. */
uint8_t fs_iso_descriptor_byte(const fs_descriptor *desc);

/* Build an FCP-style data-object sequence (tags 82, 83, 80, 8A, 88) describing
 * `desc`. Writes at most cap bytes; returns the length, or 0 if it did not fit.
 * The caller wraps it in a 6F (FCI) or 62 (FCP) template. */
uint16_t fs_build_fcp(const fs_descriptor *desc, uint8_t *out, uint16_t cap);

#endif /* SCOS_FS_H */
