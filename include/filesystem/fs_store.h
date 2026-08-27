/* SPDX-License-Identifier: MIT
 *
 * fs_store.h -- PHYSICAL layer: descriptors and data bytes in NVM.
 *
 * This layer knows NVM offsets, the serialised descriptor layout, CRCs and
 * allocation. It knows NOTHING about trees, parents, children, selection or
 * APDUs -- it will happily store a descriptor whose parent index is nonsense.
 * Structural validity is the logical layer's job (fs.c).
 *
 * WHY THE SPLIT IS WORTH THE EXTRA FILE
 * The transaction manager (M4) has to insert a journal between the logical and
 * physical layers, so that "update three descriptors" becomes atomic. With this
 * seam, M4 changes fs_store.c and nothing above it. Without it, M4 would mean
 * rewriting the filesystem.
 */
#ifndef SCOS_FS_STORE_H
#define SCOS_FS_STORE_H

#include "filesystem/fs_types.h"

/* --------------------------------------------------------------- lifecycle */

/* Read and validate the superblock. Returns:
 *   FS_OK                 mounted; the table is usable
 *   FS_ERR_NOT_FORMATTED  no superblock (blank chip)
 *   FS_ERR_VERSION        a layout version we do not understand
 *   FS_ERR_CORRUPT        superblock present but its CRC failed
 *
 * The version and corrupt cases are deliberately NOT auto-repaired. Silently
 * reformatting a card because its metadata looked wrong would destroy the very
 * data the user is trying to recover, and an attacker who can corrupt one byte
 * would gain a way to wipe the card.
 */
fs_status fs_store_mount(void);

/* Write a fresh superblock and mark every descriptor slot free. DESTRUCTIVE. */
fs_status fs_store_format(void);

bool     fs_store_is_mounted(void);
uint16_t fs_store_max_files(void);

/* ------------------------------------------------------------- descriptors */

/* Read slot `index`. Returns FS_ERR_NOT_FOUND for a free slot and
 * FS_ERR_CORRUPT if the CRC fails -- distinct, because a free slot is normal
 * and a corrupt one is an incident. */
fs_status fs_store_read_desc(uint16_t index, fs_descriptor *out);

/* Serialise and write slot `index`, recomputing the CRC. */
fs_status fs_store_write_desc(uint16_t index, const fs_descriptor *desc);

/* Mark a slot free (writes the FS_TYPE_FREE erased pattern). */
fs_status fs_store_free_desc(uint16_t index);

bool fs_store_slot_is_free(uint16_t index);

/* Lowest free slot index, or FS_INVALID_INDEX. */
uint16_t fs_store_find_free_slot(void);

/* ---------------------------------------------------------------- EF data -- */

/* Space released by a deleted file IS reclaimed, as of M4 -- see
 * fs_store_find_free_data() below. There is no free list and no compaction
 * pass: the live descriptors ARE the record of what is in use, so a freed slot
 * needs no separate bookkeeping to stop reserving its extent.
 */
/*
 * Where would `size` bytes of EF data fit? RESERVES NOTHING.
 *
 * First fit over the live descriptors. The caller reserves the space by writing
 * a descriptor that points at the returned offset -- the descriptor IS the
 * record of ownership, so there is no second place for it to be recorded and no
 * window in which the two disagree.
 *
 * Consequence worth stating: calling this twice without writing a descriptor in
 * between returns the SAME offset. Both callers write immediately. The previous
 * name, fs_store_alloc_data, implied a reservation and hung a test that relied
 * on one.
 */
fs_status fs_store_find_free_data(uint16_t size, uint32_t *out_offset);

fs_status fs_store_read_data(uint32_t offset, uint16_t len, void *dst);
fs_status fs_store_write_data(uint32_t offset, uint16_t len, const void *src);

/* Bytes of EF data space still allocatable. */
uint32_t fs_store_data_free(void);

#endif /* SCOS_FS_STORE_H */
