/* SPDX-License-Identifier: MIT
 *
 * fs_store.c -- PHYSICAL layer.
 *
 * ON-NVM LAYOUT
 * =============
 *
 * EEPROM -- metadata. Byte-writable and high-endurance, which is what makes a
 * descriptor update safe to do in place.
 *
 *   offset  size  contents
 *   0x0000  16    superblock
 *   0x0010  20*N  descriptor table, N = FS_MAX_FILES
 *
 * Superblock (16 bytes, big-endian):
 *   0   4   magic 'S' 'C' 'O' 'S'
 *   4   2   layout version
 *   6   2   max_files this image was created with
 *   8   4   data_top: next free FLASH offset
 *   12  2   reserved (0)
 *   14  2   CRC-16 over bytes 0..13
 *
 * Descriptor (20 bytes, big-endian):
 *   0   2   file_id
 *   2   1   type            (FS_TYPE_*; 0xFF = free slot)
 *   3   1   lifecycle       (ISO 7816-4 life cycle status byte)
 *   4   2   parent index    (0xFFFF for the MF)
 *   6   2   size            (EF data bytes; 0 for MF/DF)
 *   8   4   data_offset     (FLASH offset of EF data)
 *   12  1   ac_read         (M3)
 *   13  1   ac_update       (M3)
 *   14  1   sfi             (short EF identifier, 0 = none)
 *   15  1   flags
 *   16  1   ac_admin        (M3) -- was reserved, so an older card reads it as
 *                           0 = FS_AC_ALWAYS, which is the behaviour it had
 *                           before access conditions existed. Compatible by
 *                           accident of the earlier layout, not by luck: the
 *                           reserved bytes were put there for this.
 *   17  1   reserved (0)
 *   18  2   CRC-16 over bytes 0..17
 *
 * FLASH -- EF contents, bump-allocated upward from 0.
 *
 * WHY EVERY FIELD IS SERIALISED BY HAND
 * A C struct is never written to NVM. Padding and endianness are compiler- and
 * target-dependent, so a struct written by this x86 build could be unreadable
 * by a cross-compiled build for a card MCU -- and a card whose filesystem
 * cannot be read is a brick. Explicit big-endian serialisation costs a few
 * lines and makes the format a contract rather than an accident.
 *
 * WHY BIG-ENDIAN
 * Everything on the wire in ISO 7816 is big-endian, file identifiers included.
 * Matching it means no byte-swapping between the APDU and the descriptor, and
 * one fewer place to invert something.
 */
#include "filesystem/fs_store.h"

#include "hal/hal.h"
#include "os/crc16.h"
#include "os/journal.h"
#include "os/os_mem.h"

#define FS_MAGIC_0 'S'
#define FS_MAGIC_1 'C'
#define FS_MAGIC_2 'O'
#define FS_MAGIC_3 'S'

#define FS_LAYOUT_VERSION 1u

#define FS_SB_OFFSET 0u
#define FS_DESC_BASE (FS_SB_OFFSET + FS_SUPERBLOCK_SIZE)

/* In-RAM mirror of the superblock. Small, hot, and re-read on every mount. */
static struct {
    bool     mounted;
    uint16_t version;
    uint16_t max_files;
    uint32_t data_top;
} s_sb;

/* -------------------------------------------------- serialisation helpers -- */

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

static uint16_t get_u16(const uint8_t *p)
{ return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]); }

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFFu);
}

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* ------------------------------------------------------------- superblock -- */

static fs_status sb_write(void)
{
    uint8_t raw[FS_SUPERBLOCK_SIZE];
    os_memset(raw, 0, sizeof(raw));

    raw[0] = FS_MAGIC_0;
    raw[1] = FS_MAGIC_1;
    raw[2] = FS_MAGIC_2;
    raw[3] = FS_MAGIC_3;
    put_u16(&raw[4], FS_LAYOUT_VERSION);
    put_u16(&raw[6], (uint16_t)FS_MAX_FILES);
    put_u32(&raw[8], s_sb.data_top);
    put_u16(&raw[12], 0u);
    put_u16(&raw[14], crc16(raw, 14u));

    if (scos_nvm_write(HAL_NVM_EEPROM, FS_SB_OFFSET, raw, sizeof(raw)) !=
        HAL_OK) {
        return FS_ERR_NVM;
    }
    /* The superblock is the root of trust for the whole layout. Make it
     * durable before anything references it. */
    if (hal_nvm_sync() != HAL_OK) {
        return FS_ERR_NVM;
    }
    return FS_OK;
}

fs_status fs_store_mount(void)
{
    s_sb.mounted = false;

    uint8_t raw[FS_SUPERBLOCK_SIZE];
    if (hal_nvm_read(HAL_NVM_EEPROM, FS_SB_OFFSET, raw, sizeof(raw)) !=
        HAL_OK) {
        return FS_ERR_NVM;
    }

    if (raw[0] != FS_MAGIC_0 || raw[1] != FS_MAGIC_1 || raw[2] != FS_MAGIC_2 ||
        raw[3] != FS_MAGIC_3) {
        return FS_ERR_NOT_FORMATTED;
    }

    /*
     * CRC before interpreting any other field. A corrupt superblock whose
     * data_top we trusted would hand out overlapping data allocations and
     * quietly destroy file contents.
     */
    if (get_u16(&raw[14]) != crc16(raw, 14u)) {
        return FS_ERR_CORRUPT;
    }

    const uint16_t version = get_u16(&raw[4]);
    if (version != FS_LAYOUT_VERSION) {
        /* Refuse rather than guess. Misreading an unknown layout is worse than
         * declining to mount, and a future version may need a migration. */
        return FS_ERR_VERSION;
    }

    const uint16_t max_files = get_u16(&raw[6]);
    if (max_files == 0u || max_files > FS_MAX_FILES) {
        /* The image claims more files than this build can address. */
        return FS_ERR_CORRUPT;
    }

    const uint32_t data_top = get_u32(&raw[8]);
    if (data_top > hal_nvm_size(HAL_NVM_FLASH)) {
        return FS_ERR_CORRUPT;
    }

    /* The descriptor table must fit in EEPROM, or reads would run off the end. */
    const uint32_t table_end =
        (uint32_t)FS_DESC_BASE + ((uint32_t)max_files * FS_DESC_SIZE);
    if (table_end > hal_nvm_size(HAL_NVM_EEPROM)) {
        return FS_ERR_CORRUPT;
    }

    s_sb.version   = version;
    s_sb.max_files = max_files;
    s_sb.data_top  = data_top;
    s_sb.mounted   = true;
    return FS_OK;
}

fs_status fs_store_format(void)
{
    const uint32_t table_end =
        (uint32_t)FS_DESC_BASE + ((uint32_t)FS_MAX_FILES * FS_DESC_SIZE);
    if (table_end > hal_nvm_size(HAL_NVM_EEPROM)) {
        return FS_ERR_NO_SPACE;
    }

    /* Mark every slot free first, then write the superblock LAST. Ordering is
     * deliberate: the superblock is what makes the card look formatted, so if
     * power is lost part way through, the card still reads as unformatted and
     * a retry starts cleanly. Without transactions this is the best available
     * guarantee, and it is the same reasoning M4 generalises. */
    uint8_t free_desc[FS_DESC_SIZE];
    os_memset(free_desc, 0xFF, sizeof(free_desc));

    for (uint16_t i = 0; i < FS_MAX_FILES; i++) {
        const uint32_t off =
            (uint32_t)FS_DESC_BASE + ((uint32_t)i * FS_DESC_SIZE);
        if (scos_nvm_write(HAL_NVM_EEPROM, off, free_desc, FS_DESC_SIZE) !=
            HAL_OK) {
            return FS_ERR_NVM;
        }
    }

    s_sb.data_top  = 0u;
    s_sb.version   = FS_LAYOUT_VERSION;
    s_sb.max_files = (uint16_t)FS_MAX_FILES;

    const fs_status st = sb_write();
    if (st != FS_OK) {
        return st;
    }
    s_sb.mounted = true;
    return FS_OK;
}

bool fs_store_is_mounted(void)
{ return s_sb.mounted; }
uint16_t fs_store_max_files(void)
{ return s_sb.mounted ? s_sb.max_files : 0u; }

/* ------------------------------------------------------------ descriptors -- */

static fs_status desc_raw_read(uint16_t index, uint8_t raw[FS_DESC_SIZE])
{
    if (!s_sb.mounted) {
        return FS_ERR_NOT_FORMATTED;
    }
    if (index >= s_sb.max_files) {
        return FS_ERR_PARAM;
    }
    const uint32_t off =
        (uint32_t)FS_DESC_BASE + ((uint32_t)index * FS_DESC_SIZE);
    if (hal_nvm_read(HAL_NVM_EEPROM, off, raw, FS_DESC_SIZE) != HAL_OK) {
        return FS_ERR_NVM;
    }
    return FS_OK;
}

bool fs_store_slot_is_free(uint16_t index)
{
    uint8_t raw[FS_DESC_SIZE];
    if (desc_raw_read(index, raw) != FS_OK) {
        return false;
    }
    /* A free slot is recognised by its type byte ALONE, with no CRC check --
     * erased NVM is all 0xFF and would fail any CRC. That is what lets a
     * factory-blank chip present a coherent empty table. */
    return raw[2] == (uint8_t)FS_TYPE_FREE;
}

fs_status fs_store_read_desc(uint16_t index, fs_descriptor *out)
{
    if (out == NULL) {
        return FS_ERR_PARAM;
    }
    os_memset(out, 0, sizeof(*out));

    uint8_t         raw[FS_DESC_SIZE];
    const fs_status st = desc_raw_read(index, raw);
    if (st != FS_OK) {
        return st;
    }

    if (raw[2] == (uint8_t)FS_TYPE_FREE) {
        return FS_ERR_NOT_FOUND;
    }

    /* CRC before interpreting any field, for the same reason as the
     * superblock: acting on a half-written descriptor compounds the damage. */
    if (get_u16(&raw[18]) != crc16(raw, 18u)) {
        return FS_ERR_CORRUPT;
    }

    const uint8_t type = raw[2];
    if (type != (uint8_t)FS_TYPE_MF && type != (uint8_t)FS_TYPE_DF &&
        type != (uint8_t)FS_TYPE_EF_TRANSPARENT) {
        /* CRC-valid but semantically impossible: a layout bug or a targeted
         * write. Either way, not something to act on. */
        return FS_ERR_CORRUPT;
    }

    out->file_id     = get_u16(&raw[0]);
    out->type        = (fs_file_type)type;
    out->lifecycle   = (fs_lifecycle)raw[3];
    out->parent      = get_u16(&raw[4]);
    out->size        = get_u16(&raw[6]);
    out->data_offset = get_u32(&raw[8]);
    out->ac_read     = raw[12];
    out->ac_update   = raw[13];
    out->ac_admin    = raw[16];
    out->sfi         = raw[14];
    out->flags       = raw[15];

    /* Structural checks that only the physical layer can make cheaply: an EF's
     * data must lie inside FLASH. A descriptor promising data outside the chip
     * would turn every read of that file into a HAL range error at best. */
    if (out->type == FS_TYPE_EF_TRANSPARENT) {
        const uint64_t end = (uint64_t)out->data_offset + (uint64_t)out->size;
        if (end > (uint64_t)hal_nvm_size(HAL_NVM_FLASH)) {
            return FS_ERR_CORRUPT;
        }
    }
    return FS_OK;
}

fs_status fs_store_write_desc(uint16_t index, const fs_descriptor *desc)
{
    if (desc == NULL) {
        return FS_ERR_PARAM;
    }
    if (!s_sb.mounted) {
        return FS_ERR_NOT_FORMATTED;
    }
    if (index >= s_sb.max_files) {
        return FS_ERR_PARAM;
    }
    if (desc->type == FS_TYPE_FREE) {
        return FS_ERR_PARAM; /* use fs_store_free_desc() */
    }

    uint8_t raw[FS_DESC_SIZE];
    os_memset(raw, 0, sizeof(raw));

    put_u16(&raw[0], desc->file_id);
    raw[2] = (uint8_t)desc->type;
    raw[3] = (uint8_t)desc->lifecycle;
    put_u16(&raw[4], desc->parent);
    put_u16(&raw[6], desc->size);
    put_u32(&raw[8], desc->data_offset);
    raw[12] = desc->ac_read;
    raw[13] = desc->ac_update;
    raw[14] = desc->sfi;
    raw[15] = desc->flags;
    raw[16] = desc->ac_admin;
    /* Byte 17 only. This used to be put_u16(&raw[16], 0) covering both
     * reserved bytes, which now silently zeroes ac_admin -- every file would
     * have read as FS_AC_ALWAYS and every access condition in the card would
     * have been unenforced while every test that only checked the ALWAYS case
     * still passed. Written in field order so the next field to claim byte 17
     * cannot repeat it. */
    raw[17] = 0u;
    put_u16(&raw[18], crc16(raw, 18u));

    const uint32_t off =
        (uint32_t)FS_DESC_BASE + ((uint32_t)index * FS_DESC_SIZE);
    if (scos_nvm_write(HAL_NVM_EEPROM, off, raw, FS_DESC_SIZE) != HAL_OK) {
        return FS_ERR_NVM;
    }
    if (hal_nvm_sync() != HAL_OK) {
        return FS_ERR_NVM;
    }
    return FS_OK;
}

fs_status fs_store_free_desc(uint16_t index)
{
    if (!s_sb.mounted) {
        return FS_ERR_NOT_FORMATTED;
    }
    if (index >= s_sb.max_files) {
        return FS_ERR_PARAM;
    }
    uint8_t raw[FS_DESC_SIZE];
    os_memset(raw, 0xFF, sizeof(raw));

    const uint32_t off =
        (uint32_t)FS_DESC_BASE + ((uint32_t)index * FS_DESC_SIZE);
    if (scos_nvm_write(HAL_NVM_EEPROM, off, raw, FS_DESC_SIZE) != HAL_OK) {
        return FS_ERR_NVM;
    }
    if (hal_nvm_sync() != HAL_OK) {
        return FS_ERR_NVM;
    }
    return FS_OK;
}

uint16_t fs_store_find_free_slot(void)
{
    if (!s_sb.mounted) {
        return FS_INVALID_INDEX;
    }
    for (uint16_t i = 0; i < s_sb.max_files; i++) {
        if (fs_store_slot_is_free(i)) {
            return i;
        }
    }
    return FS_INVALID_INDEX;
}

/* ---------------------------------------------------------------- EF data -- */

/*
 * Is any live EF's data extent overlapping [start, start + len)?
 *
 * Only LIVE transparent EFs count. A freed slot's type byte is 0xFF and its
 * offset and size fields are whatever the deleted file left there -- counting
 * those would reserve phantom extents for ever, which is the leak this
 * function exists to remove, reintroduced from the other direction.
 */
static bool extent_in_use(uint32_t start, uint32_t len, uint32_t *out_end)
{
    const uint64_t want_end = (uint64_t)start + (uint64_t)len;

    for (uint16_t i = 0; i < FS_MAX_FILES; i++) {
        fs_descriptor d;
        if (fs_store_read_desc(i, &d) != FS_OK) {
            continue; /* free or unreadable slot: owns nothing */
        }
        if (d.type != FS_TYPE_EF_TRANSPARENT || d.size == 0u) {
            continue; /* MF and DFs hold no data bytes */
        }
        const uint64_t s = (uint64_t)d.data_offset;
        const uint64_t e = s + (uint64_t)d.size;
        if (s < want_end && start < e) {
            if (out_end != NULL) {
                *out_end = (uint32_t)e;
            }
            return true;
        }
    }
    return false;
}

/*
 * FIRST FIT OVER THE LIVE DESCRIPTORS, replacing the bump allocator.
 *
 * RENAMED FROM fs_store_alloc_data, AND THE RENAME IS THE IMPORTANT PART.
 *
 * This function no longer RESERVES anything. It answers "where would `size`
 * bytes fit?" and nothing more; the reservation happens when the caller writes
 * the descriptor, because the descriptor IS the record of ownership.
 *
 * That is a real change of contract and the old name hid it. Calling it twice
 * without writing a descriptor in between returns the SAME offset both times --
 * which is correct for what it now does and catastrophic if you believe the old
 * name. It hung a test that allocated repeatedly without ever storing a
 * descriptor: every call returned 0, the free space never shrank, and the loop
 * ran for ever.
 *
 * Both real callers (fs_personalise and fs_create_file) write the descriptor
 * immediately, so they were always correct. The name was the only thing
 * wrong.
 *
 * The bump allocator only ever moved `data_top` upward, so DELETE FILE freed a
 * descriptor slot and stranded the EF's data bytes for good. With 32 slots and
 * a 256 KB data area, repeated create/delete cycles exhausted the space --
 * asserted as a known limitation in test_create.c since M2b, waiting for
 * transactions to make a fix safe.
 *
 * The fix is not compaction. Compaction moves live data, and the undo log for
 * moving a large EF would not fit in a 2 KB journal -- so it would have to be
 * incremental, with the card consistent but differently laid out between
 * steps, for no benefit a card actually needs. Real card filesystems reuse
 * free extents rather than defragmenting, because moving data on flash costs
 * erase cycles and time.
 *
 * WHAT THIS REMOVES BESIDES THE LEAK
 *
 * `data_top` was a second source of truth about which bytes are in use, and it
 * could disagree with the descriptors -- which is exactly what happened after
 * an interrupted CREATE FILE: the superblock recorded the new top, the
 * descriptor was never written, and the space was leaked. The old comment right
 * here said so and called it "wasteful but safe".
 *
 * Deriving the answer from the descriptors means there is nothing to disagree
 * with. It also means CREATE FILE no longer writes the superblock at all, which
 * removes one NVM write and one journal entry from every file creation.
 *
 * O(n^2) in the worst case and deliberately array-free: each iteration advances
 * past at least one extent, so it terminates in at most FS_MAX_FILES steps.
 * Sorting the extents first would be faster and would cost ~200 bytes of stack
 * -- the one kind of RAM this project does not account for.
 */
fs_status fs_store_find_free_data(uint16_t size, uint32_t *out_offset)
{
    if (out_offset == NULL) {
        return FS_ERR_PARAM;
    }
    *out_offset = 0u;
    if (!s_sb.mounted) {
        return FS_ERR_NOT_FORMATTED;
    }
    if (size == 0u) {
        /* A zero-length EF is refused higher up; allocating nothing would
         * return an offset that overlaps whatever comes next. */
        return FS_ERR_PARAM;
    }

    const uint32_t flash     = hal_nvm_size(HAL_NVM_FLASH);
    uint32_t       candidate = 0u;

    for (uint16_t hops = 0; hops <= FS_MAX_FILES; hops++) {
        if ((uint64_t)candidate + (uint64_t)size > (uint64_t)flash) {
            return FS_ERR_NO_SPACE;
        }
        uint32_t end = 0u;
        if (!extent_in_use(candidate, size, &end)) {
            *out_offset = candidate;
            /*
             * No superblock write. The descriptor the caller is about to store
             * IS the record that these bytes are taken, so there is no second
             * place for it to be recorded and no window in which the two
             * disagree. If power goes before that descriptor is written,
             * nothing was allocated -- rather than "the top moved and the space
             * is leaked", which is what the previous version did.
             */
            return FS_OK;
        }
        if (end <= candidate) {
            /* Cannot happen: an overlapping extent ends after `candidate`.
             * Guarded so a corrupt descriptor cannot spin here. */
            return FS_ERR_CORRUPT;
        }
        candidate = end;
    }

    /* More hops than there are descriptor slots: each hop passed an extent, so
     * this is unreachable unless the table is inconsistent. */
    return FS_ERR_NO_SPACE;
}

fs_status fs_store_read_data(uint32_t offset, uint16_t len, void *dst)
{
    if (dst == NULL) {
        return FS_ERR_PARAM;
    }
    if (len == 0u) {
        return FS_OK;
    }
    if (!s_sb.mounted) {
        return FS_ERR_NOT_FORMATTED;
    }
    if (hal_nvm_read(HAL_NVM_FLASH, offset, dst, len) != HAL_OK) {
        return FS_ERR_RANGE;
    }
    return FS_OK;
}

fs_status fs_store_write_data(uint32_t offset, uint16_t len, const void *src)
{
    if (src == NULL) {
        return FS_ERR_PARAM;
    }
    if (len == 0u) {
        return FS_OK;
    }
    if (!s_sb.mounted) {
        return FS_ERR_NOT_FORMATTED;
    }
    if (scos_nvm_write(HAL_NVM_FLASH, offset, src, len) != HAL_OK) {
        return FS_ERR_RANGE;
    }
    if (hal_nvm_sync() != HAL_OK) {
        return FS_ERR_NVM;
    }
    return FS_OK;
}

uint32_t fs_store_data_free(void)
{
    /*
     * Derived from the live descriptors, like the allocator above, and for the
     * same reason: `data_top` was a second source of truth that could disagree
     * with them -- and did, after an interrupted CREATE FILE.
     *
     * Reports the total unused bytes, NOT the largest contiguous run. A caller
     * that sees N free is not promised an N-byte extent, because freed extents
     * leave gaps. fs_store_find_free_data() is the only honest answer to "will
     * this fit", and it is the one fs_create_file() asks.
     */
    const uint32_t flash = hal_nvm_size(HAL_NVM_FLASH);
    uint32_t       used  = 0u;

    for (uint16_t i = 0; i < FS_MAX_FILES; i++) {
        fs_descriptor d;
        if (fs_store_read_desc(i, &d) != FS_OK) {
            continue;
        }
        if (d.type != FS_TYPE_EF_TRANSPARENT || d.size == 0u) {
            continue;
        }
        used += (uint32_t)d.size;
    }
    return (used < flash) ? (flash - used) : 0u;
}
