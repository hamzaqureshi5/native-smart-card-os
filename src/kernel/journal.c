/* SPDX-License-Identifier: MIT
 *
 * journal.c -- the undo log.
 *
 * ON-NVM LAYOUT, hand-serialised big-endian like everything else that touches
 * NVM in this project. See fs_store.c for why a C struct is never written.
 *
 *   HEADER, at SCOS_EE_TXN_BASE
 *     0   2   magic 'T' 'X'
 *     2   1   layout version
 *     3   1   state          -- OUTSIDE the CRC; see below
 *     4   2   entry count
 *     6   2   total undo bytes used
 *     8   2   CRC-16 over bytes 0..2 and 4..7   (skips `state`)
 *     10      header size
 *
 *   ENTRIES, packed after the header, each:
 *     0   1   region         (hal_nvm_region)
 *     1   4   offset
 *     5   2   length
 *     7   n   the OLD bytes
 *
 * THE STATE BYTE IS OUTSIDE THE CRC, FOR THE THIRD TIME IN THIS PROJECT
 *
 * The boot loader's slot state and the PIN's retry tally are outside their
 * CRCs for the same underlying reason, and the reason is worth stating once
 * more because it is the load-bearing idea in all three: a field that must
 * change WITHOUT rewriting its container cannot be inside the container's
 * checksum. If commit had to update the CRC as well, commit would be three
 * bytes and two writes -- and a power cut between them leaves a journal whose
 * CRC says "corrupt", whose only safe reading is "roll back", which would undo
 * a transaction that had in fact committed.
 *
 * So the states are reachable by CLEARING BITS ONLY:
 *
 *   0xFF  EMPTY      nothing in progress
 *   0xF0  OPEN       a transaction is running; recovery must roll it back
 *   0x00  COMMITTED  finished; recovery must leave the data alone
 *
 * EMPTY -> OPEN -> COMMITTED is monotonic in bits, so a partial or glitched
 * write moves the journal FORWARD, never backward. Forward is the safe
 * direction: worst case a transaction that had not committed reads as
 * committed only if the byte reached 0x00, which requires the write to have
 * completed.
 *
 * Consider the alternative encoding, OPEN=1 COMMITTED=2, for a moment: a
 * half-written 2 could read as 0, 1, or 3, and two of those are wrong in the
 * dangerous direction.
 *
 * WHY RECOVERY DOES NOT NEED THE ENTRY DATA TO BE CRC-PROTECTED INDIVIDUALLY
 *
 * The header CRC covers the count and the byte total, so a header that passes
 * tells us exactly how many entries there are and how far they extend. If the
 * header fails its CRC we cannot trust the count, and a partial rollback is
 * worse than none -- so a corrupt header means the journal is discarded and NOT
 * replayed. That is a deliberate choice with a real consequence, recorded in
 * docs/roadmap.md: a card that loses power while WRITING THE JOURNAL ITSELF
 * comes back with the original data intact, because nothing had been modified
 * yet at that point. The order of operations is what makes that true, and it is
 * the one invariant in this file to preserve above all others:
 *
 *      SAVE THE OLD BYTES DURABLY, THEN WRITE THE NEW ONES.
 */
#include "os/journal.h"

#include "os/crc16.h"
#include "os/nvm_map.h"
#include "os/os_mem.h"

#define TXN_MAGIC_0 'T'
#define TXN_MAGIC_1 'X'
#define TXN_VERSION 1u

#define TXN_STATE_EMPTY     0xFFu
#define TXN_STATE_OPEN      0xF0u
#define TXN_STATE_COMMITTED 0x00u

#define TXN_HDR_MAGIC   0u
#define TXN_HDR_VERSION 2u
#define TXN_HDR_STATE   3u
#define TXN_HDR_COUNT   4u
#define TXN_HDR_USED    6u
#define TXN_HDR_CRC     8u
#define TXN_HDR_SIZE    10u

#define TXN_ENT_REGION   0u
#define TXN_ENT_OFFSET   1u
#define TXN_ENT_LENGTH   5u
#define TXN_ENT_DATA     7u
#define TXN_ENT_OVERHEAD TXN_ENT_DATA

#define TXN_DATA_BASE (SCOS_EE_TXN_BASE + TXN_HDR_SIZE)
#define TXN_DATA_SIZE (SCOS_EE_TXN_SIZE - TXN_HDR_SIZE)

/*
 * In-RAM mirror of the header. The journal is consulted on every write inside a
 * transaction, and re-reading ten bytes of EEPROM each time would be pure
 * waste -- but note what is NOT cached: the entries. Those are only ever read
 * during recovery, when the RAM copy does not exist.
 */
static struct {
    bool     open;
    uint16_t count;
    uint16_t used; /* undo bytes consumed, including per-entry overhead */
} g_txn;

/* ------------------------------------------------------------ raw access -- */
/*
 * The journal writes with hal_nvm_write() DIRECTLY, never through
 * scos_nvm_write(). Journaling the journal would recurse, and there is nothing
 * to protect: the journal's own consistency comes from the state byte and the
 * header CRC, not from a second copy of itself.
 */
static hal_status raw_write(uint32_t off, const void *src, uint32_t len)
{
    const hal_status st = hal_nvm_write(HAL_NVM_EEPROM, off, src, len);
    if (st != HAL_OK) {
        return st;
    }
    return hal_nvm_sync();
}

static hal_status raw_read(uint32_t off, void *dst, uint32_t len)
{ return hal_nvm_read(HAL_NVM_EEPROM, off, dst, len); }

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

static uint16_t get_u16(const uint8_t *p)
{ return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }

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

/* CRC over the header, skipping the state byte at offset 3. */
static uint16_t header_crc(const uint8_t *hdr)
{
    uint8_t tmp[TXN_HDR_CRC - 1u]; /* bytes 0..2 then 4..7 = 7 bytes */
    tmp[0] = hdr[0];
    tmp[1] = hdr[1];
    tmp[2] = hdr[2];
    tmp[3] = hdr[4];
    tmp[4] = hdr[5];
    tmp[5] = hdr[6];
    tmp[6] = hdr[7];
    return crc16(tmp, sizeof(tmp));
}

static void build_header(uint8_t *hdr, uint8_t state, uint16_t count,
                         uint16_t used)
{
    os_memset(hdr, 0, TXN_HDR_SIZE);
    hdr[TXN_HDR_MAGIC]      = TXN_MAGIC_0;
    hdr[TXN_HDR_MAGIC + 1u] = TXN_MAGIC_1;
    hdr[TXN_HDR_VERSION]    = TXN_VERSION;
    hdr[TXN_HDR_STATE]      = state;
    put_u16(&hdr[TXN_HDR_COUNT], count);
    put_u16(&hdr[TXN_HDR_USED], used);
    put_u16(&hdr[TXN_HDR_CRC], header_crc(hdr));
}

/* Read the header and validate it. */
static scos_txn_status load_header(uint8_t *hdr)
{
    if (raw_read(SCOS_EE_TXN_BASE, hdr, TXN_HDR_SIZE) != HAL_OK) {
        return SCOS_TXN_ERR_NVM;
    }
    if (hdr[TXN_HDR_MAGIC] != TXN_MAGIC_0 ||
        hdr[TXN_HDR_MAGIC + 1u] != TXN_MAGIC_1) {
        return SCOS_TXN_ERR_CORRUPT; /* includes a blank (0xFF) journal */
    }
    if (hdr[TXN_HDR_VERSION] != TXN_VERSION) {
        return SCOS_TXN_ERR_CORRUPT;
    }
    if (header_crc(hdr) != get_u16(&hdr[TXN_HDR_CRC])) {
        return SCOS_TXN_ERR_CORRUPT;
    }
    return SCOS_TXN_OK;
}

/*
 * Write ONLY the state byte.
 *
 * The commit primitive, and the reason the state byte sits outside the CRC:
 * one byte, one write, durable before returning. Nothing else in the header
 * changes, so nothing else can be half-written alongside it.
 */
static scos_txn_status set_state(uint8_t state)
{
    if (raw_write(SCOS_EE_TXN_BASE + TXN_HDR_STATE, &state, 1u) != HAL_OK) {
        return SCOS_TXN_ERR_NVM;
    }
    return SCOS_TXN_OK;
}

/* ---------------------------------------------------------------- public -- */

uint32_t scos_txn_capacity(void)
{ return TXN_DATA_SIZE; }

scos_txn_status scos_txn_format(void)
{
    uint8_t hdr[TXN_HDR_SIZE];
    build_header(hdr, TXN_STATE_EMPTY, 0u, 0u);
    if (raw_write(SCOS_EE_TXN_BASE, hdr, TXN_HDR_SIZE) != HAL_OK) {
        return SCOS_TXN_ERR_NVM;
    }
    g_txn.open  = false;
    g_txn.count = 0u;
    g_txn.used  = 0u;
    return SCOS_TXN_OK;
}

bool scos_txn_open(void)
{ return g_txn.open; }

scos_txn_status scos_txn_begin(void)
{
    if (g_txn.open) {
        /* See the header comment: no nesting, and the caller must handle it
         * rather than have an inner commit silently do nothing. */
        return SCOS_TXN_ERR_NESTED;
    }

    uint8_t hdr[TXN_HDR_SIZE];
    build_header(hdr, TXN_STATE_OPEN, 0u, 0u);

    /*
     * The whole header, including the OPEN state, written before any data
     * changes. If power goes here the journal reads OPEN with zero entries, so
     * recovery rolls back nothing -- correct, because nothing was written.
     */
    if (raw_write(SCOS_EE_TXN_BASE, hdr, TXN_HDR_SIZE) != HAL_OK) {
        return SCOS_TXN_ERR_NVM;
    }
    g_txn.open  = true;
    g_txn.count = 0u;
    g_txn.used  = 0u;
    return SCOS_TXN_OK;
}

scos_txn_status scos_txn_commit(void)
{
    if (!g_txn.open) {
        return SCOS_TXN_ERR_NONE_OPEN;
    }
    /*
     * One byte, and after this instant the transaction is durable. Everything
     * it wrote is already in place -- that is what undo journaling buys.
     */
    const scos_txn_status st = set_state(TXN_STATE_COMMITTED);
    if (st != SCOS_TXN_OK) {
        return st;
    }
    g_txn.open = false;

    /* Reset to EMPTY so the next transaction starts from a known state. If
     * power goes between the two writes the journal reads COMMITTED, and
     * recovery leaves the data alone -- correct. */
    return scos_txn_format();
}

/* Undo every entry, newest first. */

/*
 * Find the byte offset of entry `want` by walking forward from the start.
 *
 * O(n) per lookup and therefore O(n^2) for a full rollback, which is
 * deliberate. The obvious implementation records every entry's offset in an
 * array first -- and at 2 KB of journal that array is 292 uint32_t, 1,168
 * bytes of STACK. Stack is the one kind of RAM this project does not account
 * for: the _Static_assert measures sizeof(scos_kernel), so a frame that large
 * would be invisible to the budget it blows, on the code path that runs when
 * the card is already in trouble.
 *
 * A transaction has a handful of entries, this runs once per boot at most, and
 * the card has 14 MHz to spare. Quadratic over ten items is free; 1 KB of
 * stack during recovery is not.
 */
static scos_txn_status entry_offset(uint16_t want, uint16_t count,
                                    uint16_t used, uint32_t *out_at,
                                    uint16_t *out_len)
{
    uint32_t pos = 0u;
    for (uint16_t i = 0; i <= want && i < count; i++) {
        if (pos + TXN_ENT_OVERHEAD > used ||
            pos + TXN_ENT_OVERHEAD > TXN_DATA_SIZE) {
            return SCOS_TXN_ERR_CORRUPT;
        }
        uint8_t ent[TXN_ENT_OVERHEAD];
        if (raw_read(TXN_DATA_BASE + pos, ent, TXN_ENT_OVERHEAD) != HAL_OK) {
            return SCOS_TXN_ERR_NVM;
        }
        const uint16_t len = get_u16(&ent[TXN_ENT_LENGTH]);
        /* A zero length or one that runs past `used` means the header's count
         * and the entry stream disagree. The header CRC passed, so this is a
         * damaged entry area rather than a damaged header -- either way the
         * stream cannot be trusted and a partial rollback is worse than none. */
        if (len == 0u || pos + TXN_ENT_OVERHEAD + len > used) {
            return SCOS_TXN_ERR_CORRUPT;
        }
        if (i == want) {
            *out_at  = pos;
            *out_len = len;
            return SCOS_TXN_OK;
        }
        pos += TXN_ENT_OVERHEAD + len;
    }
    return SCOS_TXN_ERR_CORRUPT;
}

static scos_txn_status rollback(uint16_t count, uint16_t used)
{
    /*
     * NEWEST FIRST, and it matters. If two entries cover overlapping bytes --
     * which happens when one command writes the same descriptor twice --
     * restoring oldest-first would leave the SECOND entry's saved value in
     * place, and that value is the state after the first write, not before it.
     * Reverse order restores the true original.
     */
    for (uint16_t i = count; i > 0u; i--) {
        uint32_t              at  = 0u;
        uint16_t              len = 0u;
        const scos_txn_status est =
            entry_offset((uint16_t)(i - 1u), count, used, &at, &len);
        if (est != SCOS_TXN_OK) {
            return est;
        }

        uint8_t ent[TXN_ENT_OVERHEAD];
        if (raw_read(TXN_DATA_BASE + at, ent, TXN_ENT_OVERHEAD) != HAL_OK) {
            return SCOS_TXN_ERR_NVM;
        }
        const hal_nvm_region region = (hal_nvm_region)ent[TXN_ENT_REGION];
        const uint32_t       offset = get_u32(&ent[TXN_ENT_OFFSET]);

        /* Restore in chunks, so this frame stays a fixed 64 bytes whatever the
         * entry's size. Same reasoning as READ BINARY. */
        enum { CHUNK = 64u };
        uint8_t  buf[CHUNK];
        uint16_t done = 0u;
        while (done < len) {
            uint16_t take = (uint16_t)(len - done);
            if (take > CHUNK) {
                take = CHUNK;
            }
            if (raw_read(TXN_DATA_BASE + at + TXN_ENT_DATA + done, buf, take) !=
                HAL_OK) {
                return SCOS_TXN_ERR_NVM;
            }
            if (hal_nvm_write(region, offset + done, buf, take) != HAL_OK) {
                return SCOS_TXN_ERR_NVM;
            }
            done = (uint16_t)(done + take);
        }
    }

    return (hal_nvm_sync() == HAL_OK) ? SCOS_TXN_OK : SCOS_TXN_ERR_NVM;
}

scos_txn_status scos_txn_abort(void)
{
    if (!g_txn.open) {
        return SCOS_TXN_ERR_NONE_OPEN;
    }
    const scos_txn_status st = rollback(g_txn.count, g_txn.used);
    g_txn.open               = false;
    /* Format even if the rollback failed: leaving an OPEN journal behind would
     * make the next boot try the same failing rollback for ever. The data may
     * be inconsistent, and that is reported -- but the card is not bricked. */
    (void)scos_txn_format();
    return st;
}

scos_txn_status scos_txn_recover(void)
{
    uint8_t               hdr[TXN_HDR_SIZE];
    const scos_txn_status hst = load_header(hdr);

    if (hst == SCOS_TXN_ERR_CORRUPT) {
        /*
         * A blank or damaged journal. Formatted, NOT replayed.
         *
         * A partial rollback is worse than none: it would restore some bytes of
         * a multi-write operation and leave others, producing a state neither
         * the old nor the new one. And because the old bytes are saved BEFORE
         * any data changes, a card that lost power while writing the journal
         * itself has not yet modified anything -- so discarding is not merely
         * the safe choice, it is the correct one.
         */
        return scos_txn_format();
    }
    if (hst != SCOS_TXN_OK) {
        return hst;
    }

    const uint8_t state = hdr[TXN_HDR_STATE];
    if (state == TXN_STATE_COMMITTED || state == TXN_STATE_EMPTY) {
        /* Finished, or nothing was running. The data stands. */
        return scos_txn_format();
    }

    /*
     * OPEN, or a state byte that is neither of the known ones -- a partially
     * written state. Both are rolled back.
     *
     * Treating an unrecognised state as "roll back" is the safe reading: the
     * only way to reach COMMITTED is a completed write of 0x00, so anything
     * else means the commit did not complete, which means the transaction did
     * not commit.
     */
    const scos_txn_status rst =
        rollback(get_u16(&hdr[TXN_HDR_COUNT]), get_u16(&hdr[TXN_HDR_USED]));
    (void)scos_txn_format();
    return rst;
}

hal_status scos_nvm_write(hal_nvm_region region, uint32_t offset,
                          const void *src, uint32_t len)
{
    if (src == NULL) {
        return HAL_ERR_PARAM;
    }
    if (len == 0u) {
        return HAL_OK;
    }
    if (!g_txn.open) {
        /* No transaction: straight through. Not every write needs one -- see
         * the PIN retry counter, which must NOT be transactional. */
        return hal_nvm_write(region, offset, src, len);
    }

    /* Does the undo data fit? */
    const uint32_t need = (uint32_t)TXN_ENT_OVERHEAD + len;
    if ((uint32_t)g_txn.used + need > TXN_DATA_SIZE) {
        /*
         * REFUSED, and the write does not happen.
         *
         * The alternative -- perform it unprotected -- is the one outcome worse
         * than failing: the caller receives success for an operation that a
         * power cut can now corrupt, and nothing anywhere records that this
         * particular write was not covered.
         */
        return HAL_ERR_RANGE;
    }

    /* Read the OLD bytes and build the entry. */
    uint8_t ent[TXN_ENT_OVERHEAD];
    ent[TXN_ENT_REGION] = (uint8_t)region;
    put_u32(&ent[TXN_ENT_OFFSET], offset);
    put_u16(&ent[TXN_ENT_LENGTH], (uint16_t)len);

    const uint32_t at = TXN_DATA_BASE + g_txn.used;
    if (raw_write(at, ent, TXN_ENT_OVERHEAD) != HAL_OK) {
        return HAL_ERR_IO;
    }

    /* Copy the old bytes across in chunks, so this frame stays small. */
    {
        enum { CHUNK = 64u };
        uint8_t  buf[CHUNK];
        uint32_t done = 0u;
        while (done < len) {
            uint32_t take = len - done;
            if (take > CHUNK) {
                take = CHUNK;
            }
            if (hal_nvm_read(region, offset + done, buf, take) != HAL_OK) {
                return HAL_ERR_IO;
            }
            if (raw_write(at + TXN_ENT_DATA + done, buf, take) != HAL_OK) {
                return HAL_ERR_IO;
            }
            done += take;
        }
    }

    /*
     * Publish the entry by updating the header count and byte total.
     *
     * AFTER the entry's bytes are durable, so an entry is never counted before
     * it exists -- recovery would otherwise read a length field from
     * uninitialised journal space and roll back garbage over live data, which
     * is the worst thing this file could do.
     */
    uint8_t hdr[TXN_HDR_SIZE];
    build_header(hdr, TXN_STATE_OPEN, (uint16_t)(g_txn.count + 1u),
                 (uint16_t)(g_txn.used + need));
    if (raw_write(SCOS_EE_TXN_BASE, hdr, TXN_HDR_SIZE) != HAL_OK) {
        return HAL_ERR_IO;
    }
    g_txn.count = (uint16_t)(g_txn.count + 1u);
    g_txn.used  = (uint16_t)(g_txn.used + need);

    /* ONLY NOW is the new data written. Everything above exists so that this
     * line can be undone. */
    return hal_nvm_write(region, offset, src, len);
}
