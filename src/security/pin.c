/* SPDX-License-Identifier: MIT
 *
 * pin.c -- the PIN object and its retry counter.
 *
 * THE RECORD, HAND-SERIALISED
 *
 * Never a C struct written to NVM, for the reason fs_store.c gives: padding
 * and endianness are compiler- and target-dependent, and a card that stops
 * recognising its own PIN after a toolchain change is a brick.
 *
 *   off  len  field
 *   0    2    magic 'P' 'N'
 *   2    1    layout version
 *   3    1    state          (pin_state)
 *   4    1    try_limit      1..8
 *   5    1    tries          UNARY TALLY -- see below
 *   6    2    reserved, zero
 *   8    16   salt
 *   24   32   verifier = SHA-256(salt || value)
 *   56   2    CRC-16 over bytes 0..53   <-- NOTE: excludes `tries`
 *   58        total
 *
 * WHY `tries` IS A UNARY TALLY AND NOT A NUMBER
 *
 * The counter must be decremented durably before the PIN is compared. If it
 * were an integer, spending a try would mean writing the count AND updating
 * the record's CRC -- three bytes, two writes, not atomic. A power cut between
 * them leaves a record whose CRC says it is corrupt, and the only safe reading
 * of a corrupt PIN record is "blocked", so an attacker could brick a card by
 * timing a power cut. Worse, a naive implementation might instead treat it as
 * "restore from the last good value", which hands the try back.
 *
 * So `tries` is a bitmap: the number of tries left is the number of set bits.
 * Spending a try clears the lowest set bit, which is ONE byte write, and it
 * only ever clears bits. That gives three properties at once:
 *
 *   atomic       one byte, so a power cut leaves either the old value or the
 *                new one, and both are valid counts
 *   monotonic    a partial or glitched write can only lose bits, and losing a
 *                bit loses a TRY -- the safe direction
 *   CRC-free     every one of the 256 possible bytes maps to a well-defined
 *                count, so the field does not need integrity protection to be
 *                interpretable, and can therefore be excluded from the CRC
 *
 * That last point is why the CRC covers bytes 0..53 rather than 0..55. It is
 * the same trick as the boot loader's state word in src/boot/boot_hdr.c, and
 * for the same underlying reason: a field that must change without rewriting
 * its container needs to be outside the checksum.
 *
 * KNOWN LIMITATION: excluding `tries` from the CRC means a fault that SETS a
 * bit gives back a try. Setting bits in EEPROM is a harder fault to induce
 * than clearing them, and this project models no physical protection at all,
 * so the honest statement is that the counter resists power interruption and
 * says nothing about active fault injection. Tracked in docs/threat-model.md.
 */
#include "security/pin.h"

#include "crypto/crypto.h"
#include "hal/hal.h"
#include "os/crc16.h"
#include "os/nvm_map.h"
#include "os/os_mem.h"

#define PIN_MAGIC_0 'P'
#define PIN_MAGIC_1 'N'
#define PIN_VERSION 1u

#define PIN_SALT_LEN 16u

#define PIN_OFF_MAGIC     0u
#define PIN_OFF_VERSION   2u
#define PIN_OFF_STATE     3u
#define PIN_OFF_TRY_LIMIT 4u
#define PIN_OFF_TRIES     5u
#define PIN_OFF_RESERVED  6u
#define PIN_OFF_SALT      8u
#define PIN_OFF_VERIFIER  24u
#define PIN_OFF_CRC       56u
#define PIN_RECORD_SIZE   58u

/* The CRC covers everything up to `tries`, then resumes after it. Rather than
 * two ranges, the layout puts `tries` at offset 5 and the CRC covers 0..4 plus
 * 6..55 -- expressed as two spans below, because a single span would have to
 * include the field it must not. */
#define PIN_CRC_SPAN1_OFF 0u
#define PIN_CRC_SPAN1_LEN 5u /* magic, version, state, try_limit        */
#define PIN_CRC_SPAN2_OFF 6u
#define PIN_CRC_SPAN2_LEN 50u /* reserved, salt, verifier               */

_Static_assert(PIN_RECORD_SIZE *SEC_MAX_PIN_REFS <= SCOS_EE_SEC_SIZE,
               "PIN records do not fit the security store region");

static bool g_mounted = false;

static uint32_t record_offset(uint8_t ref)
{
    /* ref is 1-based, so reference 1 lands at the base of the region. */
    return SCOS_EE_SEC_BASE + (((uint32_t)ref - 1u) * PIN_RECORD_SIZE);
}

static bool ref_valid(uint8_t ref)
{ return ref >= 1u && ref <= SEC_MAX_PIN_REFS; }

static uint16_t record_crc(const uint8_t *rec)
{
    /* Two spans, skipping `tries`. crc16() is not incremental, so the bytes
     * are gathered first -- 55 bytes on the stack, once per PIN operation. */
    uint8_t tmp[PIN_CRC_SPAN1_LEN + PIN_CRC_SPAN2_LEN];
    os_memcpy_checked(tmp, sizeof(tmp), &rec[PIN_CRC_SPAN1_OFF],
                      PIN_CRC_SPAN1_LEN);
    os_memcpy_checked(&tmp[PIN_CRC_SPAN1_LEN], sizeof(tmp) - PIN_CRC_SPAN1_LEN,
                      &rec[PIN_CRC_SPAN2_OFF], PIN_CRC_SPAN2_LEN);
    return crc16(tmp, sizeof(tmp));
}

/* Number of tries left: the population count of the tally byte. */
static uint8_t tries_from_tally(uint8_t tally)
{
    uint8_t n = 0u;
    for (uint8_t i = 0; i < 8u; i++) {
        if ((tally & (uint8_t)(1u << i)) != 0u) {
            n++;
        }
    }
    return n;
}

/* A full tally for `limit` tries: the low `limit` bits set. */
static uint8_t tally_for_limit(uint8_t limit)
{
    if (limit >= 8u) {
        return 0xFFu;
    }
    return (uint8_t)((1u << limit) - 1u);
}

/* Clear the lowest set bit. This is the decrement, and it is the only
 * modification the counter ever undergoes. */
static uint8_t tally_spend(uint8_t tally)
{
    if (tally == 0u) {
        return 0u;
    }
    /* t & (t-1) clears the lowest set bit -- and only ever clears. */
    return (uint8_t)(tally & (uint8_t)(tally - 1u));
}

static pin_status read_record(uint8_t ref, uint8_t *rec)
{
    if (hal_nvm_read(HAL_NVM_EEPROM, record_offset(ref), rec,
                     PIN_RECORD_SIZE) != HAL_OK) {
        return PIN_ERR_NVM;
    }
    if (rec[PIN_OFF_MAGIC] != PIN_MAGIC_0 ||
        rec[PIN_OFF_MAGIC + 1u] != PIN_MAGIC_1) {
        return PIN_ERR_NOT_FOUND;
    }
    if (rec[PIN_OFF_VERSION] != PIN_VERSION) {
        /* A layout we do not understand is NOT auto-migrated. Guessing at the
         * meaning of a PIN record is the last thing to guess at. */
        return PIN_ERR_CORRUPT;
    }
    const uint16_t want =
        (uint16_t)(((uint16_t)rec[PIN_OFF_CRC] << 8) | rec[PIN_OFF_CRC + 1u]);
    if (record_crc(rec) != want) {
        return PIN_ERR_CORRUPT;
    }
    return PIN_OK;
}

static pin_status write_record(uint8_t ref, uint8_t *rec)
{
    const uint16_t crc    = record_crc(rec);
    rec[PIN_OFF_CRC]      = (uint8_t)(crc >> 8);
    rec[PIN_OFF_CRC + 1u] = (uint8_t)(crc & 0xFFu);
    if (hal_nvm_write(HAL_NVM_EEPROM, record_offset(ref), rec,
                      PIN_RECORD_SIZE) != HAL_OK) {
        return PIN_ERR_NVM;
    }
    if (hal_nvm_sync() != HAL_OK) {
        return PIN_ERR_NVM;
    }
    return PIN_OK;
}

/*
 * Write ONLY the tally byte, and flush.
 *
 * Separate from write_record() because it must not touch the CRC or any other
 * field: one byte, one write, durable before returning. That is the whole
 * mechanism by which a failed attempt cannot be undone.
 */
static pin_status commit_tally(uint8_t ref, uint8_t tally)
{
    const uint32_t off = record_offset(ref) + PIN_OFF_TRIES;
    if (hal_nvm_write(HAL_NVM_EEPROM, off, &tally, 1u) != HAL_OK) {
        return PIN_ERR_NVM;
    }
    /* The sync is not optional and not an optimisation to skip. Without it the
     * decrement might live only in a cache that power removal discards, which
     * is exactly the attack this design exists to stop. */
    if (hal_nvm_sync() != HAL_OK) {
        return PIN_ERR_NVM;
    }
    return PIN_OK;
}

/* verifier = SHA-256(salt || value). */
static pin_status compute_verifier(const uint8_t *salt, const uint8_t *value,
                                   uint8_t len, uint8_t out[32])
{
    crypto_sha256_ctx c;
    crypto_sha256_init(&c);
    crypto_sha256_update(&c, salt, PIN_SALT_LEN);
    crypto_sha256_update(&c, value, len);
    if (crypto_sha256_final(&c, out) != CRYPTO_OK) {
        return PIN_ERR_PARAM;
    }
    return PIN_OK;
}

static void fill_info(const uint8_t *rec, pin_info *out)
{
    if (out == NULL) {
        return;
    }
    out->state      = (pin_state)rec[PIN_OFF_STATE];
    out->try_limit  = rec[PIN_OFF_TRY_LIMIT];
    out->tries_left = tries_from_tally(rec[PIN_OFF_TRIES]);
}

/* ---------------------------------------------------------------- public -- */

pin_status pin_personalise(void)
{
    /*
     * Every reference is written as UNSET, not as a default PIN.
     *
     * A fixed factory PIN in source would be a published credential: every
     * card built from this tree would ship with the same one, and the value
     * would be in the git history for good. Real cards receive a transport PIN
     * during personalisation, from data that is not in the source tree, and
     * until this project has a personalisation step there is nothing honest to
     * put here.
     *
     * The consequence is that VERIFY answers 6985 until a PIN is set, which is
     * the correct thing for a card with no cardholder credential rather than a
     * gap to be papered over.
     */
    for (uint8_t ref = 1u; ref <= SEC_MAX_PIN_REFS; ref++) {
        uint8_t rec[PIN_RECORD_SIZE];
        os_memset(rec, 0, sizeof(rec));
        rec[PIN_OFF_MAGIC]      = PIN_MAGIC_0;
        rec[PIN_OFF_MAGIC + 1u] = PIN_MAGIC_1;
        rec[PIN_OFF_VERSION]    = PIN_VERSION;
        rec[PIN_OFF_STATE]      = (uint8_t)PIN_STATE_UNSET;
        rec[PIN_OFF_TRY_LIMIT]  = 0u;
        rec[PIN_OFF_TRIES]      = 0u;
        const pin_status st     = write_record(ref, rec);
        if (st != PIN_OK) {
            return st;
        }
    }
    g_mounted = true;
    return PIN_OK;
}

pin_status pin_init(void)
{
    uint8_t          rec[PIN_RECORD_SIZE];
    const pin_status st = read_record(PIN_REF_USER, rec);
    if (st == PIN_ERR_NOT_FOUND) {
        /* Blank store on a blank chip: format it. */
        return pin_personalise();
    }
    if (st != PIN_OK) {
        return st;
    }
    g_mounted = true;
    return PIN_OK;
}

pin_status pin_set(uint8_t ref, const uint8_t *value, uint8_t len,
                   uint8_t try_limit)
{
    if (!ref_valid(ref) || value == NULL) {
        return PIN_ERR_PARAM;
    }
    if (len < PIN_MIN_LEN || len > PIN_MAX_LEN) {
        return PIN_ERR_PARAM;
    }
    if (try_limit == 0u || try_limit > PIN_MAX_TRY_LIMIT) {
        return PIN_ERR_PARAM;
    }

    uint8_t          rec[PIN_RECORD_SIZE];
    const pin_status rst = read_record(ref, rec);
    if (rst != PIN_OK && rst != PIN_ERR_NOT_FOUND) {
        return rst;
    }
    os_memset(rec, 0, sizeof(rec));
    rec[PIN_OFF_MAGIC]      = PIN_MAGIC_0;
    rec[PIN_OFF_MAGIC + 1u] = PIN_MAGIC_1;
    rec[PIN_OFF_VERSION]    = PIN_VERSION;

    /* Fresh salt, from the TRNG, refusing rather than substituting. */
    if (crypto_random_bytes(&rec[PIN_OFF_SALT], PIN_SALT_LEN) != CRYPTO_OK) {
        crypto_wipe(rec, sizeof(rec));
        return PIN_ERR_ENTROPY;
    }

    if (compute_verifier(&rec[PIN_OFF_SALT], value, len,
                         &rec[PIN_OFF_VERIFIER]) != PIN_OK) {
        crypto_wipe(rec, sizeof(rec));
        return PIN_ERR_PARAM;
    }

    rec[PIN_OFF_STATE]     = (uint8_t)PIN_STATE_ACTIVE;
    rec[PIN_OFF_TRY_LIMIT] = try_limit;
    rec[PIN_OFF_TRIES]     = tally_for_limit(try_limit);

    const pin_status wst = write_record(ref, rec);
    /* The record held the verifier; the value it was derived from is the
     * caller's. Wipe our copy either way. */
    crypto_wipe(rec, sizeof(rec));
    return wst;
}

pin_status pin_verify(uint8_t ref, const uint8_t *value, uint8_t len,
                      pin_info *out)
{
    if (!ref_valid(ref) || value == NULL) {
        return PIN_ERR_PARAM;
    }

    uint8_t          rec[PIN_RECORD_SIZE];
    const pin_status rst = read_record(ref, rec);
    if (rst != PIN_OK) {
        return rst;
    }
    fill_info(rec, out);

    if (rec[PIN_OFF_STATE] == (uint8_t)PIN_STATE_UNSET) {
        return PIN_ERR_UNSET;
    }
    if (rec[PIN_OFF_STATE] == (uint8_t)PIN_STATE_BLOCKED) {
        return PIN_ERR_BLOCKED;
    }

    const uint8_t tally = rec[PIN_OFF_TRIES];
    if (tries_from_tally(tally) == 0u) {
        /*
         * Already exhausted but not yet marked. This is reachable: the tally is
         * outside the CRC and is written before the state, so a power cut
         * between spending the last try and recording BLOCKED lands here.
         * Finish the job rather than treating it as a usable state.
         */
        rec[PIN_OFF_STATE] = (uint8_t)PIN_STATE_BLOCKED;
        (void)write_record(ref, rec);
        fill_info(rec, out);
        return PIN_ERR_BLOCKED;
    }

    /*
     * ================= THE ORDERING THAT MATTERS =================
     *
     * Spend the try and make it durable BEFORE looking at `value`. Every other
     * order is broken:
     *
     *   compare, then decrement on failure   -- power cut after a wrong PIN
     *                                           and the try is back. Ten
     *                                           thousand attempts on a 4-digit
     *                                           PIN.
     *   decrement without syncing            -- same, if the write is cached.
     *   decrement after any early return     -- the returns above are for
     *                                           states where no attempt is
     *                                           possible, which is why they
     *                                           come first.
     *
     * The cost is that a power cut during a CORRECT attempt loses a try. That
     * is the right direction to fail, and it is why the counter is restored
     * only after a match is confirmed.
     */
    const uint8_t    spent = tally_spend(tally);
    const pin_status cst   = commit_tally(ref, spent);
    if (cst != PIN_OK) {
        return cst;
    }
    rec[PIN_OFF_TRIES] = spent;
    fill_info(rec, out);

    /* Only now is the value examined. */
    uint8_t          candidate[32];
    const pin_status vst =
        compute_verifier(&rec[PIN_OFF_SALT], value, len, candidate);
    if (vst != PIN_OK) {
        crypto_wipe(candidate, sizeof(candidate));
        return vst;
    }

    const bool match = crypto_equal_ct(candidate, &rec[PIN_OFF_VERIFIER], 32u);
    crypto_wipe(candidate, sizeof(candidate));

    if (match) {
        /* Restore the counter. Full record write, because try_limit and state
         * are involved and none of it is on the attack path -- correctness
         * here does not need to be atomic, since a power cut simply leaves the
         * consumed try, which is safe. */
        rec[PIN_OFF_TRIES]   = tally_for_limit(rec[PIN_OFF_TRY_LIMIT]);
        const pin_status wst = write_record(ref, rec);
        fill_info(rec, out);
        crypto_wipe(rec, sizeof(rec));
        return (wst == PIN_OK) ? PIN_OK : wst;
    }

    if (tries_from_tally(spent) == 0u) {
        rec[PIN_OFF_STATE] = (uint8_t)PIN_STATE_BLOCKED;
        (void)write_record(ref, rec);
        fill_info(rec, out);
        crypto_wipe(rec, sizeof(rec));
        return PIN_ERR_BLOCKED;
    }

    crypto_wipe(rec, sizeof(rec));
    return PIN_ERR_WRONG;
}

pin_status pin_unblock(uint8_t ref)
{
    if (!ref_valid(ref)) {
        return PIN_ERR_PARAM;
    }

    uint8_t          rec[PIN_RECORD_SIZE];
    const pin_status rst = read_record(ref, rec);
    if (rst != PIN_OK) {
        return rst;
    }

    if (rec[PIN_OFF_STATE] == (uint8_t)PIN_STATE_UNSET) {
        /* Nothing to unblock: there is no credential here. Reporting success
         * would tell a caller the PIN is usable when no PIN exists. */
        return PIN_ERR_UNSET;
    }
    if (rec[PIN_OFF_TRY_LIMIT] == 0u ||
        rec[PIN_OFF_TRY_LIMIT] > PIN_MAX_TRY_LIMIT) {
        /* A record whose limit is nonsense cannot have a counter restored to
         * it. Corrupt rather than repaired: guessing a retry limit is guessing
         * how many attempts an attacker gets. */
        return PIN_ERR_CORRUPT;
    }

    rec[PIN_OFF_STATE] = (uint8_t)PIN_STATE_ACTIVE;
    rec[PIN_OFF_TRIES] = tally_for_limit(rec[PIN_OFF_TRY_LIMIT]);

    const pin_status wst = write_record(ref, rec);
    crypto_wipe(rec, sizeof(rec));
    return wst;
}

pin_status pin_get(uint8_t ref, pin_info *out)
{
    if (!ref_valid(ref) || out == NULL) {
        return PIN_ERR_PARAM;
    }
    uint8_t          rec[PIN_RECORD_SIZE];
    const pin_status st = read_record(ref, rec);
    if (st != PIN_OK) {
        return st;
    }
    fill_info(rec, out);
    return PIN_OK;
}
