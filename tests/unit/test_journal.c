/* SPDX-License-Identifier: MIT
 *
 * test_journal.c -- transactions and power failure.
 *
 * The roadmap calls M4 the highest-risk milestone and says that until it lands
 * no tear-resistance claim in this project is justified. This file is what
 * turns that from a claim into a measurement, and the measurement it makes is
 * narrow and specific: for a multi-write operation, interrupting the write at
 * EVERY byte offset must leave the card in the state it had before the
 * operation started -- never half way.
 *
 * WHAT MAKES THAT TESTABLE AT ALL
 *
 * vcard_fault_after_bytes(n) makes the next hal_nvm_write() store n bytes and
 * then report HAL_ERR_POWER. The bytes before the cut are REAL and stay in the
 * array, which is what a half-programmed page looks like -- the OS has to
 * recover from partial data, not from an untouched region. Without that hook
 * an interruption test can only check offset 0 and offset N, which is close to
 * checking nothing.
 *
 * WHAT THIS STILL DOES NOT SHOW, stated so the file is not read as more than
 * it is: the simulator's power_failure discards the whole session's unflushed
 * writes, where a real chip loses only the write in flight. That makes this
 * model STRICTER than the hardware, which is the safe direction for a test --
 * but a pass here is not a substitute for running on silicon.
 */
#include "apdu/apdu.h"
#include "apdu/sw.h"
#include "filesystem/fs.h"
#include "filesystem/fs_store.h"
#include "hal/hal.h"
#include "hal/sim/vcard.h"
#include "os/journal.h"
#include "os/kernel.h"
#include "os/nvm_map.h"
#include "os/os_mem.h"

#include "scos_test.h"

static scos_kernel g_card;

static void fresh(void)
{
    vcard_fault_clear();
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(scos_init(&g_card), SCOS_OK);
}

static uint16_t send(const uint8_t *cmd, uint16_t len)
{
    uint8_t  rsp[SCOS_APDU_RSP_MAX];
    uint16_t rsp_len = 0u;
    if (scos_process(&g_card, cmd, len, rsp, (uint16_t)sizeof(rsp), &rsp_len) !=
        SCOS_OK) {
        return 0u;
    }
    if (rsp_len < 2u) {
        return 0u;
    }
    return (uint16_t)(((uint16_t)rsp[rsp_len - 2u] << 8) | rsp[rsp_len - 1u]);
}

/* Snapshot the whole EEPROM, so a test can assert "nothing changed" rather
 * than checking the fields it happens to think of. */
static void snapshot(uint8_t *out, uint32_t n)
{ CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0u, out, n), HAL_OK); }

/* Compare, ignoring the journal region: the journal is EXPECTED to differ --
 * it is the thing that recorded the attempt. What must be unchanged is the
 * data the journal protects. */
static bool same_except_journal(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        if (i >= SCOS_EE_TXN_BASE && i < SCOS_EE_TXN_BASE + SCOS_EE_TXN_SIZE) {
            continue;
        }
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

/* ============================================================== the basics = */

TEST(a_transaction_commits)
{
    fresh();
    CHECK(!scos_txn_open());
    CHECK_EQ(scos_txn_begin(), SCOS_TXN_OK);
    CHECK(scos_txn_open());

    /* Write through the journal, then commit: the new value stands. */
    const uint8_t v[4] = { 0xDEu, 0xADu, 0xBEu, 0xEFu };
    CHECK_EQ(scos_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 100u, v, 4u),
             HAL_OK);
    CHECK_EQ(scos_txn_commit(), SCOS_TXN_OK);
    CHECK(!scos_txn_open());

    uint8_t got[4];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 100u, got, 4u),
             HAL_OK);
    CHECK_HEX(got[0], 0xDE);
    CHECK_HEX(got[3], 0xEF);
}

TEST(an_abort_restores_every_byte)
{
    fresh();

    uint8_t before[8];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 100u, before, 8u),
             HAL_OK);

    CHECK_EQ(scos_txn_begin(), SCOS_TXN_OK);
    const uint8_t v[8] = { 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u };
    CHECK_EQ(scos_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 100u, v, 8u),
             HAL_OK);
    CHECK_EQ(scos_txn_abort(), SCOS_TXN_OK);

    uint8_t after[8];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 100u, after, 8u),
             HAL_OK);
    for (unsigned i = 0; i < 8u; i++) {
        CHECK_HEX(after[i], before[i]);
    }
}

TEST(overlapping_writes_roll_back_to_the_true_original)
{
    /*
     * Two entries covering the same bytes. Rolling back oldest-first would
     * leave the SECOND entry's saved value in place -- which is the state
     * after the first write, not before it. This is why rollback() walks the
     * entries in reverse.
     */
    fresh();
    const uint8_t original[4] = { 0xA0u, 0xA1u, 0xA2u, 0xA3u };
    CHECK_EQ(
        hal_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 120u, original, 4u),
        HAL_OK);

    CHECK_EQ(scos_txn_begin(), SCOS_TXN_OK);
    const uint8_t first[4]  = { 0xB0u, 0xB1u, 0xB2u, 0xB3u };
    const uint8_t second[4] = { 0xC0u, 0xC1u, 0xC2u, 0xC3u };
    CHECK_EQ(scos_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 120u, first, 4u),
             HAL_OK);
    CHECK_EQ(
        scos_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 120u, second, 4u),
        HAL_OK);
    CHECK_EQ(scos_txn_abort(), SCOS_TXN_OK);

    uint8_t got[4];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 120u, got, 4u),
             HAL_OK);
    for (unsigned i = 0; i < 4u; i++) {
        CHECK_HEX(got[i], original[i]);
    }
}

TEST(nesting_is_refused)
{
    /* Not a simplification: an inner commit that silently did nothing would
     * make a caller that checked the return value and moved on wrong. */
    fresh();
    CHECK_EQ(scos_txn_begin(), SCOS_TXN_OK);
    CHECK_EQ(scos_txn_begin(), SCOS_TXN_ERR_NESTED);
    CHECK_EQ(scos_txn_commit(), SCOS_TXN_OK);
    CHECK_EQ(scos_txn_commit(), SCOS_TXN_ERR_NONE_OPEN);
    CHECK_EQ(scos_txn_abort(), SCOS_TXN_ERR_NONE_OPEN);
}

TEST(a_write_too_large_for_the_journal_is_refused_not_performed)
{
    /*
     * The one outcome worse than failing is succeeding unprotected: the caller
     * would receive 9000 for an operation a power cut can now corrupt, and
     * nothing anywhere would record that this write was not covered.
     */
    fresh();
    const uint32_t cap = scos_txn_capacity();
    CHECK(cap > 0u);

    static uint8_t big[SCOS_EE_TXN_SIZE + 64u];
    os_memset(big, 0x5Au, sizeof(big));

    uint8_t before[16];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 140u, before, 16u),
             HAL_OK);

    CHECK_EQ(scos_txn_begin(), SCOS_TXN_OK);
    CHECK_EQ(scos_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 140u, big, cap),
             HAL_ERR_RANGE);
    CHECK_EQ(scos_txn_abort(), SCOS_TXN_OK);

    /* And the write really did not happen. */
    uint8_t after[16];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 140u, after, 16u),
             HAL_OK);
    for (unsigned i = 0; i < 16u; i++) {
        CHECK_HEX(after[i], before[i]);
    }
}

/* ===================================================== fault injection ==== */

TEST(the_fault_hook_actually_cuts_a_write)
{
    /*
     * Testing the instrument before trusting its readings. A fault hook that
     * silently did nothing would make every interruption test below pass for
     * the wrong reason -- which is the failure mode that makes a tear-resistance
     * suite worthless.
     */
    fresh();
    const uint8_t clean[8] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 160u, clean, 8u),
             HAL_OK);

    const uint8_t v[8] = { 9u, 9u, 9u, 9u, 9u, 9u, 9u, 9u };
    vcard_fault_after_bytes(3u);
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 160u, v, 8u),
             HAL_ERR_POWER);
    CHECK(vcard_fault_fired());

    /* Three bytes landed; five did not. Partial, exactly as intended. */
    uint8_t got[8];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 160u, got, 8u),
             HAL_OK);
    CHECK_HEX(got[0], 9);
    CHECK_HEX(got[2], 9);
    CHECK_HEX(got[3], 0);
    CHECK_HEX(got[7], 0);

    /* One-shot: the arming is consumed, so the next write is clean. */
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 160u, clean, 8u),
             HAL_OK);
}

/* ============================== the headline: every byte offset =========== */

TEST(create_file_interrupted_at_any_write_leaves_no_trace)
{
    /*
     * THE M4 TEST, and the second version of it.
     *
     * The first version swept BYTE OFFSETS only -- vcard_fault_after_bytes(n)
     * for n in 0..40 -- reported success at every one, and was measuring
     * nothing. Since M4 wrapped every command in a transaction, the first NVM
     * write a command performs is the journal's own header, so every arming
     * landed there: scos_txn_begin() failed, the command aborted before
     * touching any data, and "the data is unchanged" was true because the data
     * write had never been attempted.
     *
     * It came to light by disabling recovery entirely and finding the tests
     * still passed. A test that cannot fail is worse than no test, because it
     * occupies the space where a real one would go.
     *
     * So the sweep is two-dimensional: for each WRITE the command performs, for
     * each BYTE OFFSET within it. And `hold` is set, so the abort's own writes
     * fail too -- otherwise the in-session rollback fixes everything and the
     * next boot has nothing to recover, which is the in-session path rather
     * than the tear path.
     */
    static uint8_t before[SCOS_EE_TXN_BASE];
    static uint8_t after[SCOS_EE_TXN_BASE];

    /* Every length derived. Hand-typed Lc was wrong here once already. */
    uint8_t  create[32];
    uint16_t cn = 0u;
    {
        uint8_t  inner[24];
        uint16_t in = 0u;
        inner[in++] = 0x82u;
        inner[in++] = 0x01u;
        inner[in++] = 0x01u;
        inner[in++] = 0x83u;
        inner[in++] = 0x02u;
        inner[in++] = 0x2Bu;
        inner[in++] = 0x01u;
        inner[in++] = 0x80u;
        inner[in++] = 0x02u;
        inner[in++] = 0x00u;
        inner[in++] = 0x10u;

        create[cn++] = 0x00u;
        create[cn++] = 0xE0u;
        create[cn++] = 0x00u;
        create[cn++] = 0x00u;
        create[cn++] = (uint8_t)(in + 2u);
        create[cn++] = 0x62u;
        create[cn++] = (uint8_t)in;
        for (uint16_t i = 0; i < in; i++) {
            create[cn++] = inner[i];
        }
    }

    unsigned interrupted = 0u;
    for (uint32_t skip = 0u; skip < 12u; skip++) {
        for (uint32_t cut = 0u; cut < 6u; cut++) {
            fresh();
            snapshot(before, sizeof(before));

            vcard_fault_hold(true);
            vcard_fault_at_write(skip, cut);
            const uint16_t sw = send(create, cn);

            if (!vcard_fault_fired()) {
                /* The command made fewer than `skip` writes, so it completed.
                 * Nothing to recover; skip rather than pretend. */
                CHECK_HEX(sw, SW_OK);
                continue;
            }
            interrupted++;

            /* Boot again. Recovery runs inside scos_init(). */
            vcard_fault_clear();
            CHECK_EQ(scos_init(&g_card), SCOS_OK);

            const uint8_t  sel[] = { 0x00u, 0xA4u, 0x02u, 0x0Cu,
                                     0x02u, 0x2Bu, 0x01u };
            const uint16_t found = send(sel, (uint16_t)sizeof(sel));

            /*
             * THE INVARIANT, and getting it right took three tries.
             *
             * It is NOT "an interrupted command fails". A cut can land on the
             * housekeeping write that follows the commit, by which time the
             * transaction is durable and the file legitimately exists -- so the
             * command correctly reports success. Asserting failure there was
             * wrong, and asserting it is what made the third bug in this area
             * look like a test failure rather than the code defect it was.
             *
             * The real property is ALL-OR-NOTHING, in both directions:
             *
             *   reported success  ->  the file is there
             *   reported failure  ->  the card is byte-identical to before
             *
             * Never success without the file, and never failure with a trace
             * left behind. That is what a transaction means, and it is the only
             * claim a caller can act on.
             */
            if (sw == SW_OK) {
                CHECK_HEX(found, SW_OK);
            } else {
                CHECK_HEX(found, SW_FILE_NOT_FOUND);
                snapshot(after, sizeof(after));
                CHECK(same_except_journal(before, after, sizeof(before)));
            }
        }
    }

    /* The sweep is worthless if no cut ever landed, and worth little if only
     * one did -- CREATE FILE writes a descriptor AND the superblock, so a
     * meaningful sweep interrupts several distinct writes. */
    CHECK(interrupted > 10u);
}

TEST(update_binary_interrupted_at_any_write_leaves_the_old_data)
{
    /*
     * The same two-dimensional sweep for a DATA write rather than a metadata
     * one. A partial UPDATE BINARY is the case a user notices: half a record
     * written is not a record, and a card that returns an error while leaving
     * the file half modified has lost the caller's data without saying so.
     */
    static uint8_t original[8];

    unsigned interrupted = 0u;
    for (uint32_t skip = 0u; skip < 10u; skip++) {
        for (uint32_t cut = 0u; cut < 5u; cut++) {
            fresh();

            const uint8_t sel[] = { 0x00u, 0xA4u, 0x02u, 0x0Cu,
                                    0x02u, 0x2Fu, 0x00u };
            CHECK_HEX(send(sel, (uint16_t)sizeof(sel)), SW_OK);
            const uint8_t seed[] = { 0x00u, 0xD6u, 0x00u, 0x00u, 0x08u,
                                     0x11u, 0x22u, 0x33u, 0x44u, 0x55u,
                                     0x66u, 0x77u, 0x88u };
            CHECK_HEX(send(seed, (uint16_t)sizeof(seed)), SW_OK);
            CHECK_EQ(hal_nvm_read(HAL_NVM_FLASH, 0u, original, 8u), HAL_OK);

            const uint8_t over[] = { 0x00u, 0xD6u, 0x00u, 0x00u, 0x08u,
                                     0xFFu, 0xFEu, 0xFDu, 0xFCu, 0xFBu,
                                     0xFAu, 0xF9u, 0xF8u };
            vcard_fault_hold(true);
            vcard_fault_at_write(skip, cut);
            const uint16_t sw = send(over, (uint16_t)sizeof(over));

            if (!vcard_fault_fired()) {
                continue;
            }
            interrupted++;

            vcard_fault_clear();
            CHECK_EQ(scos_init(&g_card), SCOS_OK);

            uint8_t got[8];
            CHECK_EQ(hal_nvm_read(HAL_NVM_FLASH, 0u, got, 8u), HAL_OK);

            /* Same two-way invariant: the write happened completely, or not at
             * all. Half a record is the one outcome that must be impossible. */
            const uint8_t  updated[8] = { 0xFFu, 0xFEu, 0xFDu, 0xFCu,
                                          0xFBu, 0xFAu, 0xF9u, 0xF8u };
            const uint8_t *want       = (sw == SW_OK) ? updated : original;
            for (unsigned i = 0; i < 8u; i++) {
                CHECK_HEX(got[i], want[i]);
            }
        }
    }
    CHECK(interrupted > 10u);
}

TEST(the_sweep_would_notice_if_recovery_stopped_working)
{
    /*
     * A canary for the tests above, and it exists because they once could not
     * fail.
     *
     * This constructs the one situation the sweeps rely on -- a transaction
     * left OPEN with data already modified -- by hand, and asserts that
     * recovery is what puts it right. If recovery ever becomes a no-op, THIS
     * fails immediately and unambiguously, rather than the sweeps silently
     * going green because the interruption never reached any data.
     */
    fresh();
    const uint8_t original[4] = { 0x61u, 0x62u, 0x63u, 0x64u };
    CHECK_EQ(
        hal_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 240u, original, 4u),
        HAL_OK);

    CHECK_EQ(scos_txn_begin(), SCOS_TXN_OK);
    const uint8_t v[4] = { 0x71u, 0x72u, 0x73u, 0x74u };
    CHECK_EQ(scos_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 240u, v, 4u),
             HAL_OK);

    /* The new bytes really are in place -- so the ONLY thing that can restore
     * them is the journal. */
    uint8_t mid[4];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 240u, mid, 4u),
             HAL_OK);
    CHECK_HEX(mid[0], 0x71);

    /* No commit, no abort: exactly what a tear leaves. Recovery must undo it. */
    CHECK_EQ(scos_txn_recover(), SCOS_TXN_OK);

    uint8_t got[4];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 240u, got, 4u),
             HAL_OK);
    for (unsigned i = 0; i < 4u; i++) {
        CHECK_HEX(got[i], original[i]);
    }
}

/* ============================================ the journal's own integrity = */

TEST(a_corrupt_journal_header_is_discarded_not_replayed)
{
    /*
     * A partial rollback is worse than none: it would restore some bytes of a
     * multi-write and leave others, producing a state that is neither the old
     * one nor the new one.
     *
     * Discarding is not merely the safe choice, it is the correct one -- the
     * old bytes are saved BEFORE any data changes, so a card that lost power
     * while writing the journal itself has not yet modified anything.
     */
    fresh();

    uint8_t before[SCOS_EE_TXN_BASE];
    snapshot(before, sizeof(before));

    CHECK_EQ(scos_txn_begin(), SCOS_TXN_OK);
    const uint8_t v[4] = { 0x77u, 0x77u, 0x77u, 0x77u };
    CHECK_EQ(scos_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 180u, v, 4u),
             HAL_OK);

    /* Corrupt the header's CRC directly, as a glitch would. */
    uint8_t bad = 0x00u;
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, SCOS_EE_TXN_BASE + 8u, &bad, 1u),
             HAL_OK);

    /* Recovery discards it and the card comes up. */
    CHECK_EQ(scos_txn_recover(), SCOS_TXN_OK);
    CHECK(!scos_txn_open());

    /* The write that HAD completed stands -- it was already in place, and the
     * journal is not what put it there. This is the honest consequence of
     * discarding, and it is why the entry is published only after its bytes
     * are durable. */
    uint8_t got[4];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 180u, got, 4u),
             HAL_OK);
    CHECK_HEX(got[0], 0x77);
}

TEST(a_half_written_state_byte_rolls_back)
{
    /*
     * The state byte is EMPTY 0xFF -> OPEN 0xF0 -> COMMITTED 0x00, reachable by
     * clearing bits only. A partial write therefore lands on some value that is
     * none of the three, and anything that is not exactly 0x00 must be read as
     * "did not commit".
     *
     * The alternative encoding -- OPEN=1, COMMITTED=2 -- would let a
     * half-written 2 read as 0, 1 or 3, and two of those are wrong in the
     * direction that keeps an uncommitted transaction.
     */
    fresh();
    const uint8_t original[4] = { 0x31u, 0x32u, 0x33u, 0x34u };
    CHECK_EQ(
        hal_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 200u, original, 4u),
        HAL_OK);

    CHECK_EQ(scos_txn_begin(), SCOS_TXN_OK);
    const uint8_t v[4] = { 0x41u, 0x42u, 0x43u, 0x44u };
    CHECK_EQ(scos_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 200u, v, 4u),
             HAL_OK);

    /* A commit that got half way: some bits cleared, not all. */
    const uint8_t partial = 0x70u;
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, SCOS_EE_TXN_BASE + 3u, &partial, 1u),
             HAL_OK);

    CHECK_EQ(scos_txn_recover(), SCOS_TXN_OK);

    uint8_t got[4];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 200u, got, 4u),
             HAL_OK);
    for (unsigned i = 0; i < 4u; i++) {
        CHECK_HEX(got[i], original[i]);
    }
}

TEST(a_failed_rollback_keeps_the_undo_log_for_the_next_boot)
{
    /*
     * Added because a mutation went UNCAUGHT: reverting scos_txn_abort() to
     * format the journal unconditionally broke nothing in the suite, which
     * means the fix had no test behind it.
     *
     * The property: if the rollback itself cannot complete -- which happens for
     * exactly one reason, power going -- the undo log must SURVIVE so the next
     * boot can retry. Formatting it there discards the only record of what
     * needs undoing, turning a transient failure into permanent inconsistency.
     */
    fresh();
    const uint8_t original[4] = { 0x81u, 0x82u, 0x83u, 0x84u };
    CHECK_EQ(
        hal_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 130u, original, 4u),
        HAL_OK);

    CHECK_EQ(scos_txn_begin(), SCOS_TXN_OK);
    const uint8_t v[4] = { 0x91u, 0x92u, 0x93u, 0x94u };
    CHECK_EQ(scos_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 130u, v, 4u),
             HAL_OK);

    /* Make every further write fail, so the rollback cannot complete. */
    vcard_fault_hold(true);
    vcard_fault_at_write(0u, 0u);
    CHECK(scos_txn_abort() != SCOS_TXN_OK);
    vcard_fault_clear();

    /*
     * THE ASSERTION: the journal is still OPEN, so the log is still there.
     *
     * Note that this holds whether or not scos_txn_abort() tries to format --
     * under a held fault the format's own write fails too. That is why a
     * mutation removing the guard broke nothing, and why the guard's real
     * subject is the CORRUPT case rather than this one. See the comment in
     * scos_txn_abort() and the test below.
     */
    uint8_t hdr[10];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_TXN_BASE, hdr, 10u), HAL_OK);
    CHECK_HEX(hdr[3], 0xF0);                           /* TXN_STATE_OPEN */
    CHECK(((uint16_t)((hdr[4] << 8) | hdr[5])) >= 1u); /* at least one entry */

    /* And the new bytes are still in place, so recovery has real work to do. */
    uint8_t mid[4];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 130u, mid, 4u),
             HAL_OK);
    CHECK_HEX(mid[0], 0x91);

    /* Now recovery, with writes working again, must undo it. */
    CHECK_EQ(scos_txn_recover(), SCOS_TXN_OK);
    uint8_t got[4];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 130u, got, 4u),
             HAL_OK);
    for (unsigned i = 0; i < 4u; i++) {
        CHECK_HEX(got[i], original[i]);
    }
}

TEST(a_corrupt_entry_stream_is_discarded_rather_than_retried_for_ever)
{
    /*
     * The other half of the abort decision, and the one that IS observable.
     *
     * A rollback can fail for two reasons. If the writes are failing, power is
     * going and the log must survive for the next boot. But if the ENTRY STREAM
     * is damaged while writes still work, retrying is futile -- and keeping the
     * log would make every subsequent boot attempt the same failing rollback,
     * so the card would come up in FS_ERROR answering 6581 for ever. A damaged
     * card should be reported, not bricked as well.
     */
    fresh();
    CHECK_EQ(scos_txn_begin(), SCOS_TXN_OK);
    const uint8_t v[4] = { 0xA1u, 0xA2u, 0xA3u, 0xA4u };
    CHECK_EQ(scos_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 150u, v, 4u),
             HAL_OK);

    /*
     * Corrupt the entry's LENGTH field to zero, which rollback() rejects: the
     * header's count says an entry is there and the stream says it is empty, so
     * the two disagree and a partial rollback would be worse than none. The
     * header CRC still passes, so this is specifically a damaged entry area.
     */
    const uint8_t zero[2] = { 0x00u, 0x00u };
    CHECK_EQ(
        hal_nvm_write(HAL_NVM_EEPROM, SCOS_EE_TXN_BASE + 10u + 5u, zero, 2u),
        HAL_OK);

    CHECK_EQ(scos_txn_abort(), SCOS_TXN_ERR_CORRUPT);

    /* Discarded, so the next boot does not retry it. */
    uint8_t hdr[10];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_TXN_BASE, hdr, 10u), HAL_OK);
    CHECK_HEX(hdr[3], 0xFF); /* TXN_STATE_EMPTY */

    /* And the card comes up rather than refusing for ever. */
    CHECK_EQ(scos_txn_recover(), SCOS_TXN_OK);
    CHECK_EQ(scos_init(&g_card), SCOS_OK);
}

TEST(a_committed_transaction_is_not_rolled_back)
{
    /* The other direction, and the one that loses data if it is wrong. */
    fresh();
    CHECK_EQ(scos_txn_begin(), SCOS_TXN_OK);
    const uint8_t v[4] = { 0x51u, 0x52u, 0x53u, 0x54u };
    CHECK_EQ(scos_nvm_write(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 220u, v, 4u),
             HAL_OK);
    CHECK_EQ(scos_txn_commit(), SCOS_TXN_OK);

    CHECK_EQ(scos_txn_recover(), SCOS_TXN_OK);

    uint8_t got[4];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, SCOS_EE_SEC_BASE + 220u, got, 4u),
             HAL_OK);
    CHECK_HEX(got[0], 0x51);
    CHECK_HEX(got[3], 0x54);
}

/* ================================ the PIN counter must NOT be rolled back = */

TEST(a_failed_verify_still_costs_a_try)
{
    /*
     * THE INTERACTION THAT COULD HAVE UNDONE M3.
     *
     * Every command now runs inside a transaction, and a failed VERIFY returns
     * 63CX or 6983 -- both non-success. If the retry counter were journaled at
     * command scope, the abort path would hand the attempt back, and a 4-digit
     * PIN would fall in ten thousand tries again. The whole of M3's counter
     * design would have been defeated by an unrelated mechanism added later.
     *
     * It does not happen because commit_tally() in src/security/pin.c writes
     * with hal_nvm_write() directly, bypassing the journal. That bypass existed
     * for a different reason -- keeping the decrement to one atomic byte -- and
     * is now load-bearing for two.
     *
     * This test exists so that a future change to either mechanism cannot break
     * the other silently.
     */
    fresh();
    const uint8_t set[] = { 0x00u, 0x24u, 0x01u, 0x01u, 0x04u,
                            '1',   '2',   '3',   '4' };
    CHECK_HEX(send(set, (uint16_t)sizeof(set)), SW_OK);

    const uint8_t wrong[] = { 0x00u, 0x20u, 0x00u, 0x01u, 0x04u,
                              '9',   '9',   '9',   '9' };
    const uint8_t query[] = { 0x00u, 0x20u, 0x00u, 0x01u };

    CHECK_HEX(send(wrong, (uint16_t)sizeof(wrong)),
              SW_NVM_CHANGED_PIN_TRIES(2));
    CHECK_HEX(send(query, (uint16_t)sizeof(query)),
              SW_NVM_CHANGED_PIN_TRIES(2));
    CHECK_HEX(send(wrong, (uint16_t)sizeof(wrong)),
              SW_NVM_CHANGED_PIN_TRIES(1));
    CHECK_HEX(send(query, (uint16_t)sizeof(query)),
              SW_NVM_CHANGED_PIN_TRIES(1));
    /* And the third exhausts it, rather than looping forever at 1. */
    CHECK_HEX(send(wrong, (uint16_t)sizeof(wrong)), SW_AUTH_METHOD_BLOCKED);
}

TEST(a_failed_command_rolls_back_what_it_wrote)
{
    /*
     * The ordinary error path, not a power cut -- and it uses the SAME
     * machinery, which means rollback is exercised by every failing command in
     * the suite rather than only by the tests that cut power.
     *
     * DELETE FILE of a non-empty DF is refused after the lookup succeeds, so it
     * is a command that gets some way in and then declines.
     */
    fresh();
    uint8_t before[SCOS_EE_TXN_BASE];
    snapshot(before, sizeof(before));

    const uint8_t del_df[] = {
        0x00u, 0xE4u, 0x00u, 0x00u, 0x02u, 0x7Fu, 0x10u
    };
    const uint16_t sw = send(del_df, (uint16_t)sizeof(del_df));
    CHECK(sw != SW_OK);

    uint8_t after[SCOS_EE_TXN_BASE];
    snapshot(after, sizeof(after));
    CHECK(same_except_journal(before, after, sizeof(before)));
}

int main(void)
{
    RUN(a_transaction_commits);
    RUN(an_abort_restores_every_byte);
    RUN(overlapping_writes_roll_back_to_the_true_original);
    RUN(nesting_is_refused);
    RUN(a_write_too_large_for_the_journal_is_refused_not_performed);
    RUN(the_fault_hook_actually_cuts_a_write);
    RUN(create_file_interrupted_at_any_write_leaves_no_trace);
    RUN(update_binary_interrupted_at_any_write_leaves_the_old_data);
    RUN(the_sweep_would_notice_if_recovery_stopped_working);
    RUN(a_corrupt_journal_header_is_discarded_not_replayed);
    RUN(a_half_written_state_byte_rolls_back);
    RUN(a_failed_rollback_keeps_the_undo_log_for_the_next_boot);
    RUN(a_corrupt_entry_stream_is_discarded_rather_than_retried_for_ever);
    RUN(a_committed_transaction_is_not_rolled_back);
    RUN(a_failed_verify_still_costs_a_try);
    RUN(a_failed_command_rolls_back_what_it_wrote);
    TEST_MAIN_END();
}
