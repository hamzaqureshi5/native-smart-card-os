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

TEST(create_file_interrupted_at_every_byte_leaves_no_trace)
{
    /*
     * THE M4 TEST.
     *
     * CREATE FILE writes a descriptor and updates the superblock's allocation
     * pointer. For every byte offset at which the write can be cut, the card
     * must come back with the file absent and the allocator unchanged -- never
     * with a descriptor pointing at data space nobody owns, and never with the
     * allocator advanced past bytes no file claims.
     *
     * The loop re-personalises a card per offset, cuts the write there, then
     * runs recovery exactly as a boot would, and compares the whole EEPROM
     * against the snapshot taken before the command. Comparing the whole region
     * rather than the fields the test author thought of is the point: a
     * consistency bug in a field nobody remembered is precisely the bug that
     * survives review.
     */
    static uint8_t before[SCOS_EE_TXN_BASE];
    static uint8_t after[SCOS_EE_TXN_BASE];

    /*
     * CREATE FILE for a 16-byte EF 2B01, with every length DERIVED.
     *
     * The first version of this had the Lc typed by hand and it was wrong --
     * for the eighth time in this project's history, which is why
     * tests/unit/test_create.c and tools/card both grew length-deriving
     * helpers. Doing it by hand once more produced 41 failures that had
     * nothing to do with transactions.
     */
    uint8_t  create[32];
    uint16_t cn = 0u;
    {
        uint8_t  inner[24];
        uint16_t in = 0u;
        /* 82: file descriptor byte, transparent EF */
        inner[in++] = 0x82u;
        inner[in++] = 0x01u;
        inner[in++] = 0x01u;
        /* 83: file identifier */
        inner[in++] = 0x83u;
        inner[in++] = 0x02u;
        inner[in++] = 0x2Bu;
        inner[in++] = 0x01u;
        /* 80: data bytes */
        inner[in++] = 0x80u;
        inner[in++] = 0x02u;
        inner[in++] = 0x00u;
        inner[in++] = 0x10u;

        create[cn++] = 0x00u;
        create[cn++] = 0xE0u;
        create[cn++] = 0x00u;
        create[cn++] = 0x00u;
        create[cn++] = (uint8_t)(in + 2u); /* Lc: template tag + length */
        create[cn++] = 0x62u;
        create[cn++] = (uint8_t)in;
        for (uint16_t i = 0; i < in; i++) {
            create[cn++] = inner[i];
        }
    }

    unsigned interrupted = 0u;
    for (uint32_t cut = 0u; cut < 40u; cut++) {
        fresh();
        snapshot(before, sizeof(before));

        vcard_fault_after_bytes(cut);
        const uint16_t sw = send(create, cn);

        if (!vcard_fault_fired()) {
            /* The cut was beyond every write this command made, so it
             * completed. Nothing to recover; skip rather than pretend. */
            CHECK_HEX(sw, SW_OK);
            continue;
        }
        interrupted++;

        /* The command must NOT have reported success after losing power. */
        CHECK(sw != SW_OK);

        /* Boot the card again: recovery runs inside scos_init(). */
        vcard_fault_clear();
        CHECK_EQ(scos_init(&g_card), SCOS_OK);

        snapshot(after, sizeof(after));
        CHECK(same_except_journal(before, after, sizeof(before)));

        /* And the file is genuinely absent -- not merely byte-identical by
         * luck. A SELECT of it must fail. */
        const uint8_t sel[] = {
            0x00u, 0xA4u, 0x02u, 0x0Cu, 0x02u, 0x2Bu, 0x01u
        };
        CHECK_HEX(send(sel, (uint16_t)sizeof(sel)), SW_FILE_NOT_FOUND);
    }

    /* The loop is worthless if no cut ever landed. */
    CHECK(interrupted > 0u);
}

TEST(update_binary_interrupted_at_every_byte_leaves_the_old_data)
{
    /*
     * The same property for a DATA write rather than a metadata one. A partial
     * UPDATE BINARY is the case a user notices: half a record written is not a
     * record, and a card that returns an error while leaving the file half
     * modified has lost the caller's data without saying so.
     */
    static uint8_t original[8];

    unsigned interrupted = 0u;
    for (uint32_t cut = 0u; cut < 24u; cut++) {
        fresh();

        /* Put a known value in 2F00 and make it durable outside any
         * transaction, so it is the state the rollback must return to. */
        const uint8_t sel[] = {
            0x00u, 0xA4u, 0x02u, 0x0Cu, 0x02u, 0x2Fu, 0x00u
        };
        CHECK_HEX(send(sel, (uint16_t)sizeof(sel)), SW_OK);
        const uint8_t seed[] = { 0x00u, 0xD6u, 0x00u, 0x00u, 0x08u,
                                 0x11u, 0x22u, 0x33u, 0x44u, 0x55u,
                                 0x66u, 0x77u, 0x88u };
        CHECK_HEX(send(seed, (uint16_t)sizeof(seed)), SW_OK);
        CHECK_EQ(hal_nvm_read(HAL_NVM_FLASH, 0u, original, 8u), HAL_OK);

        const uint8_t over[] = { 0x00u, 0xD6u, 0x00u, 0x00u, 0x08u,
                                 0xFFu, 0xFEu, 0xFDu, 0xFCu, 0xFBu,
                                 0xFAu, 0xF9u, 0xF8u };
        vcard_fault_after_bytes(cut);
        const uint16_t sw = send(over, (uint16_t)sizeof(over));

        if (!vcard_fault_fired()) {
            continue;
        }
        interrupted++;
        CHECK(sw != SW_OK);

        vcard_fault_clear();
        CHECK_EQ(scos_init(&g_card), SCOS_OK);

        uint8_t got[8];
        CHECK_EQ(hal_nvm_read(HAL_NVM_FLASH, 0u, got, 8u), HAL_OK);
        for (unsigned i = 0; i < 8u; i++) {
            CHECK_HEX(got[i], original[i]);
        }
    }
    CHECK(interrupted > 0u);
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
    RUN(create_file_interrupted_at_every_byte_leaves_no_trace);
    RUN(update_binary_interrupted_at_every_byte_leaves_the_old_data);
    RUN(a_corrupt_journal_header_is_discarded_not_replayed);
    RUN(a_half_written_state_byte_rolls_back);
    RUN(a_committed_transaction_is_not_rolled_back);
    RUN(a_failed_verify_still_costs_a_try);
    RUN(a_failed_command_rolls_back_what_it_wrote);
    TEST_MAIN_END();
}
