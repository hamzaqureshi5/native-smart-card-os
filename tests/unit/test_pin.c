/* SPDX-License-Identifier: MIT
 *
 * test_pin.c -- VERIFY, CHANGE REFERENCE DATA, and the retry counter.
 *
 * The property most of this file exists to pin down: a failed attempt costs a
 * try, and nothing gives it back. Everything else here is in service of that,
 * or is a status word that must stay distinguishable from another status word.
 *
 * WHAT THESE TESTS CANNOT SHOW, stated so the suite is not read as more than
 * it is: they cannot cut power in the middle of pin_verify(), between the
 * counter being committed and the value being compared. That is the exact
 * instant the design is built around, and reaching it needs the
 * fault-injection hook in hal_nvm_write() that M4 adds. What is verified here
 * is that the counter is durable after the call and across a power cycle
 * (tests/python/test_pin.py), and that the ordering in the source is what it
 * claims. The interrupted-write case is M4's to prove.
 */
#include "apdu/apdu.h"
#include "apdu/dispatch.h"
#include "apdu/sw.h"
#include "crypto/crypto.h"
#include "hal/hal.h"
#include "hal/sim/vcard.h"
#include "os/kernel.h"
#include "os/os_mem.h"
#include "security/pin.h"

#include "scos_test.h"

static scos_kernel g_card;

static void fresh(void)
{
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(scos_init(&g_card), SCOS_OK);
}

static uint16_t send(const uint8_t *cmd, uint16_t len)
{
    uint8_t  rsp[SCOS_APDU_RSP_MAX];
    uint16_t rsp_len = 0u;
    CHECK_EQ(
        scos_process(&g_card, cmd, len, rsp, (uint16_t)sizeof(rsp), &rsp_len),
        SCOS_OK);
    CHECK(rsp_len >= 2u);
    if (rsp_len < 2u) {
        return 0u;
    }
    return (uint16_t)(((uint16_t)rsp[rsp_len - 2u] << 8) | rsp[rsp_len - 1u]);
}

/* VERIFY, status-query form: header only. */
static uint16_t query(uint8_t ref)
{
    const uint8_t c[] = { 0x00u, 0x20u, 0x00u, ref };
    return send(c, (uint16_t)sizeof(c));
}

/* VERIFY, attempt form. Lc derived, never typed. */
static uint16_t verify(uint8_t ref, const char *value)
{
    uint8_t  c[5u + PIN_MAX_LEN];
    uint16_t n  = 0u;
    c[n++]      = 0x00u;
    c[n++]      = 0x20u;
    c[n++]      = 0x00u;
    c[n++]      = ref;
    uint8_t len = 0u;
    while (value[len] != '\0') {
        len++;
    }
    c[n++] = len;
    for (uint8_t i = 0; i < len; i++) {
        c[n++] = (uint8_t)value[i];
    }
    return send(c, n);
}

/* CHANGE REFERENCE DATA, P1=01 (new value only). */
static uint16_t set_pin(uint8_t ref, const char *value)
{
    uint8_t  c[5u + PIN_MAX_LEN];
    uint16_t n  = 0u;
    c[n++]      = 0x00u;
    c[n++]      = 0x24u;
    c[n++]      = 0x01u;
    c[n++]      = ref;
    uint8_t len = 0u;
    while (value[len] != '\0') {
        len++;
    }
    c[n++] = len;
    for (uint8_t i = 0; i < len; i++) {
        c[n++] = (uint8_t)value[i];
    }
    return send(c, n);
}

/* ============================================================== the shape = */

TEST(a_card_with_no_pin_says_so)
{
    /*
     * 6A88, not 9000 and not 6983.
     *
     * pin_personalise() ships NO default PIN, deliberately: a fixed factory
     * PIN in source would be a published credential, identical on every card
     * built from this tree and preserved in the git history.
     *
     * The two wrong answers are wrong in opposite directions. 9000 would be a
     * card with no PIN that accepts every PIN. 6983 would claim it is blocked
     * and send an administrator hunting for a PUK that cannot help.
     */
    fresh();
    CHECK_HEX(query(PIN_REF_USER), SW_REFERENCE_DATA_NOT_FOUND);
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_REFERENCE_DATA_NOT_FOUND);
}

TEST(set_then_verify)
{
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);

    /* Query before verifying: three attempts, and NOT authenticated. */
    CHECK_HEX(query(PIN_REF_USER), SW_NVM_CHANGED_PIN_TRIES(3));
    CHECK(!scos_is_authenticated(&g_card, PIN_REF_USER));

    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_OK);
    CHECK(scos_is_authenticated(&g_card, PIN_REF_USER));

    /* Query after: 9000 means "you need do nothing". */
    CHECK_HEX(query(PIN_REF_USER), SW_OK);
}

TEST(the_verifier_is_not_the_pin)
{
    /*
     * The whole EEPROM is scanned for the PIN's own bytes. Finding them would
     * mean the card stores the credential rather than a verifier -- the single
     * rule in this area that is not a trade-off.
     *
     * This is a weaker statement than "the PIN cannot be recovered", and
     * deliberately so: a 4-digit PIN behind a salted SHA-256 is ten thousand
     * hashes to an attacker who can read NVM and compute, which is instant.
     * See pin.h. What this test shows is that a single read does not hand the
     * PIN over, which is a real if modest property.
     */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "13571357"), SW_OK);

    const uint8_t  needle[] = { '1', '3', '5', '7', '1', '3', '5', '7' };
    const uint32_t size     = hal_nvm_size(HAL_NVM_EEPROM);
    CHECK(size > 0u);

    bool found = false;
    for (uint32_t off = 0; off + sizeof(needle) <= size; off++) {
        uint8_t win[sizeof(needle)];
        if (hal_nvm_read(HAL_NVM_EEPROM, off, win, sizeof(win)) != HAL_OK) {
            continue;
        }
        bool same = true;
        for (unsigned i = 0; i < sizeof(needle); i++) {
            if (win[i] != needle[i]) {
                same = false;
                break;
            }
        }
        if (same) {
            found = true;
            break;
        }
    }
    CHECK(!found); /* the plaintext PIN must not be anywhere in NVM */
}

TEST(the_salt_participates_and_is_drawn_fresh)
{
    /*
     * What the salt is FOR: without it, identical PINs produce identical
     * verifiers, so one precomputed table breaks every card at once and a
     * verifier read from one card gives you the PIN of another.
     *
     * WHAT THIS TEST DELIBERATELY DOES NOT ASSERT, because this HAL cannot
     * provide it: that two CARDS with the same PIN get different verifiers.
     * The simulator's hal_random_bytes() is a seeded xorshift PRNG,
     * reproducible on purpose so that tests are deterministic -- and that same
     * property means two simulated cards draw the identical salt. The first
     * version of this test asserted cross-card uniqueness and failed, which
     * was the test being wrong rather than the OS.
     *
     * The real property therefore depends on a real TRNG and is a HARDWARE
     * requirement, recorded in docs/hardware-port.md: a card whose TRNG is
     * predictable has, in effect, no salt. What IS checkable here is that the
     * salt participates at all, and that a fresh one is drawn per pin_set --
     * which catches a hardcoded, zero, or reused salt.
     */
    fresh();

    /* 1. The verifier is not the UNSALTED hash of the PIN. */
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    uint8_t stored[32];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0x0400u + 24u, stored, 32u), HAL_OK);

    uint8_t unsalted[32];
    CHECK_EQ(crypto_sha256("1234", 4u, unsalted), CRYPTO_OK);
    CHECK(!crypto_equal_ct(stored, unsalted, 32u));

    /* 2. A fresh salt per set: two references, same PIN, different verifiers.
     *    Equal verifiers here would mean the salt is fixed rather than drawn. */
    CHECK_HEX(set_pin(PIN_REF_UNBLOCK, "1234"), SW_OK);
    uint8_t other[32];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0x0400u + 58u + 24u, other, 32u),
             HAL_OK);
    CHECK(!crypto_equal_ct(stored, other, 32u));

    /* 3. And the salt is not all zeroes, which is the failure a "fresh salt"
     *    check misses when entropy silently returns nothing. */
    uint8_t salt[16];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0x0400u + 8u, salt, 16u), HAL_OK);
    uint8_t zeroes[16];
    os_memset(zeroes, 0, sizeof(zeroes));
    CHECK(!crypto_equal_ct(salt, zeroes, 16u));
}

/* ================================================== the retry counter ==== */

TEST(a_wrong_pin_costs_exactly_one_try)
{
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);

    CHECK_HEX(verify(PIN_REF_USER, "9999"), SW_NVM_CHANGED_PIN_TRIES(2));
    CHECK_HEX(query(PIN_REF_USER), SW_NVM_CHANGED_PIN_TRIES(2));

    CHECK_HEX(verify(PIN_REF_USER, "9999"), SW_NVM_CHANGED_PIN_TRIES(1));
    CHECK_HEX(query(PIN_REF_USER), SW_NVM_CHANGED_PIN_TRIES(1));
}

TEST(a_correct_pin_restores_the_counter)
{
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    CHECK_HEX(verify(PIN_REF_USER, "9999"), SW_NVM_CHANGED_PIN_TRIES(2));
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_OK);
    CHECK_HEX(query(PIN_REF_USER), SW_OK); /* authenticated */

    /* And the counter really is back to full, not merely reported as such:
     * two more wrong attempts must not block the card. */
    CHECK_HEX(verify(PIN_REF_USER, "9999"), SW_NVM_CHANGED_PIN_TRIES(2));
    CHECK_HEX(verify(PIN_REF_USER, "9999"), SW_NVM_CHANGED_PIN_TRIES(1));
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_OK);
}

TEST(exhausting_the_counter_blocks_the_pin)
{
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    CHECK_HEX(verify(PIN_REF_USER, "9999"), SW_NVM_CHANGED_PIN_TRIES(2));
    CHECK_HEX(verify(PIN_REF_USER, "9999"), SW_NVM_CHANGED_PIN_TRIES(1));

    /* The third failure blocks, and says 6983 rather than 63C0. A reader that
     * gets 63C0 may reasonably retry; 6983 says retrying is pointless. */
    CHECK_HEX(verify(PIN_REF_USER, "9999"), SW_AUTH_METHOD_BLOCKED);
    CHECK_HEX(query(PIN_REF_USER), SW_AUTH_METHOD_BLOCKED);
}

TEST(the_correct_pin_does_not_unblock_a_blocked_pin)
{
    /*
     * THE test for whether blocking means anything.
     *
     * If presenting the right value after exhaustion worked, the counter would
     * be a speed bump rather than a limit: an attacker would guess until
     * blocked, then guess again. Blocked is a state, not a mood.
     */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    for (int i = 0; i < 3; i++) {
        (void)verify(PIN_REF_USER, "9999");
    }
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_AUTH_METHOD_BLOCKED);
    CHECK(!scos_is_authenticated(&g_card, PIN_REF_USER));

    /* And it survives a reset -- the state is in NVM, not in the session. */
    scos_reset(&g_card);
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_AUTH_METHOD_BLOCKED);
}

TEST(a_malformed_attempt_does_not_cost_a_try)
{
    /*
     * pin_verify() spends the try BEFORE it looks at the value, which is the
     * point of the design -- so a length check that happened inside it would
     * let a reader burn the cardholder's attempts with junk that was never
     * compared against anything. The check therefore lives in the command
     * handler, ahead of the call.
     */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);

    CHECK_HEX(verify(PIN_REF_USER, "1"), SW_WRONG_LENGTH);   /* too short */
    CHECK_HEX(verify(PIN_REF_USER, "123"), SW_WRONG_LENGTH); /* still short */
    const uint8_t too_long[] = {
        0x00u, 0x20u, 0x00u, PIN_REF_USER, 0x11u, 1,  2,  3,  4,  5,  6,
        7,     8,     9,     10,           11,    12, 13, 14, 15, 16, 17
    };
    CHECK_HEX(send(too_long, (uint16_t)sizeof(too_long)), SW_WRONG_LENGTH);

    /* Nothing was spent. */
    CHECK_HEX(query(PIN_REF_USER), SW_NVM_CHANGED_PIN_TRIES(3));
}

TEST(brute_force_stops_at_the_limit)
{
    /*
     * Ten thousand attempts on a 4-digit PIN is the attack the counter exists
     * for. Here it dies after three, and the loop asserts the card never once
     * answers 9000 to a wrong value.
     */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "4271"), SW_OK);

    unsigned refused = 0u;
    for (unsigned n = 0; n < 200u; n++) {
        char guess[5];
        guess[0] = (char)('0' + ((n / 1000u) % 10u));
        guess[1] = (char)('0' + ((n / 100u) % 10u));
        guess[2] = (char)('0' + ((n / 10u) % 10u));
        guess[3] = (char)('0' + (n % 10u));
        guess[4] = '\0';
        if (guess[0] == '4' && guess[1] == '2' && guess[2] == '7' &&
            guess[3] == '1') {
            continue; /* do not accidentally guess right */
        }
        const uint16_t sw = verify(PIN_REF_USER, guess);
        CHECK(sw != SW_OK); /* a wrong PIN must never be accepted */
        if (sw == SW_AUTH_METHOD_BLOCKED) {
            refused++;
        }
    }
    /* Blocked long before the search space is exhausted. */
    CHECK(refused > 190u);
}

/* ============================================ authentication lifetime ==== */

TEST(authentication_does_not_survive_a_reset)
{
    /*
     * A card must forget that a PIN was presented when the session ends.
     * Otherwise pulling the card out and putting it back leaves it
     * authenticated -- and a stolen card needs no PIN at all.
     */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_OK);
    CHECK(scos_is_authenticated(&g_card, PIN_REF_USER));

    scos_reset(&g_card);
    CHECK(!scos_is_authenticated(&g_card, PIN_REF_USER));
    /* The PIN itself is untouched: three attempts, and it still works. */
    CHECK_HEX(query(PIN_REF_USER), SW_NVM_CHANGED_PIN_TRIES(3));
}

TEST(a_failed_attempt_drops_an_existing_authentication)
{
    /*
     * Without this, one success followed by wrong guesses would leave the
     * session authenticated while the counter ran down -- so somebody who
     * learned the PIN once would keep access even after it changed. Failure
     * means not authenticated, with no exceptions.
     */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_OK);
    CHECK(scos_is_authenticated(&g_card, PIN_REF_USER));

    CHECK_HEX(verify(PIN_REF_USER, "9999"), SW_NVM_CHANGED_PIN_TRIES(2));
    CHECK(!scos_is_authenticated(&g_card, PIN_REF_USER));
}

TEST(re_verifying_is_not_a_free_oracle)
{
    /*
     * It is tempting to short-circuit VERIFY when the reference is already
     * authenticated. That would let an attacker holding an authenticated
     * session test candidate PINs at no cost -- and a WRONG one would answer
     * 9000, which is worse than free.
     */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_OK);

    /* Authenticated, and a wrong value still costs a try and still fails. */
    CHECK_HEX(verify(PIN_REF_USER, "0000"), SW_NVM_CHANGED_PIN_TRIES(2));
}

/* ============================================== CHANGE REFERENCE DATA ==== */

TEST(changing_an_active_pin_requires_authentication)
{
    /*
     * The rule that makes the PIN mean anything before per-file access
     * conditions exist. Without it, CHANGE REFERENCE DATA is an
     * unauthenticated overwrite: anyone with the reader replaces the PIN with
     * one they know, and every counter and constant-time comparison in
     * pin.c becomes decoration.
     */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK); /* UNSET -> allowed */

    /* Now ACTIVE and not authenticated: refused with 6982, and 6982 rather
     * than 6983 because the command is available to someone -- just not to
     * this caller. */
    CHECK_HEX(set_pin(PIN_REF_USER, "5678"), SW_SECURITY_NOT_SATISFIED);
    /* The old PIN still works, so nothing was changed. */
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_OK);

    /* Authenticated: allowed. */
    CHECK_HEX(set_pin(PIN_REF_USER, "5678"), SW_OK);
    /* And the change took effect in both directions. */
    CHECK_HEX(verify(PIN_REF_USER, "5678"), SW_OK);
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_NVM_CHANGED_PIN_TRIES(2));
}

TEST(a_new_pin_voids_the_old_authentication)
{
    /* Whoever was authenticated was authenticated against a value that no
     * longer exists. Keeping the bit set would continue a session on a
     * credential the card has forgotten. */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_OK);
    CHECK(scos_is_authenticated(&g_card, PIN_REF_USER));

    CHECK_HEX(set_pin(PIN_REF_USER, "5678"), SW_OK);
    CHECK(!scos_is_authenticated(&g_card, PIN_REF_USER));
    CHECK_HEX(query(PIN_REF_USER), SW_NVM_CHANGED_PIN_TRIES(3));
}

TEST(a_blocked_pin_cannot_be_changed)
{
    /*
     * Allowing this would make blocking pointless: exhaust the counter, set a
     * new PIN, carry on. Recovery is the PUK's job and RESET RETRY COUNTER
     * does not exist yet, so on this card a blocked PIN is TERMINAL -- a
     * deliberate, documented state.
     */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_OK); /* authenticate first */
    for (int i = 0; i < 3; i++) {
        (void)verify(PIN_REF_USER, "9999");
    }
    CHECK_HEX(query(PIN_REF_USER), SW_AUTH_METHOD_BLOCKED);
    CHECK_HEX(set_pin(PIN_REF_USER, "5678"), SW_AUTH_METHOD_BLOCKED);
}

/* ================================================== the command surface == */

TEST(malformed_verify_is_refused_precisely)
{
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);

    /* P1 must be 00. ISO assigns other values -- FF RESETS the security
     * status -- and implementing that by accident would be a security bug in
     * the quietest possible form. */
    const uint8_t p1_ff[] = { 0x00u, 0x20u, 0xFFu, PIN_REF_USER };
    CHECK_HEX(send(p1_ff, (uint16_t)sizeof(p1_ff)), SW_INCORRECT_P1P2);

    /* An unknown reference names something this card does not have. */
    const uint8_t bad_ref[] = { 0x00u, 0x20u, 0x00u, 0x7Fu };
    CHECK_HEX(send(bad_ref, (uint16_t)sizeof(bad_ref)),
              SW_REFERENCE_DATA_NOT_FOUND);

    /* Neither form returns data, so an Le is a caller error. */
    const uint8_t with_le[] = { 0x00u, 0x20u, 0x00u, PIN_REF_USER, 0x00u };
    CHECK_HEX(send(with_le, (uint16_t)sizeof(with_le)), SW_WRONG_LENGTH);

    /* None of that spent a try or authenticated anything. */
    CHECK_HEX(query(PIN_REF_USER), SW_NVM_CHANGED_PIN_TRIES(3));
}

TEST(malformed_change_is_refused_precisely)
{
    fresh();
    /* P1=00 (old||new) needs a fixed PIN format this project does not impose,
     * so it is refused rather than guessed at. */
    const uint8_t p1_00[] = { 0x00u, 0x24u, 0x00u, PIN_REF_USER, 0x04u,
                              '1',   '2',   '3',   '4' };
    CHECK_HEX(send(p1_00, (uint16_t)sizeof(p1_00)), SW_INCORRECT_P1P2);

    CHECK_HEX(set_pin(PIN_REF_USER, "12"), SW_WRONG_LENGTH);     /* too short */
    CHECK_HEX(query(PIN_REF_USER), SW_REFERENCE_DATA_NOT_FOUND); /* unchanged */
}

/* ============================================ RESET RETRY COUNTER ======== */

/* RESET RETRY COUNTER, P1=02 (PUK alone). Lc derived. */
static uint16_t unblock(const char *puk)
{
    uint8_t  c[5u + PIN_MAX_LEN];
    uint16_t n  = 0u;
    c[n++]      = 0x00u;
    c[n++]      = 0x2Cu;
    c[n++]      = 0x02u;
    c[n++]      = PIN_REF_USER;
    uint8_t len = 0u;
    while (puk[len] != '\0') {
        len++;
    }
    c[n++] = len;
    for (uint8_t i = 0; i < len; i++) {
        c[n++] = (uint8_t)puk[i];
    }
    return send(c, n);
}

/* Set up a card with a PUK and a PIN, then block the PIN. */
static void block_the_pin(void)
{
    fresh();
    CHECK_HEX(set_pin(PIN_REF_UNBLOCK, "87654321"), SW_OK);
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    for (int i = 0; i < 3; i++) {
        (void)verify(PIN_REF_USER, "9999");
    }
    CHECK_HEX(query(PIN_REF_USER), SW_AUTH_METHOD_BLOCKED);
}

TEST(the_puk_unblocks_and_leaves_the_pin_value_alone)
{
    /*
     * The whole point of the PUK-only form. The cardholder who mistyped their
     * own PIN three times knows it perfectly well, so recovery must not force
     * them to choose a new one -- and the card CANNOT recover the old value
     * anyway, only its verifier is stored, which is why pin_unblock() exists
     * as a primitive separate from pin_set().
     */
    block_the_pin();

    CHECK_HEX(unblock("87654321"), SW_OK);

    /* Counter restored, and NOT authenticated: presenting the PUK proves
     * entitlement to reset the PIN, not knowledge of it. */
    CHECK_HEX(query(PIN_REF_USER), SW_NVM_CHANGED_PIN_TRIES(3));
    CHECK(!scos_is_authenticated(&g_card, PIN_REF_USER));

    /* And the ORIGINAL PIN still works -- the value was untouched. */
    CHECK_HEX(verify(PIN_REF_USER, "1234"), SW_OK);
}

TEST(the_puk_is_not_a_master_key)
{
    /*
     * Presenting the PUK must not grant PIN authentication. If it did, the PUK
     * would open every PIN-protected file -- a far larger privilege than the
     * one a cardholder is given it for, and one an attacker who obtained the
     * PUK from a letter would inherit.
     */
    block_the_pin();
    CHECK_HEX(unblock("87654321"), SW_OK);
    CHECK(!scos_is_authenticated(&g_card, PIN_REF_USER));
    CHECK(!scos_is_authenticated(&g_card, PIN_REF_UNBLOCK));
}

TEST(a_wrong_puk_costs_a_puk_try)
{
    /*
     * The recovery path is itself limited, or it is just a second PIN with more
     * attempts. pin_verify() spends the try before comparing, so this command
     * is no more of a free oracle against the PUK than VERIFY is against the
     * PIN.
     */
    block_the_pin();

    CHECK_HEX(unblock("00000000"), SW_NVM_CHANGED_PIN_TRIES(2));
    CHECK_HEX(unblock("00000000"), SW_NVM_CHANGED_PIN_TRIES(1));
    /* The PIN is still blocked throughout: a failed unblock changes nothing. */
    CHECK_HEX(query(PIN_REF_USER), SW_AUTH_METHOD_BLOCKED);

    /* The third failure blocks the PUK, and now the card really is terminal
     * for this reference -- the intended end of a limited recovery path. */
    CHECK_HEX(unblock("00000000"), SW_AUTH_METHOD_BLOCKED);
    CHECK_HEX(query(PIN_REF_UNBLOCK), SW_AUTH_METHOD_BLOCKED);
    CHECK_HEX(unblock("87654321"), SW_AUTH_METHOD_BLOCKED); /* even correct */
    CHECK_HEX(query(PIN_REF_USER), SW_AUTH_METHOD_BLOCKED);
}

TEST(unblocking_works_on_a_pin_that_is_not_blocked)
{
    /* Idempotent, for the same reason every other command here is: a reader
     * whose response was lost must be able to send it again. Restoring a full
     * counter is a harmless no-op. */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_UNBLOCK, "87654321"), SW_OK);
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    CHECK_HEX(verify(PIN_REF_USER, "9999"), SW_NVM_CHANGED_PIN_TRIES(2));

    CHECK_HEX(unblock("87654321"), SW_OK);
    CHECK_HEX(query(PIN_REF_USER), SW_NVM_CHANGED_PIN_TRIES(3));
    CHECK_HEX(unblock("87654321"), SW_OK); /* again */
    CHECK_HEX(query(PIN_REF_USER), SW_NVM_CHANGED_PIN_TRIES(3));
}

TEST(without_a_puk_a_blocked_pin_is_terminal)
{
    /*
     * A card issued with no PUK has a terminal PIN. That is a personalisation
     * choice rather than a bug, and 6A88 makes it diagnosable: the reference
     * data this command needs is not there. NOT 6983, which would describe the
     * PIN's state rather than the reason recovery is impossible.
     */
    fresh();
    CHECK_HEX(set_pin(PIN_REF_USER, "1234"), SW_OK);
    for (int i = 0; i < 3; i++) {
        (void)verify(PIN_REF_USER, "9999");
    }
    CHECK_HEX(query(PIN_REF_USER), SW_AUTH_METHOD_BLOCKED);
    CHECK_HEX(unblock("87654321"), SW_REFERENCE_DATA_NOT_FOUND);
    CHECK_HEX(query(PIN_REF_USER), SW_AUTH_METHOD_BLOCKED);
}

TEST(reset_retry_is_refused_precisely)
{
    block_the_pin();

    /* P1=00 is a real ISO form -- PUK followed by a new PIN -- that this card
     * does not implement, because splitting two values in one field needs a
     * length and storing the PUK's length would leak it. 6A86. */
    const uint8_t p1_00[] = { 0x00u, 0x2Cu, 0x00u, PIN_REF_USER, 0x08u,
                              '8',   '7',   '6',   '5',          '4',
                              '3',   '2',   '1' };
    CHECK_HEX(send(p1_00, (uint16_t)sizeof(p1_00)), SW_INCORRECT_P1P2);

    /* P2 names the reference being UNBLOCKED. Letting a caller nominate the
     * unblocking reference would let a PIN unblock itself. */
    const uint8_t p2_puk[] = { 0x00u, 0x2Cu, 0x02u, PIN_REF_UNBLOCK,
                               0x08u, '8',   '7',   '6',
                               '5',   '4',   '3',   '2',
                               '1' };
    CHECK_HEX(send(p2_puk, (uint16_t)sizeof(p2_puk)),
              SW_REFERENCE_DATA_NOT_FOUND);

    /* A short value is a malformed command, not a failed attempt, so it must
     * not cost a PUK try -- same ordering rule as VERIFY. */
    CHECK_HEX(unblock("12"), SW_WRONG_LENGTH);
    CHECK_HEX(query(PIN_REF_UNBLOCK), SW_NVM_CHANGED_PIN_TRIES(3));

    /* Nothing above unblocked anything. */
    CHECK_HEX(query(PIN_REF_USER), SW_AUTH_METHOD_BLOCKED);
}

TEST(the_puk_reference_exists_but_is_unset)
{
    /* Reserved so the record layout and the EEPROM map do not have to change
     * when RESET RETRY COUNTER lands. It is addressable and honestly empty. */
    fresh();
    CHECK_HEX(query(PIN_REF_UNBLOCK), SW_REFERENCE_DATA_NOT_FOUND);
    CHECK_HEX(set_pin(PIN_REF_UNBLOCK, "87654321"), SW_OK);
    CHECK_HEX(verify(PIN_REF_UNBLOCK, "87654321"), SW_OK);
    /* And it is a SEPARATE credential: authenticating the PUK does not
     * authenticate the PIN. */
    CHECK(scos_is_authenticated(&g_card, PIN_REF_UNBLOCK));
    CHECK(!scos_is_authenticated(&g_card, PIN_REF_USER));
}

int main(void)
{
    RUN(a_card_with_no_pin_says_so);
    RUN(set_then_verify);
    RUN(the_verifier_is_not_the_pin);
    RUN(the_salt_participates_and_is_drawn_fresh);
    RUN(a_wrong_pin_costs_exactly_one_try);
    RUN(a_correct_pin_restores_the_counter);
    RUN(exhausting_the_counter_blocks_the_pin);
    RUN(the_correct_pin_does_not_unblock_a_blocked_pin);
    RUN(a_malformed_attempt_does_not_cost_a_try);
    RUN(brute_force_stops_at_the_limit);
    RUN(authentication_does_not_survive_a_reset);
    RUN(a_failed_attempt_drops_an_existing_authentication);
    RUN(re_verifying_is_not_a_free_oracle);
    RUN(changing_an_active_pin_requires_authentication);
    RUN(a_new_pin_voids_the_old_authentication);
    RUN(a_blocked_pin_cannot_be_changed);
    RUN(malformed_verify_is_refused_precisely);
    RUN(malformed_change_is_refused_precisely);
    RUN(the_puk_unblocks_and_leaves_the_pin_value_alone);
    RUN(the_puk_is_not_a_master_key);
    RUN(a_wrong_puk_costs_a_puk_try);
    RUN(unblocking_works_on_a_pin_that_is_not_blocked);
    RUN(without_a_puk_a_blocked_pin_is_terminal);
    RUN(reset_retry_is_refused_precisely);
    RUN(the_puk_reference_exists_but_is_unset);
    TEST_MAIN_END();
}
