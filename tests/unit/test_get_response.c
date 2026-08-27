/* SPDX-License-Identifier: MIT
 *
 * test_get_response.c -- GET RESPONSE (C0) and the 61XX mechanism.
 *
 * The interesting behaviour here is not "does it return the bytes" -- it is the
 * SEQUENCING. ISO/IEC 7816-4 requires GET RESPONSE to immediately follow the
 * 61XX that announced the data, and the reason is not tidiness: a card that
 * kept pending data around would let a later, unrelated command collect the
 * output of an earlier one. From M3 that could mean collecting data produced
 * while authenticated, after authentication was dropped.
 *
 * So most of this file is about when the data must be GONE.
 */
#include "apdu/sw.h"
#include "filesystem/fs.h"
#include "hal/hal.h"
#include "hal/sim/vcard.h"
#include "os/kernel.h"
#include "os/os_mem.h"

#include "scos_test.h"

static scos_kernel g_card;

static void fresh(void)
{
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(scos_init(&g_card), SCOS_OK);
}

static uint16_t send(const uint8_t *cmd, uint16_t len, uint8_t *out,
                     uint16_t *out_len)
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
    const uint16_t dlen = (uint16_t)(rsp_len - 2u);
    if (out != NULL && dlen > 0u) {
        (void)os_memcpy_checked(out, dlen, rsp, dlen);
    }
    if (out_len != NULL) {
        *out_len = dlen;
    }
    return (uint16_t)(((uint16_t)rsp[rsp_len - 2u] << 8) | rsp[rsp_len - 1u]);
}

/* A Case 3 SELECT of the MF: Lc=2, data=3F00, NO Le. This is the command that
 * cannot return data under T=0 and therefore produces 61XX. */
static uint16_t select_case3(void)
{
    const uint8_t c[] = { 0x00u, 0xA4u, 0x00u, 0x00u, 0x02u, 0x3Fu, 0x00u };
    return send(c, (uint16_t)sizeof(c), NULL, NULL);
}

static uint16_t get_response(uint8_t le, uint8_t *out, uint16_t *out_len)
{
    const uint8_t c[] = { 0x00u, 0xC0u, 0x00u, 0x00u, le };
    return send(c, (uint16_t)sizeof(c), out, out_len);
}

/* ============================================================== the basics = */

TEST(case3_select_announces_its_fci)
{
    /*
     * The bug this whole command exists to fix. Before GET RESPONSE, this
     * answered 9000 with no data -- well-formed and silently useless: a
     * conformant reader got success and no file information, with nothing to
     * indicate the card had more to say.
     */
    fresh();
    CHECK_HEX(select_case3(), SW_MORE_DATA(0x0C));
    CHECK_EQ(scos_pending_remaining(&g_card), 12);
}

TEST(get_response_returns_exactly_what_was_announced)
{
    fresh();
    const uint16_t sw = select_case3();
    CHECK_HEX(sw, SW_MORE_DATA(0x0C));
    const uint8_t announced = (uint8_t)(sw & 0xFFu);

    uint8_t  data[64];
    uint16_t dlen = 0u;
    CHECK_HEX(get_response(announced, data, &dlen), SW_OK);
    CHECK_EQ(dlen, announced);
    CHECK_HEX(data[0], 0x6F); /* FCI template */
    CHECK_EQ(scos_pending_remaining(&g_card), 0);
}

TEST(the_two_step_matches_the_one_step)
{
    /*
     * A Case 4 SELECT returns the template directly. The 61XX path must
     * produce the IDENTICAL bytes -- otherwise the card's answer depends on
     * how the reader asked, which is a conformance bug that would only surface
     * against real reader software.
     */
    fresh();
    uint8_t       direct[64];
    uint16_t      direct_len = 0u;
    const uint8_t c4[] = { 0x00u, 0xA4u, 0x00u, 0x00u,
                           0x02u, 0x3Fu, 0x00u, 0x00u }; /* Le = 0 -> 256 */
    CHECK_HEX(send(c4, (uint16_t)sizeof(c4), direct, &direct_len), SW_OK);
    CHECK(direct_len > 0u);

    fresh();
    uint8_t  staged[64];
    uint16_t staged_len = 0u;
    CHECK_HEX(select_case3(), SW_MORE_DATA(direct_len & 0xFFu));
    CHECK_HEX(get_response((uint8_t)direct_len, staged, &staged_len), SW_OK);

    CHECK_EQ(staged_len, direct_len);
    CHECK(os_memeq_ct(staged, direct, direct_len));
}

TEST(data_can_be_collected_in_several_chunks)
{
    fresh();
    CHECK_HEX(select_case3(), SW_MORE_DATA(0x0C));

    uint8_t  part1[16], part2[16];
    uint16_t l1 = 0u, l2 = 0u;

    /* Four bytes now, eight still to come. */
    CHECK_HEX(get_response(4u, part1, &l1), SW_MORE_DATA(8));
    CHECK_EQ(l1, 4);
    CHECK_EQ(scos_pending_remaining(&g_card), 8);

    CHECK_HEX(get_response(8u, part2, &l2), SW_OK);
    CHECK_EQ(l2, 8);
    CHECK_EQ(scos_pending_remaining(&g_card), 0);

    /* Reassembled, it is the whole template. */
    CHECK_HEX(part1[0], 0x6F);
    CHECK_HEX(part1[1], 0x0A);

    /* And a third attempt finds nothing left. */
    CHECK_HEX(get_response(1u, NULL, NULL), SW_CONDITIONS_NOT_SATISFIED);
}

/* ========================================================== the sequencing = */

TEST(get_response_with_nothing_pending_is_refused)
{
    /*
     * 6985 and not 6D00. The instruction IS supported, so claiming otherwise
     * would tell a reader to stop trying it for good. What is wrong is the
     * sequence.
     */
    fresh();
    CHECK_HEX(get_response(4u, NULL, NULL), SW_CONDITIONS_NOT_SATISFIED);
}

TEST(any_other_command_discards_the_pending_data)
{
    /* THE security-relevant rule in this file. */
    fresh();
    CHECK_HEX(select_case3(), SW_MORE_DATA(0x0C));
    CHECK_EQ(scos_pending_remaining(&g_card), 12);

    /* A perfectly innocent, successful command intervenes. */
    const uint8_t sel[] = { 0x00u, 0xA4u, 0x00u, 0x0Cu, 0x02u, 0x3Fu, 0x00u };
    CHECK_HEX(send(sel, (uint16_t)sizeof(sel), NULL, NULL), SW_OK);
    CHECK_EQ(scos_pending_remaining(&g_card), 0);

    CHECK_HEX(get_response(0x0Cu, NULL, NULL), SW_CONDITIONS_NOT_SATISFIED);
}

TEST(a_failed_command_also_discards_it)
{
    /* The rule is about a command having been dispatched, not about it having
     * succeeded. A reader must not be able to preserve pending data by
     * deliberately sending something that fails. */
    fresh();
    CHECK_HEX(select_case3(), SW_MORE_DATA(0x0C));
    const uint8_t bad[] = { 0x00u, 0xA4u, 0x00u, 0x0Cu, 0x02u, 0xDEu, 0xADu };
    CHECK_HEX(send(bad, (uint16_t)sizeof(bad), NULL, NULL), SW_FILE_NOT_FOUND);
    CHECK_EQ(scos_pending_remaining(&g_card), 0);
}

TEST(a_malformed_frame_does_NOT_discard_it)
{
    /*
     * The deliberate exception, and the one that needs justifying.
     *
     * A frame that fails the structural parse or the class check never reached
     * a command handler, so from the reader's point of view no command
     * intervened -- it was line noise. A card that dropped pending data on a
     * bad frame would make GET RESPONSE unusable on a noisy link, where the
     * reader's only recourse is to retransmit.
     */
    fresh();
    CHECK_HEX(select_case3(), SW_MORE_DATA(0x0C));

    /* Too short to be a header. */
    const uint8_t stub[] = { 0x00u, 0xA4u };
    CHECK_HEX(send(stub, (uint16_t)sizeof(stub), NULL, NULL), SW_WRONG_LENGTH);
    CHECK_EQ(scos_pending_remaining(&g_card), 12);

    /* A class we do not serve. */
    const uint8_t cla[] = { 0x80u, 0xA4u, 0x00u, 0x00u };
    CHECK_HEX(send(cla, (uint16_t)sizeof(cla), NULL, NULL),
              SW_CLA_NOT_SUPPORTED);
    CHECK_EQ(scos_pending_remaining(&g_card), 12);

    /* Still collectable. */
    CHECK_HEX(get_response(0x0Cu, NULL, NULL), SW_OK);
}

TEST(a_reset_discards_it)
{
    fresh();
    CHECK_HEX(select_case3(), SW_MORE_DATA(0x0C));
    scos_reset(&g_card);
    CHECK_EQ(scos_pending_remaining(&g_card), 0);
    CHECK_HEX(get_response(0x0Cu, NULL, NULL), SW_CONDITIONS_NOT_SATISFIED);
}

TEST(the_buffer_is_zeroed_once_collected)
{
    /* Not merely marked empty. The buffer holds file control information now
     * and can hold file contents later; leaving it in RAM after it is no longer
     * reachable through any command costs nothing to avoid. */
    fresh();
    CHECK_HEX(select_case3(), SW_MORE_DATA(0x0C));
    CHECK_HEX(get_response(0x0Cu, NULL, NULL), SW_OK);
    for (uint16_t i = 0; i < SCOS_PENDING_MAX; i++) {
        CHECK_HEX(g_card.pending[i], 0x00);
    }
}

/* ============================================================== bad input = */

TEST(le_larger_than_pending_gives_6cxx_and_does_not_consume)
{
    /*
     * 6CXX tells the reader the exact right length so the retry succeeds first
     * time. Crucially it must NOT consume: a reader that gets 6C0C and asks
     * again for 12 bytes must still find them.
     *
     * The alternative -- returning what exists with 9000 -- is also seen in
     * the wild and is rejected here, because it silently changes the length
     * contract: the reader asked for Le and got fewer, with no indication that
     * it was the card's decision rather than a truncation.
     */
    fresh();
    CHECK_HEX(select_case3(), SW_MORE_DATA(0x0C));
    CHECK_HEX(get_response(0x20u, NULL, NULL), SW_WRONG_LE(0x0C));
    CHECK_EQ(scos_pending_remaining(&g_card), 12);

    uint8_t  data[64];
    uint16_t dlen = 0u;
    CHECK_HEX(get_response(0x0Cu, data, &dlen), SW_OK);
    CHECK_EQ(dlen, 12);
}

TEST(malformed_get_response_is_refused)
{
    fresh();

    struct {
        const uint8_t *a;
        uint16_t       n;
        uint16_t       sw;
        const char    *why;
    } cases[] = {
        { (const uint8_t[]){ 0x00, 0xC0, 0x01, 0x00, 0x04 }, 5,
          SW_INCORRECT_P1P2, "P1 not 0" },
        { (const uint8_t[]){ 0x00, 0xC0, 0x00, 0x01, 0x04 }, 5,
          SW_INCORRECT_P1P2, "P2 not 0" },
        /* Lc: GET RESPONSE has no data field. */
        { (const uint8_t[]){ 0x00, 0xC0, 0x00, 0x00, 0x02, 0x01, 0x02 }, 7,
          SW_WRONG_LENGTH, "has a data field" },
        /* Case 1: no Le at all, so there is nothing to act on. */
        { (const uint8_t[]){ 0x00, 0xC0, 0x00, 0x00 }, 4, SW_WRONG_LENGTH,
          "no Le" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        /* Re-arm before each, so a case that wrongly consumes the data cannot
         * make a later case pass for the wrong reason. */
        CHECK_HEX(select_case3(), SW_MORE_DATA(0x0C));
        const uint16_t sw = send(cases[i].a, cases[i].n, NULL, NULL);
        if (sw != cases[i].sw) {
            (void)printf("      case '%s': got %04X want %04X\n", cases[i].why,
                         sw, cases[i].sw);
        }
        CHECK_HEX(sw, cases[i].sw);
        /* A rejected GET RESPONSE must leave the data alone: it is still the
         * command immediately after the 61XX as far as ISO is concerned. */
        CHECK_EQ(scos_pending_remaining(&g_card), 12);
    }
}

TEST(staging_refuses_impossible_sizes)
{
    /* An OS bug, not a protocol error, so it must not be reported as one. */
    fresh();
    uint8_t buf[SCOS_PENDING_MAX];
    os_memset(buf, 0xA5, sizeof(buf));

    CHECK_HEX(scos_stage_response(&g_card, buf, 0u), SW_NO_PRECISE_DIAGNOSIS);
    CHECK_EQ(scos_pending_remaining(&g_card), 0);

    /* The largest announceable response: 256 bytes, announced as 6100. */
    CHECK_HEX(scos_stage_response(&g_card, buf, SCOS_PENDING_MAX),
              SW_MORE_DATA(0x00));
    CHECK_EQ(scos_pending_remaining(&g_card), SCOS_PENDING_MAX);

    /* One more than can be announced. */
    CHECK_HEX(scos_stage_response(&g_card, buf, SCOS_PENDING_MAX + 1u),
              SW_NO_PRECISE_DIAGNOSIS);
}

TEST(a_full_256_byte_response_round_trips)
{
    /* The boundary where SW2 wraps: 256 bytes must be announced as 6100, and
     * an Le of 00 must be read as 256 rather than 0. */
    fresh();
    uint8_t staged[SCOS_PENDING_MAX];
    for (uint16_t i = 0; i < SCOS_PENDING_MAX; i++) {
        staged[i] = (uint8_t)i;
    }
    CHECK_HEX(scos_stage_response(&g_card, staged, SCOS_PENDING_MAX),
              SW_MORE_DATA(0x00));

    uint8_t  got[SCOS_APDU_RSP_MAX];
    uint16_t glen = 0u;
    CHECK_HEX(get_response(0x00u, got, &glen), SW_OK); /* Le 00 means 256 */
    CHECK_EQ(glen, 256);
    CHECK_HEX(got[0], 0x00);
    CHECK_HEX(got[255], 0xFF);
}

int main(void)
{
    RUN(case3_select_announces_its_fci);
    RUN(get_response_returns_exactly_what_was_announced);
    RUN(the_two_step_matches_the_one_step);
    RUN(data_can_be_collected_in_several_chunks);
    RUN(get_response_with_nothing_pending_is_refused);
    RUN(any_other_command_discards_the_pending_data);
    RUN(a_failed_command_also_discards_it);
    RUN(a_malformed_frame_does_NOT_discard_it);
    RUN(a_reset_discards_it);
    RUN(the_buffer_is_zeroed_once_collected);
    RUN(le_larger_than_pending_gives_6cxx_and_does_not_consume);
    RUN(malformed_get_response_is_refused);
    RUN(staging_refuses_impossible_sizes);
    RUN(a_full_256_byte_response_round_trips);
    TEST_MAIN_END();
}
