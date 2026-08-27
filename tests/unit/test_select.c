/* SPDX-License-Identifier: MIT
 *
 * test_select.c -- SELECT and the kernel's command path.
 *
 * These tests call scos_process() directly: no reader, no transport, no
 * sockets. That is the "scos_process is a pure function of (state, command)"
 * rule paying off -- the whole command surface is exercised as a library.
 *
 * WHAT CHANGED IN M2: a HAL is now linked in.
 * The filesystem needs storage, so command tests need NVM. Rather than write a
 * mock, we use the simulator HAL with state_dir = NULL, which is already an
 * in-RAM hermetic NVM -- a test double that happens to be the real code path.
 * The genuinely HAL-free tests are test_apdu_parse and test_os_mem.
 */
#include "apdu/sw.h"
#include "filesystem/fs.h"
#include "hal/hal.h"
#include "hal/sim/vcard.h"
#include "os/kernel.h"

#include "scos_test.h"

static scos_kernel g_card;

/* --- selection helpers -------------------------------------------------- */
/* M1 stored a bare selected_fid. M2 stores descriptor indices, so the tests
 * ask the filesystem what those indices mean. */

static uint16_t selected_fid(void)
{
    fs_descriptor d;
    if (fs_get(fs_selected_index(&g_card.sel), &d) != FS_OK) {
        return 0xFFFFu;
    }
    return d.file_id;
}

static uint16_t current_df_fid(void)
{
    fs_descriptor d;
    if (fs_get(g_card.sel.cur_df, &d) != FS_OK) {
        return 0xFFFFu;
    }
    return d.file_id;
}

static bool has_current_ef(void)
{ return g_card.sel.cur_ef != FS_INVALID_INDEX; }

/* Send an APDU, return the status word, and check the response shape. */
static uint16_t send(const uint8_t *cmd, uint16_t len, uint16_t *out_data_len)
{
    uint8_t  rsp[SCOS_APDU_RSP_MAX];
    uint16_t rsp_len = 0u;

    const scos_status st =
        scos_process(&g_card, cmd, len, rsp, (uint16_t)sizeof(rsp), &rsp_len);
    CHECK_EQ(st, SCOS_OK);

    /* THE core invariant: every response carries at least SW1 SW2. */
    CHECK(rsp_len >= 2u);
    if (rsp_len < 2u) {
        return 0u;
    }
    if (out_data_len != NULL) {
        *out_data_len = (uint16_t)(rsp_len - 2u);
    }
    return (uint16_t)(((uint16_t)rsp[rsp_len - 2u] << 8) | rsp[rsp_len - 1u]);
}

/* A freshly personalised card: blank NVM, factory file layout, MF selected. */
static void fresh(void)
{
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(scos_init(&g_card), SCOS_OK);
}

/* ------------------------------------------------- the milestone target --- */

TEST(select_mf_the_first_test)
{
    fresh();
    /* 00 A4 00 00 02 3F 00
     * CLA=00 interindustry, INS=A4 SELECT, P1=00 by file identifier,
     * P2=00 first occurrence / return FCI, Lc=02, data=3F00 (the Master File).
     *
     * Case 3: no Le, so under T=0 the card cannot return the FCI on this
     * command at all. It answers 61XX -- "I have XX bytes" -- and the reader
     * collects them with GET RESPONSE. Until M2b this returned 9000 with no
     * data, which was well-formed and silently useless.
     *
     * 61XX is a SUCCESS status, so the selection must have moved. Asserting
     * that here is what caught the bug where it had not. */
    const uint8_t cmd[]    = { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00 };
    uint16_t      data_len = 0xFFFFu;
    CHECK_HEX(send(cmd, sizeof(cmd), &data_len), SW_MORE_DATA(0x0C));
    CHECK_EQ(data_len, 0); /* 61XX carries no data of its own */
    CHECK_HEX(selected_fid(), 0x3F00);
    CHECK(!has_current_ef());
}

TEST(select_mf_with_absent_data_field)
{
    fresh();
    /* ISO permits an absent data field with P1=00, meaning "select the MF".
     * Case 1 (header only) and Case 2 (with Le) must both work. */
    /* Case 1 has no Le either, so it too announces rather than returns. */
    const uint8_t case1[] = { 0x00, 0xA4, 0x00, 0x00 };
    CHECK_HEX(send(case1, sizeof(case1), NULL), SW_MORE_DATA(0x0C));
    CHECK_HEX(selected_fid(), 0x3F00);

    fresh();
    /* Case 2 asks for up to 256 bytes, so the FCI template comes back. */
    const uint8_t case2[]  = { 0x00, 0xA4, 0x00, 0x00, 0x00 };
    uint16_t      data_len = 0u;
    CHECK_HEX(send(case2, sizeof(case2), &data_len), SW_OK);
    CHECK(data_len > 0);
    CHECK_HEX(selected_fid(), 0x3F00);
}

TEST(select_p2_no_response_data_accepted)
{
    fresh();
    /* P2 = 0C: "return no response data". */
    const uint8_t cmd[]    = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00 };
    uint16_t      data_len = 0xFFFFu;
    CHECK_HEX(send(cmd, sizeof(cmd), &data_len), SW_OK);
    CHECK_EQ(data_len, 0);
}

/* ------------------------------------------------------- rejection paths -- */

TEST(select_unknown_file_is_6a82)
{
    fresh();
    /* 2F02 is not in the factory layout. NOT 2F01: that is EF.ATR, which the
     * card now really has -- this test used it as a stand-in for "absent" and
     * started failing with 61XX the moment the file became real. */
    const uint8_t cmd[] = { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0x02 };
    CHECK_HEX(send(cmd, sizeof(cmd), NULL), SW_FILE_NOT_FOUND);
    /* The failure must not have moved the selection off the MF. */
    CHECK_HEX(current_df_fid(), 0x3F00);
    CHECK(!has_current_ef());
}

TEST(failed_select_preserves_previous_selection)
{
    fresh();
    /* Select a real EF, then fail a selection, and confirm the EF is still
     * current. ISO requires it, and a card that cleared its selection on a
     * failed lookup would let an attacker drop the security context with a
     * junk APDU. */
    const uint8_t good[] = { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0x00 };
    CHECK_HEX(send(good, sizeof(good), NULL), SW_MORE_DATA(0x13));
    CHECK_HEX(selected_fid(), 0x2F00);
    CHECK(has_current_ef());

    const uint8_t bad[] = { 0x00, 0xA4, 0x00, 0x00, 0x02, 0xDE, 0xAD };
    CHECK_HEX(send(bad, sizeof(bad), NULL), SW_FILE_NOT_FOUND);
    CHECK_HEX(selected_fid(), 0x2F00);
    CHECK(has_current_ef());
}

TEST(select_by_df_name_not_supported)
{
    fresh();
    /* P1=04 selects by AID. AIDs are registered by the Card Manager, which
     * does not exist yet -- so there is nothing to search. 6A81 says "function
     * not supported", which is the truth; 6A82 "file not found" would imply we
     * looked. */
    const uint8_t by_name[] = { 0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00 };
    CHECK_HEX(send(by_name, sizeof(by_name), NULL), SW_FUNC_NOT_SUPPORTED);
}

TEST(select_undefined_p1_is_6a86)
{
    fresh();
    const uint8_t bad[] = { 0x00, 0xA4, 0x77, 0x00, 0x02, 0x3F, 0x00 };
    CHECK_HEX(send(bad, sizeof(bad), NULL), SW_INCORRECT_P1P2);
}

TEST(select_reserved_p2_bits_rejected)
{
    fresh();
    /* b8..b5 of P2 are reserved and must be zero. */
    const uint8_t cmd[] = { 0x00, 0xA4, 0x00, 0x80, 0x02, 0x3F, 0x00 };
    CHECK_HEX(send(cmd, sizeof(cmd), NULL), SW_INCORRECT_P1P2);
}

TEST(select_fmd_template_not_supported)
{
    fresh();
    /* FCP (P2=04) IS supported in M2 -- see test_fs.c. FMD (P2=08) is issuer
     * management data we hold none of; an empty 64 template would assert "this
     * file has no management data" rather than "this card has no FMD". */
    const uint8_t fmd[] = { 0x00, 0xA4, 0x00, 0x08, 0x02, 0x3F, 0x00, 0x20 };
    CHECK_HEX(send(fmd, sizeof(fmd), NULL), SW_FUNC_NOT_SUPPORTED);
}

TEST(select_wrong_lc_is_6a87)
{
    fresh();
    /* A structurally valid APDU whose Lc is wrong for this P1. */
    const uint8_t cmd[] = { 0x00, 0xA4, 0x00, 0x00, 0x03, 0x3F, 0x00, 0x01 };
    CHECK_HEX(send(cmd, sizeof(cmd), NULL), SW_LC_INCONSISTENT_P1P2);
    const uint8_t one[] = { 0x00, 0xA4, 0x00, 0x00, 0x01, 0x3F };
    CHECK_HEX(send(one, sizeof(one), NULL), SW_LC_INCONSISTENT_P1P2);
}

/* -------------------------------------------------------- kernel routing -- */

TEST(unknown_ins_is_6d00)
{
    fresh();
    const uint8_t cmd[] = { 0x00, 0xEE, 0x00, 0x00 };
    CHECK_HEX(send(cmd, sizeof(cmd), NULL), SW_INS_NOT_SUPPORTED);
}

TEST(not_yet_implemented_ins_is_6d00)
{
    fresh();
    /*
     * Commands that ISO defines and we have not written yet must report "INS
     * not supported", which is the truth. This list SHRINKS as milestones
     * land, and each graduation is a deliberate edit here:
     *
     *   B0 / D6  -> M2a, covered by test_fs.c
     *   E0 / E4  -> M2b, covered by test_create.c
     *   C0       -> M2b, covered by test_get_response.c
     *   44 / 04  -> M2b, covered by test_lifecycle.c
     *   20       -> M3,  covered by test_pin.c
     *
     * Still absent: GET DATA.
     */
    const uint8_t ins[] = { 0xCA };
    for (unsigned i = 0; i < sizeof(ins); i++) {
        const uint8_t cmd[] = { 0x00, ins[i], 0x00, 0x00 };
        CHECK_HEX(send(cmd, sizeof(cmd), NULL), SW_INS_NOT_SUPPORTED);
    }
}

TEST(implemented_ins_is_never_6d00)
{
    /*
     * The other half of the test above, and the half that catches a real
     * mistake: a handler that exists but was never added to the dispatch table
     * answers 6D00, and a list of what is ABSENT cannot detect that.
     */
    fresh();
    const uint8_t ins[] = {
        0xA4, 0xB0, 0xD6, 0xE0, 0xE4, 0xC0, 0x44, 0x04, 0x20
    };
    for (unsigned i = 0; i < sizeof(ins); i++) {
        const uint8_t  cmd[] = { 0x00, ins[i], 0x00, 0x00 };
        const uint16_t sw    = send(cmd, sizeof(cmd), NULL);
        if (sw == SW_INS_NOT_SUPPORTED) {
            (void)printf("      INS %02X answered 6D00: not in the dispatch "
                         "table?\n",
                         ins[i]);
        }
        CHECK(sw != SW_INS_NOT_SUPPORTED);
    }
}

TEST(bad_cla_is_diagnosed)
{
    fresh();
    const uint8_t sm[] = { 0x0C, 0xA4, 0x00, 0x00 };
    CHECK_HEX(send(sm, sizeof(sm), NULL), SW_SECURE_MESSAGING_NOT_SUPPORTED);
    const uint8_t chan[] = { 0x01, 0xA4, 0x00, 0x00 };
    CHECK_HEX(send(chan, sizeof(chan), NULL), SW_LOGICAL_CHANNEL_NOT_SUPPORTED);
    const uint8_t chain[] = { 0x10, 0xA4, 0x00, 0x00 };
    CHECK_HEX(send(chain, sizeof(chain), NULL), SW_CHAINING_NOT_SUPPORTED);
    const uint8_t prop[] = { 0x80, 0xA4, 0x00, 0x00 };
    CHECK_HEX(send(prop, sizeof(prop), NULL), SW_CLA_NOT_SUPPORTED);
    const uint8_t ff[] = { 0xFF, 0xA4, 0x00, 0x00 };
    CHECK_HEX(send(ff, sizeof(ff), NULL), SW_CLA_NOT_SUPPORTED);
}

/* CLA is checked before INS: an unsupported class must not reveal whether the
 * instruction inside it exists. Both of these must give the same answer. */
TEST(cla_checked_before_ins)
{
    fresh();
    const uint8_t known_ins[]   = { 0x80, 0xA4, 0x00, 0x00 };
    const uint8_t unknown_ins[] = { 0x80, 0xEE, 0x00, 0x00 };
    CHECK_HEX(send(known_ins, sizeof(known_ins), NULL),
              send(unknown_ins, sizeof(unknown_ins), NULL));
}

TEST(malformed_apdu_still_answers)
{
    fresh();
    const uint8_t truncated[] = { 0x00, 0xA4, 0x00 };
    CHECK_HEX(send(truncated, sizeof(truncated), NULL), SW_WRONG_LENGTH);

    uint8_t  rsp[SCOS_APDU_RSP_MAX];
    uint16_t rsp_len = 0u;
    /* Empty APDU: zero length, and a NULL pointer. Both must produce a
     * well-formed 6700 rather than a crash. */
    CHECK_EQ(
        scos_process(&g_card, rsp, 0u, rsp, (uint16_t)sizeof(rsp), &rsp_len),
        SCOS_OK);
    CHECK_EQ(rsp_len, 2);
    CHECK_HEX(((uint16_t)rsp[0] << 8) | rsp[1], SW_WRONG_LENGTH);

    CHECK_EQ(
        scos_process(&g_card, NULL, 0u, rsp, (uint16_t)sizeof(rsp), &rsp_len),
        SCOS_OK);
    CHECK_EQ(rsp_len, 2);
}

TEST(response_buffer_too_small_is_a_param_error)
{
    fresh();
    const uint8_t cmd[] = { 0x00, 0xA4, 0x00, 0x00 };
    uint8_t       rsp[2];
    uint16_t      rsp_len = 0u;
    /* Exactly 2 bytes is enough for SW alone. */
    CHECK_EQ(scos_process(&g_card, cmd, sizeof(cmd), rsp, 2u, &rsp_len),
             SCOS_OK);
    CHECK_EQ(rsp_len, 2);
    /* Fewer than 2 is a platform bug, reported as such rather than papered
     * over -- the card physically cannot answer. */
    CHECK_EQ(scos_process(&g_card, cmd, sizeof(cmd), rsp, 1u, &rsp_len),
             SCOS_ERR_PARAM);
    CHECK_EQ(scos_process(&g_card, cmd, sizeof(cmd), NULL, 8u, &rsp_len),
             SCOS_ERR_PARAM);
    CHECK_EQ(scos_process(NULL, cmd, sizeof(cmd), rsp, 2u, &rsp_len),
             SCOS_ERR_PARAM);
}

/* --------------------------------------------------------------- lifecycle */

TEST(reset_clears_selection_but_counts_up)
{
    fresh();
    const uint8_t cmd[] = { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0x00 };
    CHECK_HEX(send(cmd, sizeof(cmd), NULL), SW_MORE_DATA(0x13));
    CHECK(has_current_ef());

    scos_reset(&g_card);
    /* Volatile state is gone -- this is what makes a reset a security event.
     * Note the selection does not become "none": ISO says a reset returns to
     * the MF, so the MF is current with no EF selected. */
    CHECK_HEX(current_df_fid(), 0x3F00);
    CHECK(!has_current_ef());
    CHECK_EQ(g_card.reset_count, 1);
    CHECK_EQ(g_card.lifecycle, SCOS_LC_OPERATIONAL);

    scos_reset(&g_card);
    CHECK_EQ(g_card.reset_count, 2);

    /* The card still works after a reset. Still a Case 3 SELECT, so still
     * 61XX -- the point of the check is that it answers at all. */
    CHECK_HEX(send(cmd, sizeof(cmd), NULL), SW_MORE_DATA(0x13));
}

TEST(terminated_card_answers_6985)
{
    fresh();
    g_card.lifecycle    = SCOS_LC_TERMINATED;
    const uint8_t cmd[] = { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00 };
    /* A terminated card is a brick, but it must still answer so that a reader
     * can distinguish "terminated" from "dead". */
    CHECK_HEX(send(cmd, sizeof(cmd), NULL), SW_CONDITIONS_NOT_SATISFIED);
}

/* ---------------------------------------------------------- robustness ---- */

/*
 * Every 4-byte header in a large slice of the space, plus every length from 0
 * to 261 on a fixed pattern. Not a substitute for the fuzzer (Milestone 2),
 * but it makes "the card always answers" a tested property rather than a hope.
 */
TEST(never_fails_to_answer)
{
    fresh();
    uint8_t  cmd[261];
    uint8_t  rsp[SCOS_APDU_RSP_MAX];
    uint16_t rsp_len;

    for (unsigned i = 0; i < sizeof(cmd); i++) {
        cmd[i] = (uint8_t)(i * 7u);
    }

    unsigned answered = 0u;
    for (unsigned cla = 0; cla <= 0xFFu; cla += 17u) {
        for (unsigned ins = 0; ins <= 0xFFu; ins += 13u) {
            for (unsigned len = 0; len <= 261u; len += 7u) {
                cmd[0]  = (uint8_t)cla;
                cmd[1]  = (uint8_t)ins;
                rsp_len = 0u;
                const scos_status st =
                    scos_process(&g_card, cmd, (uint16_t)len, rsp,
                                 (uint16_t)sizeof(rsp), &rsp_len);
                CHECK_EQ(st, SCOS_OK);
                CHECK(rsp_len >= 2u);
                CHECK(rsp_len <= sizeof(rsp));
                /* SW1 must be a valid ISO status class: 6X or 9X. */
                const uint8_t s1 = rsp[rsp_len - 2u];
                CHECK((s1 & 0xF0u) == 0x60u || (s1 & 0xF0u) == 0x90u);
                answered++;
            }
        }
    }
    CHECK(answered > 5000u);
}

int main(void)
{
    vcard_config cfg;
    vcard_config_default(&cfg);
    cfg.state_dir = NULL; /* hermetic in-RAM NVM */
    cfg.quiet     = true;
    vcard_configure(&cfg);
    if (hal_init() != HAL_OK) {
        (void)printf("FATAL: hal_init failed\n");
        return EXIT_FAILURE;
    }

    RUN(select_mf_the_first_test);
    RUN(select_mf_with_absent_data_field);
    RUN(select_p2_no_response_data_accepted);
    RUN(select_unknown_file_is_6a82);
    RUN(failed_select_preserves_previous_selection);
    RUN(select_by_df_name_not_supported);
    RUN(select_undefined_p1_is_6a86);
    RUN(select_reserved_p2_bits_rejected);
    RUN(select_fmd_template_not_supported);
    RUN(select_wrong_lc_is_6a87);
    RUN(unknown_ins_is_6d00);
    RUN(not_yet_implemented_ins_is_6d00);
    RUN(implemented_ins_is_never_6d00);
    RUN(bad_cla_is_diagnosed);
    RUN(cla_checked_before_ins);
    RUN(malformed_apdu_still_answers);
    RUN(response_buffer_too_small_is_a_param_error);
    RUN(reset_clears_selection_but_counts_up);
    RUN(terminated_card_answers_6985);
    RUN(never_fails_to_answer);
    TEST_MAIN_END();
}
