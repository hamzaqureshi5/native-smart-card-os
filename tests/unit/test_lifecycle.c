/* SPDX-License-Identifier: MIT
 *
 * test_lifecycle.c -- ACTIVATE FILE (44) and DEACTIVATE FILE (04) at the
 * command layer.
 *
 * tests/unit/test_fs.c covers fs_set_lifecycle() and the selectable/usable
 * split underneath. What is here is the APDU contract: which P1-P2 and length
 * combinations are accepted, which status word each refusal produces, and --
 * the sequence that matters most -- that deactivate followed by activate
 * works with no SELECT in between.
 *
 * That last one is the whole reason this pair of commands is testable at all.
 * Both address "the currently selected file", so if deactivating a file
 * dropped it from the selection, or if a deactivated file could not be
 * selected, the pair would be a one-way door.
 */
#include "apdu/apdu.h"
#include "apdu/dispatch.h"
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

/* Case 1: header only, which is the shape both commands take. */
static uint16_t lc_cmd(uint8_t ins, uint8_t p1, uint8_t p2)
{
    const uint8_t c[] = { 0x00u, ins, p1, p2 };
    return send(c, (uint16_t)sizeof(c), NULL, NULL);
}

static uint16_t activate(void)
{ return lc_cmd(INS_ACTIVATE_FILE, 0u, 0u); }
static uint16_t deactivate(void)
{ return lc_cmd(INS_DEACTIVATE_FILE, 0u, 0u); }

/*
 * CREATE FILE templates are BUILT, never hand-written.
 *
 * The first draft of the DF/EF pair below had the wrong Lc twice -- the same
 * mistake tests/unit/test_create.c already carries a warning about, made again
 * by the same author in the same session. So the only lengths stated here are
 * the ones inside the objects; every enclosing length is derived and cannot
 * disagree with what it encloses.
 */
static uint16_t put_tlv(uint8_t *out, uint8_t tag, const uint8_t *val,
                        uint8_t len)
{
    out[0] = tag;
    out[1] = len;
    for (uint8_t i = 0; i < len; i++) {
        out[2u + i] = val[i];
    }
    return (uint16_t)(2u + len);
}

/* CREATE FILE with a 62 template wrapping `inner`, all lengths derived. */
static uint16_t create_from(const uint8_t *inner, uint8_t inner_len)
{
    uint8_t  apdu[64];
    uint16_t n = 0u;
    apdu[n++]  = 0x00u;
    apdu[n++]  = 0xE0u;
    apdu[n++]  = 0x00u;
    apdu[n++]  = 0x00u;
    apdu[n++]  = (uint8_t)(inner_len + 2u); /* Lc: template tag + length  */
    apdu[n++]  = 0x62u;
    apdu[n++]  = inner_len;
    for (uint8_t i = 0; i < inner_len; i++) {
        apdu[n++] = inner[i];
    }
    return send(apdu, n, NULL, NULL);
}

static uint16_t create_ef(uint16_t fid, uint16_t size)
{
    uint8_t       inner[32];
    uint16_t      n     = 0u;
    const uint8_t fdb[] = { 0x01u }; /* transparent EF */
    const uint8_t id[]  = { (uint8_t)(fid >> 8), (uint8_t)(fid & 0xFFu) };
    const uint8_t sz[]  = { (uint8_t)(size >> 8), (uint8_t)(size & 0xFFu) };
    const uint8_t lc[]  = { 0x05u };
    n += put_tlv(&inner[n], 0x82u, fdb, 1u);
    n += put_tlv(&inner[n], 0x83u, id, 2u);
    n += put_tlv(&inner[n], 0x80u, sz, 2u);
    n += put_tlv(&inner[n], 0x8Au, lc, 1u);
    return create_from(inner, (uint8_t)n);
}

/* Navigate to an EF: SELECT by FID with P2=0C (no FCI wanted). */
static uint16_t select_ef(uint16_t fid)
{
    const uint8_t c[] = { 0x00u,
                          0xA4u,
                          0x02u,
                          0x0Cu,
                          0x02u,
                          (uint8_t)(fid >> 8),
                          (uint8_t)(fid & 0xFFu) };
    return send(c, (uint16_t)sizeof(c), NULL, NULL);
}

static uint16_t select_mf(void)
{
    const uint8_t c[] = { 0x00u, 0xA4u, 0x00u, 0x0Cu, 0x02u, 0x3Fu, 0x00u };
    return send(c, (uint16_t)sizeof(c), NULL, NULL);
}

static uint16_t read4(void)
{
    const uint8_t c[] = { 0x00u, 0xB0u, 0x00u, 0x00u, 0x04u };
    return send(c, (uint16_t)sizeof(c), NULL, NULL);
}

/* ========================================================= the round trip = */

TEST(deactivate_then_activate_needs_no_reselect)
{
    /*
     * THE test. Both commands act on the current selection, so the sequence
     * below is the one an administrator sends -- and every plausible design
     * mistake breaks it:
     *
     *   - clearing the selection after DEACTIVATE (the tempting tidy-up)
     *   - refusing to select a deactivated file (the old fs.c rule)
     *   - refusing ACTIVATE on a file that is not usable
     *
     * Each of those is individually defensible and all three make the pair
     * useless.
     */
    fresh();
    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(select_ef(0x2F00u), SW_OK);
    CHECK_HEX(read4(), SW_OK);

    CHECK_HEX(deactivate(), SW_OK);
    /* Now unreadable... */
    CHECK_HEX(read4(), SW_CONDITIONS_NOT_SATISFIED);

    /* ...and reactivated in place, with no SELECT between. */
    CHECK_HEX(activate(), SW_OK);
    CHECK_HEX(read4(), SW_OK);
}

TEST(deactivate_survives_a_reselect)
{
    /* The state is in NVM, not in the selection. Selecting away and back must
     * find the file still deactivated. */
    fresh();
    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(select_ef(0x2F00u), SW_OK);
    CHECK_HEX(deactivate(), SW_OK);

    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(select_ef(0x2F00u), SW_OK); /* selectable, per the new rule */
    CHECK_HEX(read4(), SW_CONDITIONS_NOT_SATISFIED);

    CHECK_HEX(activate(), SW_OK);
    CHECK_HEX(read4(), SW_OK);
}

TEST(repeating_the_command_succeeds)
{
    /*
     * Idempotent on purpose. If the response to a DEACTIVATE is lost on the
     * link, the reader's only recourse is to send it again; failing the retry
     * would leave a correct reader unable to complete a correct sequence.
     */
    fresh();
    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(select_ef(0x2F00u), SW_OK);
    CHECK_HEX(deactivate(), SW_OK);
    CHECK_HEX(deactivate(), SW_OK);
    CHECK_HEX(activate(), SW_OK);
    CHECK_HEX(activate(), SW_OK);
    CHECK_HEX(read4(), SW_OK);
}

/* ============================================================ the refusals = */

TEST(the_mf_cannot_be_deactivated)
{
    /*
     * With the MF selected and no current EF, DEACTIVATE targets the MF. It
     * must be refused: the MF is the only entry point to the tree, so turning
     * it off is bricking the card rather than administering it. Taking a whole
     * card out of service is TERMINATE CARD's job, deliberately a different
     * command.
     */
    fresh();
    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(deactivate(), SW_CONDITIONS_NOT_SATISFIED);

    /* And the card is still fully usable afterwards. */
    CHECK_HEX(select_ef(0x2F00u), SW_OK);
    CHECK_HEX(read4(), SW_OK);
}

TEST(non_zero_p1_p2_is_incorrect_p1_p2)
{
    /*
     * ISO/IEC 7816-9 also defines path- and identifier-based addressing for
     * these commands. Not implemented, and refused with 6A86 rather than
     * guessed at -- the encoding of that data field is something this project
     * would be inventing rather than following.
     *
     * 6A86 and not 6D00: the instruction IS supported. Claiming otherwise
     * would tell a reader to stop using the command entirely.
     */
    fresh();
    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(select_ef(0x2F00u), SW_OK);

    CHECK_HEX(lc_cmd(INS_DEACTIVATE_FILE, 0x08u, 0x00u), SW_INCORRECT_P1P2);
    CHECK_HEX(lc_cmd(INS_DEACTIVATE_FILE, 0x00u, 0x01u), SW_INCORRECT_P1P2);
    CHECK_HEX(lc_cmd(INS_ACTIVATE_FILE, 0x09u, 0x00u), SW_INCORRECT_P1P2);
    CHECK_HEX(lc_cmd(INS_ACTIVATE_FILE, 0xFFu, 0xFFu), SW_INCORRECT_P1P2);

    /* None of those changed anything. */
    CHECK_HEX(read4(), SW_OK);
}

TEST(a_data_field_is_refused_not_ignored)
{
    /*
     * The dangerous case. With P1-P2 both zero the target is the selection, so
     * a data field would be a file identifier the card is NOT reading.
     * Ignoring it would let a reader believe it had deactivated 6F01 while the
     * card actually deactivated whatever happened to be selected -- a
     * successful answer to a command that did something else.
     *
     * 6A87 "Lc inconsistent with P1-P2" is exactly that fact.
     */
    fresh();
    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(select_ef(0x2F00u), SW_OK);

    const uint8_t with_fid[] = {
        0x00u, 0x04u, 0x00u, 0x00u, 0x02u, 0x6Fu, 0x01u
    };
    CHECK_HEX(send(with_fid, (uint16_t)sizeof(with_fid), NULL, NULL),
              SW_LC_INCONSISTENT_P1P2);

    /* The selected file was NOT deactivated as a side effect. */
    CHECK_HEX(read4(), SW_OK);
}

TEST(an_le_is_refused)
{
    /* Neither command returns data, so an Le is a caller error worth
     * reporting rather than ignoring -- the same rule UPDATE BINARY uses. */
    fresh();
    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(select_ef(0x2F00u), SW_OK);

    const uint8_t with_le[] = { 0x00u, 0x04u, 0x00u, 0x00u, 0x00u };
    CHECK_HEX(send(with_le, (uint16_t)sizeof(with_le), NULL, NULL),
              SW_WRONG_LENGTH);
    CHECK_HEX(read4(), SW_OK);
}

TEST(the_two_instructions_are_not_swapped)
{
    /*
     * 44 is ACTIVATE and 04 is DEACTIVATE. They are not adjacent and they are
     * easy to transpose, and a transposition would turn "take this file out of
     * service" into "put it back" -- a security failure that every other test
     * here would still pass, because they all use the helpers.
     *
     * So this one asserts the raw INS bytes have the effects claimed.
     */
    fresh();
    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(select_ef(0x2F00u), SW_OK);

    const uint8_t ins04[] = { 0x00u, 0x04u, 0x00u, 0x00u };
    const uint8_t ins44[] = { 0x00u, 0x44u, 0x00u, 0x00u };

    /* 04 must make the file unreadable. */
    CHECK_HEX(send(ins04, (uint16_t)sizeof(ins04), NULL, NULL), SW_OK);
    CHECK_HEX(read4(), SW_CONDITIONS_NOT_SATISFIED);

    /* 44 must make it readable again. */
    CHECK_HEX(send(ins44, (uint16_t)sizeof(ins44), NULL, NULL), SW_OK);
    CHECK_HEX(read4(), SW_OK);
}

TEST(deactivating_a_df_blocks_its_children_over_the_command_layer)
{
    /*
     * The end-to-end form of test_fs.c's ancestor check. Deactivating a DF
     * must take its contents out of service, or the command is a lie: it
     * would report success while every file inside stayed readable.
     *
     * NAVIGATION MATTERS HERE, and getting it wrong cost a debugging round.
     * Both commands target "the current EF if one is selected, else the
     * current DF", so to aim at a DF the current EF must be clear. Selecting
     * a child DF from the MF does that. Selecting the PARENT (P1=03) does
     * NOT: from inside 7F10 it moves the current DF to the MF, and the card
     * then correctly refused to deactivate the root.
     */
    fresh();

    /* 7F10 is already a DF in the factory layout (see fs_personalise), so
     * this uses it rather than creating a duplicate -- creating it answers
     * 6A89. */
    const uint8_t sel_df[] = {
        0x00u, 0xA4u, 0x01u, 0x0Cu, 0x02u, 0x7Fu, 0x10u
    };
    const uint8_t sel_ef[] = {
        0x00u, 0xA4u, 0x02u, 0x0Cu, 0x02u, 0x6Fu, 0x10u
    };

    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(send(sel_df, (uint16_t)sizeof(sel_df), NULL, NULL), SW_OK);
    CHECK_HEX(create_ef(0x6F10u, 16u), SW_OK);
    CHECK_HEX(send(sel_ef, (uint16_t)sizeof(sel_ef), NULL, NULL), SW_OK);
    CHECK_HEX(read4(), SW_OK);

    /* Aim at the DF: back to the MF, then into 7F10, which clears cur_ef. */
    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(send(sel_df, (uint16_t)sizeof(sel_df), NULL, NULL), SW_OK);
    CHECK_HEX(deactivate(), SW_OK);

    /*
     * The EF is still ACTIVATED in its own right. Only the ancestor walk can
     * catch this, which is exactly the point: before ancestors_usable(), this
     * read succeeded and DEACTIVATE on a directory protected nothing.
     */
    CHECK_HEX(send(sel_ef, (uint16_t)sizeof(sel_ef), NULL, NULL), SW_OK);
    CHECK_HEX(read4(), SW_CONDITIONS_NOT_SATISFIED);

    /* Reactivate the DF and the whole subtree comes back. Note that this
     * requires selecting a DEACTIVATED DF -- the thing the old rule forbade,
     * and the reason it was a one-way door. */
    CHECK_HEX(select_mf(), SW_OK);
    CHECK_HEX(send(sel_df, (uint16_t)sizeof(sel_df), NULL, NULL), SW_OK);
    CHECK_HEX(activate(), SW_OK);
    CHECK_HEX(send(sel_ef, (uint16_t)sizeof(sel_ef), NULL, NULL), SW_OK);
    CHECK_HEX(read4(), SW_OK);
}

TEST(both_instructions_are_known_to_the_dispatcher)
{
    /* A registration that silently did not apply is a real failure mode here:
     * clang-format once collapsed an aligned table entry so a string replace
     * matched nothing, the build stayed clean, and the command answered 6D00.
     * So assert the dispatcher knows them by name. */
    CHECK(scos_ins_name(INS_ACTIVATE_FILE) != NULL);
    CHECK(scos_ins_name(INS_DEACTIVATE_FILE) != NULL);
    CHECK_EQ(scos_ins_name(0x44u)[0], 'A');
    CHECK_EQ(scos_ins_name(0x04u)[0], 'D');
}

int main(void)
{
    RUN(deactivate_then_activate_needs_no_reselect);
    RUN(deactivate_survives_a_reselect);
    RUN(repeating_the_command_succeeds);
    RUN(the_mf_cannot_be_deactivated);
    RUN(non_zero_p1_p2_is_incorrect_p1_p2);
    RUN(a_data_field_is_refused_not_ignored);
    RUN(an_le_is_refused);
    RUN(the_two_instructions_are_not_swapped);
    RUN(deactivating_a_df_blocks_its_children_over_the_command_layer);
    RUN(both_instructions_are_known_to_the_dispatcher);
    TEST_MAIN_END();
}
