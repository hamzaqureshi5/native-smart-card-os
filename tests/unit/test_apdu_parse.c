/* SPDX-License-Identifier: MIT
 *
 * test_apdu_parse.c -- The parser is the attack surface, so it gets the most
 * tests. Each group documents the ISO rule it pins down.
 */
#include "apdu/apdu.h"
#include "os/scos_config.h"
#include "os/os_mem.h"
#include "apdu/sw.h"

#include "scos_test.h"

/* ---------------------------------------------------- the four ISO cases -- */

TEST(case1_header_only)
{
    const uint8_t buf[] = { 0x00, 0xA4, 0x00, 0x00 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK_EQ(c.acase, APDU_CASE_1);
    CHECK_HEX(c.cla, 0x00);
    CHECK_HEX(c.ins, 0xA4);
    CHECK_EQ(c.lc, 0);
    CHECK(c.data == NULL);
    CHECK(!c.le_present);
}

TEST(case2_le_only)
{
    /* Five bytes: the fifth is Le, NOT Lc. This is the rule that catches
     * everyone. */
    const uint8_t buf[] = { 0x00, 0xB0, 0x00, 0x00, 0x08 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK_EQ(c.acase, APDU_CASE_2);
    CHECK_EQ(c.lc, 0);
    CHECK(c.data == NULL);
    CHECK(c.le_present);
    CHECK_EQ(c.le, 8);
}

TEST(case2_le_zero_means_256)
{
    const uint8_t buf[] = { 0x00, 0xB0, 0x00, 0x00, 0x00 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK_EQ(c.acase, APDU_CASE_2);
    CHECK(c.le_present);
    CHECK_EQ(c.le, 256); /* not 0 */
}

TEST(case3_data_no_le)
{
    const uint8_t buf[] = { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK_EQ(c.acase, APDU_CASE_3);
    CHECK_EQ(c.lc, 2);
    CHECK(c.data == &buf[5]); /* aliases the input; no copy */
    CHECK_HEX(c.data[0], 0x3F);
    CHECK_HEX(c.data[1], 0x00);
    CHECK(!c.le_present);
}

TEST(case4_data_and_le)
{
    const uint8_t buf[] = { 0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00, 0x10 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK_EQ(c.acase, APDU_CASE_4);
    CHECK_EQ(c.lc, 2);
    CHECK(c.le_present);
    CHECK_EQ(c.le, 0x10);
}

TEST(case4_le_zero_means_256)
{
    const uint8_t buf[] = { 0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00, 0x00 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK_EQ(c.le, 256);
}

TEST(case3_max_lc)
{
    /* Lc = 255 is the largest short-form data field. 4 + 1 + 255 = 260. */
    uint8_t buf[260];
    buf[0] = 0x00;
    buf[1] = 0xD6;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0xFF;
    for (unsigned i = 5; i < sizeof(buf); i++) {
        buf[i] = (uint8_t)i;
    }

    apdu_command c;
    CHECK_EQ(apdu_parse(buf, (uint16_t)sizeof(buf), &c), APDU_PARSE_OK);
    CHECK_EQ(c.acase, APDU_CASE_3);
    CHECK_EQ(c.lc, 255);
    CHECK_HEX(c.data[254], buf[259]);
}

TEST(case4_max_length)
{
    /* 4 + 1 + 255 + 1 = 261, the largest short-form command APDU. */
    uint8_t buf[261];
    buf[0] = 0x00;
    buf[1] = 0xD6;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0xFF;
    for (unsigned i = 5; i < 260; i++) {
        buf[i] = 0xAA;
    }
    buf[260] = 0x05;

    apdu_command c;
    CHECK_EQ(apdu_parse(buf, (uint16_t)sizeof(buf), &c), APDU_PARSE_OK);
    CHECK_EQ(c.acase, APDU_CASE_4);
    CHECK_EQ(c.lc, 255);
    CHECK_EQ(c.le, 5);
}

/* ----------------------------------------------------- malformed input ---- */

TEST(reject_too_short)
{
    const uint8_t buf[] = { 0x00, 0xA4, 0x00 };
    apdu_command  c;
    for (uint16_t n = 0; n < 4u; n++) {
        CHECK_EQ(apdu_parse(buf, n, &c), APDU_PARSE_TOO_SHORT);
        /* Output must be zeroed so a caller ignoring the status cannot act on
         * a stale field. */
        CHECK_EQ(c.cla, 0);
        CHECK_EQ(c.lc, 0);
        CHECK(c.data == NULL);
    }
}

TEST(reject_null_buffer)
{
    apdu_command c;
    CHECK_EQ(apdu_parse(NULL, 10, &c), APDU_PARSE_TOO_SHORT);
    /* And a NULL output must not crash. */
    CHECK_EQ(apdu_parse(NULL, 10, NULL), APDU_PARSE_TOO_SHORT);
}

TEST(reject_lc_longer_than_data)
{
    /* Lc says 10, only 2 data bytes follow: truncated APDU. */
    const uint8_t buf[] = { 0x00, 0xA4, 0x00, 0x00, 0x0A, 0x3F, 0x00 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_BAD_LENGTH);
    CHECK(c.data == NULL);
}

TEST(reject_lc_shorter_than_data)
{
    /* Lc says 1, but 3 bytes follow: trailing junk, so Case 4 does not fit
     * either (that would need exactly 2 trailing bytes). */
    const uint8_t buf[] = { 0x00, 0xA4, 0x00, 0x00, 0x01, 0x3F, 0x00, 0x11 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_BAD_LENGTH);
}

/* ------------------------------------------------------ extended length --- */

TEST(ext_case2_le)
{
    /* header 00 Le1 Le2 -- seven bytes, no data field. */
    const uint8_t buf[] = { 0x00, 0xB0, 0x00, 0x00, 0x00, 0x01, 0x00 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK(c.extended);
    CHECK_EQ(c.acase, APDU_CASE_2);
    CHECK_EQ(c.lc, 0);
    CHECK(c.data == NULL);
    CHECK(c.le_present);
    CHECK_EQ(c.le, 256); /* 0x0100, not 0x0001 -- big-endian on the wire */
}

TEST(ext_case2_le_zero_means_65536)
{
    /* The extended mirror of "Le==0 means 256". A card that read this as zero
     * would return nothing where the reader asked for everything. */
    const uint8_t buf[] = { 0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK(c.extended);
    CHECK(c.le_present);
    CHECK_EQ(c.le, 65536);
}

TEST(ext_case2_max_le)
{
    const uint8_t buf[] = { 0x00, 0xB0, 0x00, 0x00, 0x00, 0xFF, 0xFF };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK_EQ(c.le, 65535);
}

TEST(ext_case3_data_no_le)
{
    /* header 00 Lc1 Lc2 <data> -- Lc = 3, total 10 bytes. */
    const uint8_t buf[] = { 0x00, 0xD6, 0x00, 0x00, 0x00,
                            0x00, 0x03, 0xAA, 0xBB, 0xCC };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK(c.extended);
    CHECK_EQ(c.acase, APDU_CASE_3);
    CHECK_EQ(c.lc, 3);
    CHECK(!c.le_present);
    CHECK(c.data == &buf[7]);
    CHECK_EQ(c.data[0], 0xAA);
    CHECK_EQ(c.data[2], 0xCC);
}

TEST(ext_case4_data_and_le)
{
    /* header 00 Lc1 Lc2 <data> Le1 Le2 -- Lc = 2, total 11 bytes. */
    const uint8_t buf[] = { 0x00, 0xD6, 0x00, 0x00, 0x00, 0x00,
                            0x02, 0xAA, 0xBB, 0x02, 0x00 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK(c.extended);
    CHECK_EQ(c.acase, APDU_CASE_4);
    CHECK_EQ(c.lc, 2);
    CHECK(c.data == &buf[7]);
    CHECK(c.le_present);
    CHECK_EQ(c.le, 512);
}

TEST(ext_case4_le_zero_means_65536)
{
    const uint8_t buf[] = { 0x00, 0xD6, 0x00, 0x00, 0x00,
                            0x00, 0x01, 0xAA, 0x00, 0x00 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK_EQ(c.acase, APDU_CASE_4);
    CHECK_EQ(c.lc, 1);
    CHECK_EQ(c.le, 65536);
}

TEST(five_bytes_is_short_le_not_extended)
{
    /*
     * THE BOUNDARY THAT MATTERS. "00 A4 00 00 00" is five bytes with a zero
     * fifth byte, and it is a SHORT Case 2 with Le=256 -- not the start of an
     * extended APDU. The extended form needs three bytes for its length field
     * and there is only one here.
     *
     * This is the project's own canonical first APDU, so getting it wrong
     * would break the very command the card is most often asked.
     */
    const uint8_t buf[] = { 0x00, 0xA4, 0x00, 0x00, 0x00 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_OK);
    CHECK(!c.extended);
    CHECK_EQ(c.acase, APDU_CASE_2);
    CHECK_EQ(c.le, 256);
}

TEST(ext_six_bytes_is_malformed)
{
    /* 00 introduces a three-byte length field; only two bytes follow. No legal
     * APDU has this shape. 6700, not "extended unsupported". */
    const uint8_t buf[] = { 0x00, 0xA4, 0x00, 0x00, 0x00, 0x01 };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_BAD_LENGTH);
    CHECK(!c.extended);
    CHECK_HEX(apdu_parse_status_sw(APDU_PARSE_BAD_LENGTH), SW_WRONG_LENGTH);
}

TEST(ext_lc_zero_is_malformed)
{
    /*
     * Lc = 0x0000 with a body present. Zero data bytes means Case 1 or Case 2,
     * so this is not encodable -- and without the explicit check it would be
     * dangerous rather than merely wrong: case4_len with lc==0 is 9, so this
     * nine-byte frame would parse as a Case 4E with an empty data field and a
     * data pointer into the middle of the buffer.
     */
    const uint8_t buf[] = {
        0x00, 0xD6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
    };
    apdu_command c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_BAD_LENGTH);
    CHECK_EQ(c.lc, 0);
    CHECK(c.data == NULL);
}

TEST(ext_lc_above_ceiling_is_reported_as_such)
{
    /*
     * A well-formed extended header announcing more than this card can hold.
     * The status is LC_TOO_LARGE and not BAD_LENGTH: the reader's frame is
     * correct, the card is simply too small. Both answer 6700, but only one
     * of them is fixed by a bigger buffer -- and someone debugging a 6700
     * needs to know which end of the link to look at.
     */
    uint8_t        buf[16] = { 0x00, 0xD6, 0x00, 0x00, 0x00 };
    const uint32_t over    = SCOS_APDU_EXT_DATA_MAX + 1u;
    buf[5]                 = (uint8_t)(over >> 8);
    buf[6]                 = (uint8_t)(over & 0xFFu);
    apdu_command c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_LC_TOO_LARGE);
    CHECK_EQ(c.lc, 0);
    CHECK(c.data == NULL);
    CHECK(!c.extended);
    CHECK_HEX(apdu_parse_status_sw(APDU_PARSE_LC_TOO_LARGE), SW_WRONG_LENGTH);
}

TEST(ext_lc_at_ceiling_is_accepted)
{
    /* The ceiling itself must be usable, not one-off. Built dynamically so
     * this test tracks SCOS_APDU_EXT_DATA_MAX rather than pinning a number
     * that a later change would silently make wrong. */
    static uint8_t buf[7u + SCOS_APDU_EXT_DATA_MAX];
    buf[0] = 0x00;
    buf[1] = 0xD6;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = (uint8_t)(SCOS_APDU_EXT_DATA_MAX >> 8);
    buf[6] = (uint8_t)(SCOS_APDU_EXT_DATA_MAX & 0xFFu);
    for (uint32_t i = 0; i < SCOS_APDU_EXT_DATA_MAX; i++) {
        buf[7u + i] = (uint8_t)(i & 0xFFu);
    }
    apdu_command c;
    CHECK_EQ(apdu_parse(buf, (uint16_t)sizeof(buf), &c), APDU_PARSE_OK);
    CHECK(c.extended);
    CHECK_EQ(c.acase, APDU_CASE_3);
    CHECK_EQ(c.lc, SCOS_APDU_EXT_DATA_MAX);
    CHECK(c.data == &buf[7]);
    CHECK_EQ(c.data[SCOS_APDU_EXT_DATA_MAX - 1u],
             (uint8_t)((SCOS_APDU_EXT_DATA_MAX - 1u) & 0xFFu));
}

TEST(ext_truncated_data_is_bad_length)
{
    /* Lc says 8, four data bytes delivered. */
    const uint8_t buf[] = { 0x00, 0xD6, 0x00, 0x00, 0x00, 0x00,
                            0x08, 0xAA, 0xBB, 0xCC, 0xDD };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_BAD_LENGTH);
}

TEST(ext_trailing_junk_is_bad_length)
{
    /* Lc says 1, and the frame is one byte longer than even Case 4E allows. */
    const uint8_t buf[] = { 0x00, 0xD6, 0x00, 0x00, 0x00, 0x00,
                            0x01, 0xAA, 0x00, 0x10, 0xFF };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_BAD_LENGTH);
}

/*
 * Exhaustive sweep of the extended shapes, the counterpart to the short-form
 * sweep below. For every declared Lc in 0..80 and every frame length in
 * 6..96, the parser must accept EXACTLY the two lengths ISO defines (7+Lc and
 * 9+Lc) and reject everything else -- and it must never report OK while
 * describing a data field that runs past the buffer.
 *
 * This is the check that would have caught a Case 3E/4E mix-up, an off-by-one
 * in the three-byte length field, or an Lc==0 frame slipping through.
 */
TEST(ext_exhaustive_length_consistency)
{
    static uint8_t buf[128];
    for (uint32_t lc = 0; lc <= 80u; lc++) {
        for (uint32_t len = 6u; len <= 96u; len++) {
            os_memset(buf, 0xEE, sizeof(buf));
            buf[0] = 0x00;
            buf[1] = 0xD6;
            buf[2] = 0x00;
            buf[3] = 0x00;
            buf[4] = 0x00; /* extended introducer */
            buf[5] = (uint8_t)(lc >> 8);
            buf[6] = (uint8_t)(lc & 0xFFu);

            apdu_command            c;
            const apdu_parse_status st = apdu_parse(buf, (uint16_t)len, &c);

            /*
             * At exactly seven bytes the two bytes after the introducer are
             * Le, not Lc -- so EVERY value of the pair is a legal Case 2E and
             * the sweep must expect success there whatever `lc` happens to
             * hold. Getting this wrong in the first draft of this test is
             * itself the point: the same confusion in the parser would have
             * made "00 D6 00 00 00 00 03" a three-byte write with no data.
             */
            const bool is_c2 = (len == APDU_EXT_CASE2_LEN);
            const bool is_c3 = !is_c2 && (lc > 0u) && (len == 7u + lc);
            const bool is_c4 = !is_c2 && (lc > 0u) && (len == 9u + lc);

            if (is_c2) {
                CHECK_EQ(st, APDU_PARSE_OK);
                CHECK(c.extended);
                CHECK_EQ(c.acase, APDU_CASE_2);
                CHECK_EQ(c.lc, 0);
                CHECK(c.data == NULL);
                CHECK(c.le_present);
                /* 0x0000 normalises to 65536, never to 0. */
                CHECK_EQ(c.le, (lc == 0u) ? 65536u : lc);
            } else if (is_c3 || is_c4) {
                CHECK_EQ(st, APDU_PARSE_OK);
                CHECK(c.extended);
                CHECK_EQ(c.lc, lc);
                CHECK_EQ(c.acase, is_c3 ? APDU_CASE_3 : APDU_CASE_4);
                CHECK_EQ(c.le_present, is_c4);
                /* The data field must lie wholly inside the frame. */
                CHECK((size_t)(c.data - buf) + c.lc <= len);
            } else {
                CHECK_EQ(st, APDU_PARSE_BAD_LENGTH);
                CHECK_EQ(c.lc, 0);
                CHECK(c.data == NULL);
            }
        }
    }
}

/*
 * Exhaustive sweep. For every (declared Lc, actual buffer length) pair in a
 * meaningful range, the parser must return OK exactly when the length is one
 * of the two legal values, and must never report OK with a data pointer that
 * runs past the buffer. Run under ASan, this is also an out-of-bounds hunt.
 */
TEST(exhaustive_length_consistency)
{
    uint8_t buf[300];
    for (unsigned i = 0; i < sizeof(buf); i++) {
        buf[i] = (uint8_t)i;
    }
    buf[0] = 0x00;
    buf[1] = 0xA4;
    buf[2] = 0x00;
    buf[3] = 0x00;

    int ok_count = 0;
    for (unsigned lc = 1; lc <= 255u; lc++) {
        buf[4] = (uint8_t)lc;
        for (unsigned len = 6u; len <= 261u && len <= sizeof(buf); len++) {
            apdu_command            c;
            const apdu_parse_status st = apdu_parse(buf, (uint16_t)len, &c);

            const bool legal = (len == 5u + lc) || (len == 6u + lc);
            if (legal) {
                CHECK_EQ(st, APDU_PARSE_OK);
                CHECK_EQ(c.lc, lc);
                /* The data field must lie entirely inside the input. */
                CHECK(c.data == &buf[5]);
                CHECK((size_t)(c.data - buf) + c.lc <= len);
                ok_count++;
            } else {
                CHECK_EQ(st, APDU_PARSE_BAD_LENGTH);
            }
        }
    }
    CHECK(ok_count >
          400); /* sanity: the sweep really did exercise the OK path */
}

/* -------------------------------------------------------------- CLA rules -- */

TEST(cla_accepts_only_00_this_milestone)
{
    CHECK_EQ(apdu_check_cla(0x00), APDU_CLA_OK);

    /* Precise diagnostics, not a blanket 6E00. */
    CHECK_EQ(apdu_check_cla(0x01), APDU_CLA_CHANNEL_UNSUPPORTED);
    CHECK_EQ(apdu_check_cla(0x03), APDU_CLA_CHANNEL_UNSUPPORTED);
    CHECK_EQ(apdu_check_cla(0x04), APDU_CLA_SM_UNSUPPORTED);
    CHECK_EQ(apdu_check_cla(0x08), APDU_CLA_SM_UNSUPPORTED);
    CHECK_EQ(apdu_check_cla(0x10), APDU_CLA_CHAINING_UNSUPPORTED);
    CHECK_EQ(apdu_check_cla(0xFF), APDU_CLA_INVALID);
    CHECK_EQ(apdu_check_cla(0x80), APDU_CLA_INVALID); /* proprietary class */
    CHECK_EQ(apdu_check_cla(0xA0), APDU_CLA_INVALID);

    CHECK_HEX(apdu_cla_status_sw(APDU_CLA_CHANNEL_UNSUPPORTED), 0x6881);
    CHECK_HEX(apdu_cla_status_sw(APDU_CLA_SM_UNSUPPORTED), 0x6882);
    CHECK_HEX(apdu_cla_status_sw(APDU_CLA_CHAINING_UNSUPPORTED), 0x6884);
    CHECK_HEX(apdu_cla_status_sw(APDU_CLA_INVALID), 0x6E00);
}

/* Every one of the 256 CLA values must be classified, none may crash. */
TEST(cla_total_coverage)
{
    for (unsigned v = 0; v <= 0xFFu; v++) {
        const apdu_cla_status st = apdu_check_cla((uint8_t)v);
        CHECK(st >= APDU_CLA_OK && st <= APDU_CLA_CHAINING_UNSUPPORTED);
        const uint16_t sw = apdu_cla_status_sw(st);
        CHECK(sw != 0u);
    }
}

int main(void)
{
    RUN(case1_header_only);
    RUN(case2_le_only);
    RUN(case2_le_zero_means_256);
    RUN(case3_data_no_le);
    RUN(case4_data_and_le);
    RUN(case4_le_zero_means_256);
    RUN(case3_max_lc);
    RUN(case4_max_length);
    RUN(reject_too_short);
    RUN(reject_null_buffer);
    RUN(reject_lc_longer_than_data);
    RUN(reject_lc_shorter_than_data);
    RUN(ext_case2_le);
    RUN(ext_case2_le_zero_means_65536);
    RUN(ext_case2_max_le);
    RUN(ext_case3_data_no_le);
    RUN(ext_case4_data_and_le);
    RUN(ext_case4_le_zero_means_65536);
    RUN(five_bytes_is_short_le_not_extended);
    RUN(ext_six_bytes_is_malformed);
    RUN(ext_lc_zero_is_malformed);
    RUN(ext_lc_above_ceiling_is_reported_as_such);
    RUN(ext_lc_at_ceiling_is_accepted);
    RUN(ext_truncated_data_is_bad_length);
    RUN(ext_trailing_junk_is_bad_length);
    RUN(ext_exhaustive_length_consistency);
    RUN(exhaustive_length_consistency);
    RUN(cla_accepts_only_00_this_milestone);
    RUN(cla_total_coverage);
    TEST_MAIN_END();
}
