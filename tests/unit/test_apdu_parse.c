/* SPDX-License-Identifier: MIT
 *
 * test_apdu_parse.c -- The parser is the attack surface, so it gets the most
 * tests. Each group documents the ISO rule it pins down.
 */
#include "apdu/apdu.h"
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

TEST(reject_extended_length)
{
    /* Lc byte of 0x00 with more bytes following is the extended encoding. It
     * must be identified as such, not misread as a short APDU. */
    const uint8_t buf[] = { 0x00, 0xA4, 0x00, 0x00, 0x00, 0x01, 0x02, 0x3F };
    apdu_command  c;
    CHECK_EQ(apdu_parse(buf, sizeof(buf), &c), APDU_PARSE_EXTENDED);
    CHECK_EQ(c.lc, 0);
    CHECK(c.data == NULL);
    /* 6A81 "function not supported" -- the length is legal, we just do not
     * implement it. Not 6700, which would claim the APDU was malformed. */
    CHECK_HEX(apdu_parse_status_sw(APDU_PARSE_EXTENDED), SW_FUNC_NOT_SUPPORTED);
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
    RUN(reject_extended_length);
    RUN(exhaustive_length_consistency);
    RUN(cla_accepts_only_00_this_milestone);
    RUN(cla_total_coverage);
    TEST_MAIN_END();
}
