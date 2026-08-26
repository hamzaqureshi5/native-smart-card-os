/* SPDX-License-Identifier: MIT
 *
 * test_tlv.c -- BER-TLV parser. Attack surface, so the malformed cases
 * outnumber the well-formed ones.
 */
#include "apdu/tlv.h"

#include "scos_test.h"

/* ----------------------------------------------------------- well-formed -- */

TEST(single_primitive_object)
{
    const uint8_t buf[] = { 0x82, 0x01, 0x38 };
    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, sizeof(buf));

    CHECK_EQ(tlv_next(&r, &o), TLV_OK);
    CHECK_HEX(o.tag, 0x82);
    CHECK_EQ(o.length, 1);
    CHECK_HEX(o.value[0], 0x38);
    CHECK(!o.constructed);
    CHECK(o.value == &buf[2]);      /* aliases the input; no copy */
    CHECK(tlv_reader_done(&r));
    CHECK_EQ(tlv_next(&r, &o), TLV_END);
}

TEST(real_fcp_template)
{
    /* The exact shape our SELECT emits and CREATE FILE will consume. */
    const uint8_t buf[] = {
        0x62, 0x0B,                     /* 3 + 4 + 4 = 11 bytes of content */
        0x82, 0x01, 0x01,
        0x83, 0x02, 0x6F, 0x03,
        0x80, 0x02, 0x00, 0x40
    };
    tlv_reader r;
    tlv_object outer;
    tlv_reader_init(&r, buf, sizeof(buf));

    CHECK_EQ(tlv_next(&r, &outer), TLV_OK);
    CHECK_HEX(outer.tag, 0x62);
    CHECK(outer.constructed);       /* bit 6 of 0x62 is set */
    CHECK_EQ(outer.length, 11);

    /* Descend by making a NEW reader over the value. No recursion anywhere in
     * the parser -- nesting depth is the caller's choice, not the attacker's. */
    tlv_reader inner;
    tlv_object o;
    tlv_reader_init(&inner, outer.value, outer.length);

    CHECK_EQ(tlv_next(&inner, &o), TLV_OK);
    CHECK_HEX(o.tag, 0x82);
    CHECK_HEX(o.value[0], 0x01);

    CHECK_EQ(tlv_next(&inner, &o), TLV_OK);
    CHECK_HEX(o.tag, 0x83);
    CHECK_EQ(o.length, 2);
    CHECK_HEX(((uint16_t)o.value[0] << 8) | o.value[1], 0x6F03);

    CHECK_EQ(tlv_next(&inner, &o), TLV_OK);
    CHECK_HEX(o.tag, 0x80);
    uint32_t size = 0u;
    CHECK_EQ(tlv_get_uint(&o, &size), TLV_OK);
    CHECK_EQ(size, 64);

    CHECK_EQ(tlv_next(&inner, &o), TLV_END);
}

TEST(two_byte_tag)
{
    /* Low five bits of the first byte all set = high tag number form. */
    const uint8_t buf[] = { 0x5F, 0x2D, 0x02, 0x65, 0x6E };
    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, sizeof(buf));
    CHECK_EQ(tlv_next(&r, &o), TLV_OK);
    CHECK_HEX(o.tag, 0x5F2D);
    CHECK_EQ(o.length, 2);
    CHECK_HEX(o.value[0], 0x65);
}

TEST(long_form_lengths)
{
    /* 0x81 = one length byte follows. */
    uint8_t buf[3 + 200];
    buf[0] = 0x80; buf[1] = 0x81; buf[2] = 200;
    for (unsigned i = 0; i < 200u; i++) { buf[3 + i] = (uint8_t)i; }

    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, (uint16_t)sizeof(buf));
    CHECK_EQ(tlv_next(&r, &o), TLV_OK);
    CHECK_EQ(o.length, 200);
    CHECK_HEX(o.value[199], 199);

    /* 0x82 = two length bytes follow. */
    static uint8_t big[4 + 300];
    big[0] = 0x80; big[1] = 0x82; big[2] = 0x01; big[3] = 0x2C;  /* 300 */
    tlv_reader r2;
    tlv_reader_init(&r2, big, (uint16_t)sizeof(big));
    CHECK_EQ(tlv_next(&r2, &o), TLV_OK);
    CHECK_EQ(o.length, 300);
}

TEST(zero_length_object)
{
    const uint8_t buf[] = { 0x80, 0x00, 0x81, 0x01, 0x07 };
    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, sizeof(buf));
    CHECK_EQ(tlv_next(&r, &o), TLV_OK);
    CHECK_HEX(o.tag, 0x80);
    CHECK_EQ(o.length, 0);
    CHECK(o.value == NULL);         /* no value, so no pointer to one */
    /* Parsing must continue correctly past it. */
    CHECK_EQ(tlv_next(&r, &o), TLV_OK);
    CHECK_HEX(o.tag, 0x81);
    CHECK_HEX(o.value[0], 0x07);
}

/* ISO 7816-4 allows 00 and FF as fillers. Erased NVM is all FF, so a template
 * read from a blank region must parse as empty, not as garbage. */
TEST(padding_is_skipped)
{
    const uint8_t buf[] = { 0xFF, 0x00, 0x82, 0x01, 0x38, 0x00, 0xFF, 0xFF };
    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, sizeof(buf));
    CHECK_EQ(tlv_next(&r, &o), TLV_OK);
    CHECK_HEX(o.tag, 0x82);
    CHECK_EQ(tlv_next(&r, &o), TLV_END);

    const uint8_t erased[] = { 0xFF, 0xFF, 0xFF, 0xFF };
    tlv_reader r2;
    tlv_reader_init(&r2, erased, sizeof(erased));
    CHECK(tlv_reader_done(&r2));
    CHECK_EQ(tlv_next(&r2, &o), TLV_END);
}

TEST(find_locates_top_level_only)
{
    const uint8_t buf[] = {
        0x62, 0x05, 0x83, 0x02, 0x6F, 0x03, 0x00,
        0x8A, 0x01, 0x05
    };
    tlv_object o;
    CHECK_EQ(tlv_find(buf, sizeof(buf), 0x8A, &o), TLV_OK);
    CHECK_HEX(o.value[0], 0x05);
    CHECK_EQ(tlv_find(buf, sizeof(buf), 0x62, &o), TLV_OK);
    /* 0x83 is INSIDE the 62 template, so a top-level search must not find it.
     * Descending is the caller's decision, because that is where unbounded
     * nesting would come from. */
    CHECK_EQ(tlv_find(buf, sizeof(buf), 0x83, &o), TLV_END);
}

/* ------------------------------------------------------------ malformed --- */

TEST(reject_truncated_value)
{
    /* Length says 5, only 2 bytes follow. */
    const uint8_t buf[] = { 0x80, 0x05, 0xAA, 0xBB };
    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, sizeof(buf));
    CHECK_EQ(tlv_next(&r, &o), TLV_ERR_TRUNCATED);
    CHECK(o.value == NULL);
    /* And the reader must be exhausted, so a caller looping cannot spin. */
    CHECK(tlv_reader_done(&r));
}

TEST(reject_missing_length)
{
    const uint8_t buf[] = { 0x80 };
    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, sizeof(buf));
    CHECK_EQ(tlv_next(&r, &o), TLV_ERR_TRUNCATED);
}

TEST(reject_truncated_two_byte_tag)
{
    const uint8_t buf[] = { 0x5F };
    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, sizeof(buf));
    CHECK_EQ(tlv_next(&r, &o), TLV_ERR_TRUNCATED);
}

TEST(reject_three_byte_tag)
{
    /* 0x5F then 0x81 (bit 8 set = another byte follows). BER permits an
     * unbounded chain; we do not, because that is an attacker-controlled
     * unbounded read. */
    const uint8_t buf[] = { 0x5F, 0x81, 0x2D, 0x01, 0xAA };
    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, sizeof(buf));
    CHECK_EQ(tlv_next(&r, &o), TLV_ERR_TAG);
}

TEST(reject_indefinite_length)
{
    /* 0x80 as the length byte means "content ends at an end-of-contents marker
     * somewhere later". It cannot be bounds-checked up front. */
    const uint8_t buf[] = { 0x30, 0x80, 0x82, 0x01, 0x38, 0x00, 0x00 };
    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, sizeof(buf));
    CHECK_EQ(tlv_next(&r, &o), TLV_ERR_LENGTH);
}

TEST(reject_oversized_length_field)
{
    /* 0x83 = three length bytes. Refused: it could describe more data than the
     * card could ever hold. */
    const uint8_t buf[] = { 0x80, 0x83, 0x01, 0x00, 0x00 };
    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, sizeof(buf));
    CHECK_EQ(tlv_next(&r, &o), TLV_ERR_LENGTH);

    const uint8_t reserved[] = { 0x80, 0xFF, 0x01 };
    tlv_reader r2;
    tlv_reader_init(&r2, reserved, sizeof(reserved));
    CHECK_EQ(tlv_next(&r2, &o), TLV_ERR_LENGTH);
}

/* The overflow case: a 2-byte length near 0xFFFF must not wrap past the end of
 * the buffer when added to the position. */
TEST(reject_length_that_would_overflow)
{
    const uint8_t buf[] = { 0x80, 0x82, 0xFF, 0xFF, 0xAA };
    tlv_reader r;
    tlv_object o;
    tlv_reader_init(&r, buf, sizeof(buf));
    CHECK_EQ(tlv_next(&r, &o), TLV_ERR_TRUNCATED);

    const uint8_t l2[] = { 0x80, 0x82, 0xFF, 0xFE };
    tlv_reader r2;
    tlv_reader_init(&r2, l2, sizeof(l2));
    CHECK_EQ(tlv_next(&r2, &o), TLV_ERR_TRUNCATED);
}

TEST(null_and_empty_inputs)
{
    tlv_reader r;
    tlv_object o;

    tlv_reader_init(&r, NULL, 10u);
    CHECK_EQ(tlv_next(&r, &o), TLV_ERR_PARAM);
    CHECK(tlv_reader_done(&r));

    const uint8_t buf[] = { 0x80, 0x00 };
    tlv_reader_init(&r, buf, 0u);
    CHECK_EQ(tlv_next(&r, &o), TLV_END);

    tlv_reader_init(&r, buf, sizeof(buf));
    CHECK_EQ(tlv_next(&r, NULL), TLV_ERR_PARAM);
    CHECK_EQ(tlv_next(NULL, &o), TLV_ERR_PARAM);
    CHECK_EQ(tlv_find(NULL, 4u, 0x80, &o), TLV_ERR_PARAM);
}

TEST(get_uint_bounds)
{
    tlv_object o = { .tag = 0x80, .value = NULL, .length = 0, .constructed = false };
    uint32_t v = 0u;
    CHECK_EQ(tlv_get_uint(&o, &v), TLV_ERR_LENGTH);  /* empty is not a number */

    const uint8_t four[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    o.value = four; o.length = 4u;
    CHECK_EQ(tlv_get_uint(&o, &v), TLV_OK);
    CHECK_EQ(v, 0xDEADBEEFu);

    const uint8_t five[] = { 1, 2, 3, 4, 5 };
    o.value = five; o.length = 5u;
    CHECK_EQ(tlv_get_uint(&o, &v), TLV_ERR_LENGTH);  /* would not fit */
    CHECK_EQ(v, 0);
    CHECK_EQ(tlv_get_uint(NULL, &v), TLV_ERR_PARAM);
}

/* ------------------------------------------------------------- writing ---- */

TEST(put_roundtrip_and_overflow)
{
    uint8_t buf[16];
    uint16_t pos = 0u;
    const uint8_t val[] = { 0x6F, 0x03 };

    CHECK(tlv_put(buf, sizeof(buf), &pos, 0x83, val, 2u));
    CHECK_EQ(pos, 4);
    CHECK_HEX(buf[0], 0x83);
    CHECK_HEX(buf[1], 0x02);

    CHECK(tlv_put(buf, sizeof(buf), &pos, 0x5F2D, val, 2u));
    CHECK_EQ(pos, 9);            /* 2 tag + 1 len + 2 value */
    CHECK_HEX(buf[4], 0x5F);
    CHECK_HEX(buf[5], 0x2D);

    /* Read back what we wrote. */
    tlv_object o;
    CHECK_EQ(tlv_find(buf, pos, 0x5F2D, &o), TLV_OK);
    CHECK_EQ(o.length, 2);

    /* Overflow must write NOTHING, not a partial object. */
    const uint16_t before = pos;
    uint8_t big[64] = { 0 };
    CHECK(!tlv_put(buf, sizeof(buf), &pos, 0x80, big, 60u));
    CHECK_EQ(pos, before);
    CHECK(!tlv_put(buf, sizeof(buf), &pos, 0x80, big, 200u)); /* > 127 */
    CHECK_EQ(pos, before);
    CHECK(!tlv_put(NULL, 8u, &pos, 0x80, big, 1u));
    CHECK(!tlv_put(buf, sizeof(buf), &pos, 0x80, NULL, 4u));
}

/*
 * Exhaustive sweep over every 3-byte input. Every one must return a defined
 * status, and any that reports TLV_OK must describe a value lying entirely
 * inside the buffer. Run under ASan, this is an out-of-bounds hunt over the
 * whole small-input space -- 16.7 million cases.
 */
TEST(exhaustive_three_byte_inputs)
{
    unsigned ok = 0u, err = 0u;
    for (unsigned a = 0; a <= 0xFFu; a++) {
        for (unsigned b = 0; b <= 0xFFu; b++) {
            for (unsigned c = 0; c <= 0xFFu; c++) {
                const uint8_t buf[3] = { (uint8_t)a, (uint8_t)b, (uint8_t)c };
                tlv_reader r;
                tlv_object o;
                tlv_reader_init(&r, buf, 3u);
                const tlv_status st = tlv_next(&r, &o);

                if (st == TLV_OK) {
                    /* The value must lie inside buf[0..3). */
                    if (o.length > 0u) {
                        CHECK(o.value >= buf);
                        CHECK((size_t)(o.value - buf) + o.length <= 3u);
                    }
                    ok++;
                } else {
                    CHECK(st == TLV_END || st == TLV_ERR_TRUNCATED ||
                          st == TLV_ERR_TAG || st == TLV_ERR_LENGTH);
                    err++;
                }
            }
        }
    }
    /* Both paths must have been exercised, or the sweep proved nothing. */
    CHECK(ok > 1000u);
    CHECK(err > 1000u);
}

int main(void)
{
    RUN(single_primitive_object);
    RUN(real_fcp_template);
    RUN(two_byte_tag);
    RUN(long_form_lengths);
    RUN(zero_length_object);
    RUN(padding_is_skipped);
    RUN(find_locates_top_level_only);
    RUN(reject_truncated_value);
    RUN(reject_missing_length);
    RUN(reject_truncated_two_byte_tag);
    RUN(reject_three_byte_tag);
    RUN(reject_indefinite_length);
    RUN(reject_oversized_length_field);
    RUN(reject_length_that_would_overflow);
    RUN(null_and_empty_inputs);
    RUN(get_uint_bounds);
    RUN(put_roundtrip_and_overflow);
    RUN(exhaustive_three_byte_inputs);
    TEST_MAIN_END();
}
