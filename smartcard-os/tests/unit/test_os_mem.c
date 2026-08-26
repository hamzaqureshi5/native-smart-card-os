/* SPDX-License-Identifier: MIT
 *
 * test_os_mem.c -- The memory primitives everything else is built on.
 */
#include "os/os_mem.h"

#include "scos_test.h"

TEST(memset_and_zero)
{
    uint8_t buf[16];
    os_memset(buf, 0xA5, sizeof(buf));
    for (unsigned i = 0; i < sizeof(buf); i++) { CHECK_HEX(buf[i], 0xA5); }

    os_memzero(buf, sizeof(buf));
    for (unsigned i = 0; i < sizeof(buf); i++) { CHECK_HEX(buf[i], 0x00); }

    os_memset(NULL, 0, 16);   /* must not crash */
    os_memset(buf, 0xFF, 0);  /* zero length is a no-op */
    CHECK_HEX(buf[0], 0x00);
}

TEST(memcpy_checked_respects_capacity)
{
    const uint8_t src[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t dst[8];

    os_memset(dst, 0, sizeof(dst));
    CHECK(os_memcpy_checked(dst, sizeof(dst), src, sizeof(src)));
    CHECK(os_memeq_ct(dst, src, sizeof(src)));

    /* One byte too many must be refused, and must write NOTHING -- a partial
     * copy would leave a half-updated structure behind. */
    os_memset(dst, 0xEE, sizeof(dst));
    CHECK(!os_memcpy_checked(dst, 4u, src, 5u));
    for (unsigned i = 0; i < sizeof(dst); i++) { CHECK_HEX(dst[i], 0xEE); }

    CHECK(!os_memcpy_checked(NULL, 8u, src, 1u));
    CHECK(!os_memcpy_checked(dst, 8u, NULL, 1u));
    CHECK(os_memcpy_checked(dst, 0u, src, 0u));      /* empty copy is fine */
    CHECK(os_memcpy_checked(NULL, 0u, NULL, 0u));
}

TEST(constant_time_equality_is_correct)
{
    /* Correctness first; the timing property itself is not observable from a
     * unit test. What IS testable is that it never exits early -- verified by
     * inspection of os_mem.c and by the absence of a branch on the data. */
    const uint8_t a[4] = { 1, 2, 3, 4 };
    const uint8_t b[4] = { 1, 2, 3, 4 };
    const uint8_t c[4] = { 1, 2, 3, 5 };   /* differs in the LAST byte */
    const uint8_t d[4] = { 9, 2, 3, 4 };   /* differs in the FIRST byte */

    CHECK(os_memeq_ct(a, b, 4u));
    CHECK(!os_memeq_ct(a, c, 4u));
    CHECK(!os_memeq_ct(a, d, 4u));
    CHECK(os_memeq_ct(a, d, 0u));          /* empty comparison is equal */
    CHECK(os_memeq_ct(a, a, 4u));
    CHECK(!os_memeq_ct(NULL, a, 4u));
    CHECK(!os_memeq_ct(a, NULL, 4u));

    /* Every single-bit difference at every position must be detected -- an
     * accumulator built with + instead of |= could cancel out. */
    for (unsigned pos = 0; pos < 4u; pos++) {
        for (unsigned bit = 0; bit < 8u; bit++) {
            uint8_t x[4] = { 1, 2, 3, 4 };
            x[pos] ^= (uint8_t)(1u << bit);
            CHECK(!os_memeq_ct(a, x, 4u));
        }
    }
}

int main(void)
{
    RUN(memset_and_zero);
    RUN(memcpy_checked_respects_capacity);
    RUN(constant_time_equality_is_correct);
    TEST_MAIN_END();
}
