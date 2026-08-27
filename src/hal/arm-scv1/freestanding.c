/* SPDX-License-Identifier: MIT
 *
 * freestanding.c -- the four libc functions a bare-metal link cannot do
 * without, provided by us because nothing else will.
 *
 * WHY THIS FILE EXISTS
 *
 * The card links with no C library. Two separate things then need memcpy and
 * memset by their standard names:
 *
 *   1. GCC itself. Struct assignment, array initialisation and some loop
 *      idioms are compiled into calls to memcpy/memset with no such call in
 *      the source. -ffreestanding does not stop this; the standard explicitly
 *      permits it. tests/integration/check_core_deps.cmake allows those two
 *      symbols for exactly this reason and says so.
 *   2. Vendored third-party code. mbedTLS calls them outright, and patching
 *      it to use our os_mem* names would turn the submodule into a fork whose
 *      next update is a merge -- which is the thing vendoring is supposed to
 *      avoid.
 *
 * WHY NOT IN src/kernel/os_mem.c
 *
 * Because that is part of libscos_core, which is also linked into the HOST
 * build, and defining memcpy there would collide with glibc's. These
 * definitions must exist only where there is no libc, so they live in the
 * cross-compiled HAL.
 *
 * WHY THE OS STILL HAS ITS OWN os_mem* PRIMITIVES
 *
 * These are the plain, fast, standard-behaviour versions. os_mem.c keeps its
 * own for anything security-relevant, and the reason is memcmp: the standard
 * one is permitted to return as soon as it finds a difference, so its timing
 * leaks how many leading bytes matched. Nothing that compares a secret may use
 * it -- see crypto_equal_ct() in src/crypto/crypto_mbedtls.c. The memcmp below
 * is for ordinary data only.
 *
 * These are deliberately simple. A byte-at-a-time copy is slower than a
 * word-aligned one, and on a card that runs a hash a handful of times per
 * session the difference does not register, while the correctness of an
 * unaligned-access-safe loop is obvious by inspection. ARMv7-M tolerates
 * unaligned access; ARMv6-M does not, and docs/hardware-port.md records that
 * a real part is likely to be ARMv6-M -- so byte-at-a-time is also the
 * portable choice.
 */
#include <stddef.h>
#include <stdint.h>

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
void *memmove(void *dst, const void *src, size_t n);
int   memcmp(const void *a, const void *b, size_t n);

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    for (size_t i = 0; i < n; i++) {
        d[i] = (uint8_t)c;
    }
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (d == s || n == 0u) {
        return dst;
    }
    /* Overlapping regions: copy in whichever direction does not overwrite
     * source bytes before they are read. memcpy is undefined here, and the
     * distinction is the entire reason memmove exists. */
    if (d < s) {
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else {
        for (size_t i = n; i > 0u; i--) {
            d[i - 1u] = s[i - 1u];
        }
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    for (size_t i = 0; i < n; i++) {
        if (x[i] != y[i]) {
            /* NOT constant time, and that is correct for this function. Use
             * crypto_equal_ct() for anything secret. */
            return (int)x[i] - (int)y[i];
        }
    }
    return 0;
}
