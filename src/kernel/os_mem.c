/* SPDX-License-Identifier: MIT
 *
 * os_mem.c -- Memory primitives, freestanding.
 *
 * No <string.h>. See include/os/os_mem.h for why.
 */
#include "os/os_mem.h"

void os_memset(void *dst, uint8_t value, size_t len)
{
    if (dst == NULL) {
        return;
    }
    volatile uint8_t *p = (volatile uint8_t *)dst;
    for (size_t i = 0; i < len; i++) {
        p[i] = value;
    }
}

bool os_memcpy_checked(void *dst, size_t dst_cap, const void *src, size_t len)
{
    if (len == 0u) {
        return true;
    }
    if (dst == NULL || src == NULL || len > dst_cap) {
        return false;
    }
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < len; i++) {
        d[i] = s[i];
    }
    return true;
}

/*
 * Constant-time comparison.
 *
 * The naive loop `if (a[i] != b[i]) return false;` leaks the length of the
 * matching prefix through its execution time. Against a PIN that turns a
 * 10^6-guess search into 6 x 10 guesses. So: accumulate all differences with
 * OR, branch once at the end, and never exit early.
 *
 * This defends against a REMOTE timing observer only. An attacker holding the
 * chip has power and EM traces, which this cannot address; that needs hardware
 * countermeasures. See docs/threat-model.md.
 */
bool os_memeq_ct(const void *a, const void *b, size_t len)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    const volatile uint8_t *pa   = (const volatile uint8_t *)a;
    const volatile uint8_t *pb   = (const volatile uint8_t *)b;
    uint8_t                 diff = 0u;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    return diff == 0u;
}

/* volatile writes so the compiler may not discard this as a dead store to a
 * buffer that is about to go out of scope. */
void os_memzero(void *dst, size_t len)
{ os_memset(dst, 0u, len); }
