/* SPDX-License-Identifier: MIT
 *
 * os_mem.h -- Minimal memory primitives for the OS core.
 *
 * The core must not include <string.h>: on a bare secure MCU there is no libc,
 * and the standard functions are also a poor fit for a card OS (memcmp is not
 * constant time, and nothing bounds-checks). These replacements are explicit
 * about size and return failure instead of trusting the caller.
 */
#ifndef SCOS_OS_MEM_H
#define SCOS_OS_MEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void os_memset(void *dst, uint8_t value, size_t len);

/* Bounds-checked copy. Returns false and writes nothing if len > dst_cap. */
bool os_memcpy_checked(void *dst, size_t dst_cap, const void *src, size_t len);

/* Constant-time equality. Runtime does not depend on WHERE the buffers differ,
 * only on len. Use this for PINs, MACs and key material -- never os_memcmp
 * style early-exit comparison. See docs/threat-model.md (timing side channel). */
bool os_memeq_ct(const void *a, const void *b, size_t len);

/* Overwrite a buffer that held secrets. Marked so the compiler may not elide
 * it as a dead store. */
void os_memzero(void *dst, size_t len);

#endif /* SCOS_OS_MEM_H */
