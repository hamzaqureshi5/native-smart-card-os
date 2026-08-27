/* SPDX-License-Identifier: MIT
 *
 * cflash.h -- code-flash semantics.
 *
 * On the emulator the OS flash region is ordinary writable memory, so a naive
 * loader would appear to work while doing something no real chip can do. This
 * module imposes the two rules that actual NOR/embedded flash lives by:
 *
 *   1. Erase works on whole pages and sets them to 0xFF.
 *   2. Programming can only clear bits. Writing 0xF0 over 0x0F does NOT give
 *      you 0xF0; it gives you 0x00. So programming a location that is not
 *      erased is an error, not a silent wrong answer.
 *
 * Enforcing this in the simulator is the point. A loader bug that "works" in
 * QEMU and then bricks a real part at the factory is precisely the class of
 * bug this project exists to catch early. cf_program() refuses the write and
 * returns CF_ERR_NOT_ERASED instead of corrupting the image.
 *
 * Timing, endurance limits and program-suspend are NOT modelled; those are
 * datasheet facts of a real part and we have none. See docs/chip-scv1.md.
 */
#ifndef CFLASH_H
#define CFLASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    CF_OK = 0,
    CF_ERR_PARAM,     /* null pointer or zero-size region                */
    CF_ERR_RANGE,     /* offset+length outside the region                */
    CF_ERR_ALIGN,     /* erase offset is not on a page boundary          */
    CF_ERR_NOT_ERASED /* the write would need to set a bit from 0 to 1   */
} cf_status;

/* Erase one page. off must be page-aligned; page_size must be non-zero. */
cf_status cf_erase_page(uint8_t *base, uint32_t size, uint32_t page_size,
                        uint32_t off);

/* Erase the whole region, page by page. */
cf_status cf_erase_all(uint8_t *base, uint32_t size, uint32_t page_size);

/* Program n bytes at off. Fails without writing anything if any byte would
 * require a 0->1 transition -- checked in full before the first store, so a
 * refused program leaves the flash exactly as it was. */
cf_status cf_program(uint8_t *base, uint32_t size, uint32_t off,
                     const uint8_t *src, uint32_t n);

/* True if every byte in the region is 0xFF. */
bool cf_is_erased(const uint8_t *base, uint32_t size);

#endif /* CFLASH_H */
