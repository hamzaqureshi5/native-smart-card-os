/* SPDX-License-Identifier: MIT
 *
 * cflash.c -- code-flash semantics. See cflash.h.
 */
#include "boot/cflash.h"

/* All bounds arithmetic in uint64_t so that off + n cannot wrap. The loader is
 * driven by APDU fields an attacker controls; a wrapped bound here would be a
 * write outside the flash region. */
static bool in_range(uint32_t size, uint32_t off, uint32_t n)
{
    const uint64_t end = (uint64_t)off + (uint64_t)n;
    return end <= (uint64_t)size;
}

cf_status cf_erase_page(uint8_t *base, uint32_t size, uint32_t page_size, uint32_t off)
{
    if (base == NULL || size == 0u || page_size == 0u) {
        return CF_ERR_PARAM;
    }
    if ((off % page_size) != 0u) {
        return CF_ERR_ALIGN;
    }
    if (!in_range(size, off, page_size)) {
        return CF_ERR_RANGE;
    }
    for (uint32_t i = 0; i < page_size; i++) {
        base[off + i] = 0xFFu;
    }
    return CF_OK;
}

cf_status cf_erase_all(uint8_t *base, uint32_t size, uint32_t page_size)
{
    if (base == NULL || size == 0u || page_size == 0u) {
        return CF_ERR_PARAM;
    }
    if ((size % page_size) != 0u) {
        return CF_ERR_RANGE; /* a region that is not a whole number of pages */
    }
    for (uint32_t off = 0; off < size; off += page_size) {
        const cf_status st = cf_erase_page(base, size, page_size, off);
        if (st != CF_OK) {
            return st;
        }
    }
    return CF_OK;
}

cf_status cf_program(uint8_t *base, uint32_t size, uint32_t off,
                     const uint8_t *src, uint32_t n)
{
    if (base == NULL || size == 0u || (src == NULL && n > 0u)) {
        return CF_ERR_PARAM;
    }
    if (!in_range(size, off, n)) {
        return CF_ERR_RANGE;
    }
    /* Check every byte first. A partially applied program is worse than a
     * refused one: the caller would have no way to know how far it got. */
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t old = base[off + i];
        const uint8_t nw  = src[i];
        if ((uint8_t)(old & nw) != nw) {
            return CF_ERR_NOT_ERASED;
        }
    }
    for (uint32_t i = 0; i < n; i++) {
        base[off + i] = src[i];
    }
    return CF_OK;
}

bool cf_is_erased(const uint8_t *base, uint32_t size)
{
    if (base == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        if (base[i] != 0xFFu) {
            return false;
        }
    }
    return true;
}
