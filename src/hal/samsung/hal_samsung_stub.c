/* SPDX-License-Identifier: MIT
 *
 * hal_samsung_stub.c -- PLACEHOLDER. NOT A PORT.
 *
 * ==========================================================================
 * NOTHING IN THIS FILE IS DERIVED FROM ANY SAMSUNG DOCUMENTATION.
 *
 * No register addresses, no memory map, no boot sequence, no crypto
 * peripheral, no debug interface. The author of this file has never seen a
 * datasheet for the target part. Every function below fails at run time and
 * the whole file fails at compile time unless you explicitly acknowledge
 * that, because a HAL that quietly returns plausible values is far more
 * dangerous than one that refuses to build: it would let the OS appear to
 * work while writing nothing to real NVM.
 * ==========================================================================
 *
 * WHAT THIS FILE IS FOR
 *
 * It proves the seam is real. include/hal/hal.h is a complete contract, and
 * this file is a second, independent implementation of it. If the OS core has
 * accidentally grown a dependency on the simulator, linking this
 * implementation is what exposes it -- the core links cleanly against a HAL
 * that does nothing.
 *
 * HOW TO TURN IT INTO A PORT (when documentation exists)
 *
 *   1. Supply the datasheet / reference manual / SDK.
 *   2. Establish, from that documentation only:
 *        - CPU architecture, endianness, and toolchain
 *        - memory map: ROM/flash/EEPROM/RAM base addresses and sizes
 *        - NVM programming: page size, erase granularity, write timing,
 *          how to detect completion, and what a power loss mid-program leaves
 *          behind (this last point decides the transaction design)
 *        - TRNG: how to start it, how to read it, and how its health test
 *          reports failure
 *        - crypto accelerator: AES/ECC interfaces, and whether key material
 *          can be kept in hardware key slots rather than in RAM
 *        - the ISO 7816-3 / 14443 interface block and its ATR configuration
 *        - security sensors and how tamper events are delivered
 *   3. Implement each hal_* function against those documented registers.
 *   4. Run the same tests. That is the payoff: the test suite written against
 *      the simulator is a conformance suite for the port.
 *
 * See docs/hardware-port.md for the full checklist.
 */

/* Refuse to build unless the developer has stated intent. This is the guard
 * rail: `-DSCOS_HAL=samsung` alone will not produce a binary that pretends to
 * work on hardware. */
#if !defined(SCOS_SAMSUNG_STUB_ACKNOWLEDGED)
#error "src/hal/samsung is an unimplemented placeholder, not a port. \
Configure with -DSCOS_ACK_SAMSUNG_STUB=ON to build it anyway (it will fail \
at run time), or use -DSCOS_HAL=simulator."
#endif

#include "hal/hal.h"

/* Every entry point returns HAL_ERR_UNSUPPORTED. Deliberately not
 * HAL_ERR_IO: the distinction between "this platform does not provide it" and
 * "the hardware failed" matters when diagnosing a real board. */

hal_status hal_init(void)
{ return HAL_ERR_UNSUPPORTED; }
void hal_reset(void)
{
}
void hal_shutdown(void)
{
}

uint32_t hal_nvm_size(hal_nvm_region region)
{
    (void)region;
    return 0u;
}
uint32_t hal_nvm_page_size(hal_nvm_region region)
{
    (void)region;
    return 0u;
}

hal_status hal_nvm_read(hal_nvm_region region, uint32_t offset, void *dst,
                        uint32_t len)
{
    (void)region;
    (void)offset;
    (void)dst;
    (void)len;
    return HAL_ERR_UNSUPPORTED;
}

hal_status hal_nvm_write(hal_nvm_region region, uint32_t offset,
                         const void *src, uint32_t len)
{
    (void)region;
    (void)offset;
    (void)src;
    (void)len;
    return HAL_ERR_UNSUPPORTED;
}

hal_status hal_nvm_sync(void)
{ return HAL_ERR_UNSUPPORTED; }

hal_status hal_random_bytes(void *dst, size_t len)
{
    (void)dst;
    (void)len;
    /* Note what this does NOT do: it does not fall back to a software PRNG.
     * A HAL that silently substitutes weak entropy for a missing TRNG is how
     * real products ship predictable keys. */
    return HAL_ERR_UNSUPPORTED;
}

uint32_t hal_timer_get_ms(void)
{ return 0u; }

hal_status hal_card_receive(uint8_t *buf, uint32_t cap, uint32_t *out_len)
{
    (void)buf;
    (void)cap;
    if (out_len != NULL) {
        *out_len = 0u;
    }
    return HAL_ERR_UNSUPPORTED;
}

hal_status hal_card_send(const uint8_t *buf, uint32_t len)
{
    (void)buf;
    (void)len;
    return HAL_ERR_UNSUPPORTED;
}

const uint8_t *hal_card_atr(uint32_t *out_len)
{
    /* An ATR is chip- and configuration-specific. Inventing one here would be
     * a lie about hardware we have not seen. */
    if (out_len != NULL) {
        *out_len = 0u;
    }
    return NULL;
}
