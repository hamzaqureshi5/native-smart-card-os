/* SPDX-License-Identifier: MIT
 *
 * hal_s3m228a.c -- the Samsung S3M228A port. NOT IMPLEMENTED.
 *
 * ==========================================================================
 * NOTHING IN THIS FILE IS DERIVED FROM ANY SAMSUNG DOCUMENTATION.
 *
 * No register addresses, no memory map, no boot sequence, no crypto
 * peripheral, no debug interface. The author has never seen a datasheet or
 * reference manual for this part. Every function below fails at run time and
 * the whole file fails at compile time unless you explicitly acknowledge
 * that, because a HAL that quietly returns plausible values is far more
 * dangerous than one that refuses to build: it would let the OS appear to
 * work while writing nothing to real NVM.
 * ==========================================================================
 *
 * WHAT IS PUBLICLY KNOWN ABOUT THE TARGET
 *
 * From Samsung's public product page only -- a marketing page, not a
 * datasheet:
 *
 *   Core          ARM SecurCore SC000, 14 MHz
 *   Architecture  ARMv6-M (Cortex-M0 class)
 *   Flash         228 KB (one figure; no published code/data split)
 *   RAM           5 KB
 *   Interface     ISO 7816
 *
 * https://semiconductor.samsung.com/security-solution/ese-esim-sim/part-number/s3m228a/
 *
 * That is enough to know the toolchain (arm-none-eabi, -mcpu=cortex-m0) and
 * that the OS must fit in 5 KB of RAM shared with the stack. It is NOT enough
 * to write a single line of the port. See docs/hardware-port.md.
 *
 * WHAT THIS FILE IS FOR TODAY
 *
 * It proves the seam is real. include/hal/hal.h is a complete contract, and
 * this file is a second, independent implementation of it. If the OS core has
 * accidentally grown a dependency on the simulator, linking this
 * implementation is what exposes it -- the core links cleanly against a HAL
 * that does nothing. CI builds this configuration for exactly that reason.
 *
 * WHAT IS STILL MISSING, AND WHY EACH ITEM BLOCKS THE PORT
 *
 *   - Memory map: flash/EEPROM/RAM base addresses and the code/data split
 *     inside those 228 KB. Without it there is no linker script.
 *   - NVM programming: page size, erase granularity, write timing, how to
 *     detect completion, and what a power loss mid-program leaves behind.
 *     That last point decides the whole transaction design (M4).
 *   - Vector table handling: ARMv6-M has no VTOR, so how a boot ROM hands
 *     control to a separately-loaded OS is an open question on this part.
 *     Requires the ARM SecurCore SC000 TRM. See docs/hardware-port.md.
 *   - TRNG: how to start it, how to read it, how its health test reports
 *     failure.
 *   - Crypto accelerator: AES/ECC interfaces, and whether keys can live in
 *     hardware slots rather than RAM.
 *   - ISO 7816-3 interface block and its ATR configuration.
 *   - Security sensors and how tamper events are delivered.
 *
 * Supply the documentation and each hal_* function below gets implemented
 * against documented registers. Then run the same test suite: that is the
 * payoff -- the tests written against the simulator are a conformance suite
 * for this port.
 */

/* Refuse to build unless the developer has stated intent. This is the guard
 * rail: `-DSCOS_HAL=s3m228a` alone will not produce a binary that pretends to
 * work on hardware. */
#if !defined(SCOS_S3M228A_STUB_ACKNOWLEDGED)
#error "src/hal/s3m228a is an unimplemented placeholder, not a port. \
Configure with -DSCOS_ACK_S3M228A_STUB=ON to build it anyway (it will fail \
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
