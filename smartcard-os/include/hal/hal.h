/* SPDX-License-Identifier: MIT
 *
 * hal.h -- Generic Hardware Abstraction Layer for the smart-card OS.
 *
 * THIS IS THE ONLY WAY THE OS CORE MAY TOUCH HARDWARE.
 *
 * Rules for this header:
 *   1. It may include <stdint.h>, <stddef.h>, <stdbool.h> and nothing else.
 *      No <stdio.h>, no <stdlib.h>, no <string.h>, no OS headers.
 *   2. Every function here must be implementable on a bare secure MCU with no
 *      operating system, no heap and no filesystem.
 *   3. No function here may allocate memory. The caller always owns the buffer.
 *   4. Exactly one implementation is linked into a given build, chosen by the
 *      CMake option SCOS_HAL (simulator | samsung).
 *
 * Implementations:
 *   src/hal/simulator/  -- virtual chip on a PC (this milestone)
 *   src/hal/samsung/    -- stubbed; awaiting real chip documentation
 */
#ifndef SCOS_HAL_H
#define SCOS_HAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ status */

typedef enum {
    HAL_OK              =  0,
    /* Not an error: the reader asserted RST. hal_card_receive() returns this
     * INSTEAD of a command, and the OS must clear its volatile state. Reported
     * as a return value rather than delivered by a callback into the OS,
     * because the HAL must never depend on the layer above it. */
    HAL_CARD_RESET      =  1,
    HAL_ERR_PARAM       = -1, /* caller passed a bad argument                */
    HAL_ERR_RANGE       = -2, /* offset/length outside the addressed region   */
    HAL_ERR_IO          = -3, /* link or memory device failure                */
    HAL_ERR_UNSUPPORTED = -4, /* not provided by this platform                */
    HAL_ERR_POWER       = -5, /* device is not powered / power was lost       */
    HAL_ERR_LINK_DOWN   = -6  /* reader went away; card should stop           */
} hal_status;

/* ---------------------------------------------------------------- lifecycle */

/* Cold start. Brings up virtual/real peripherals and makes NVM readable.
 * Must be called exactly once before any other hal_* call. */
hal_status hal_init(void);

/* Warm reset (ISO 7816-3 reset): peripherals are re-initialised and volatile
 * state is cleared, but non-volatile memory is preserved. Does NOT re-run
 * hal_init(). */
void hal_reset(void);

/* Orderly power-down. After this, NVM contents are guaranteed durable.
 * On real silicon this is a no-op or a low-power entry; in the simulator it
 * flushes the backing store. */
void hal_shutdown(void);

/* ------------------------------------------------------------ non-volatile */

typedef enum {
    HAL_NVM_EEPROM = 0, /* small, byte-writable, high endurance: OS metadata */
    HAL_NVM_FLASH  = 1  /* large, page-erase, lower endurance: file data     */
} hal_nvm_region;

/* Usable size in bytes of a region, or 0 if the region does not exist. */
uint32_t hal_nvm_size(hal_nvm_region region);

/* Smallest unit the device can write atomically-ish. The OS uses this to plan
 * transaction journalling; it must never assume a value. */
uint32_t hal_nvm_page_size(hal_nvm_region region);

hal_status hal_nvm_read(hal_nvm_region region, uint32_t offset,
                        void *dst, uint32_t len);

/* Write may be buffered by the device. It is NOT durable until
 * hal_nvm_sync() returns HAL_OK. */
hal_status hal_nvm_write(hal_nvm_region region, uint32_t offset,
                         const void *src, uint32_t len);

/* Write barrier: block until every preceding hal_nvm_write() is durable.
 * The transaction manager depends on this; see docs/transactions.md. */
hal_status hal_nvm_sync(void);

/* ------------------------------------------------------------------ entropy */

/* Fill dst with len cryptographically usable random bytes.
 * Returns HAL_ERR_IO if the generator failed its health test -- callers must
 * check, never ignore. */
hal_status hal_random_bytes(void *dst, size_t len);

/* -------------------------------------------------------------------- time */

/* Free-running millisecond counter. Wraps. Monotonic between resets only;
 * a smart card has no calendar clock and no trusted time source. */
uint32_t hal_timer_get_ms(void);

/* ----------------------------------------------------------------- card I/O */

/* The card is PASSIVE. It waits for the reader.
 *
 * hal_card_receive() blocks until a complete command APDU has been received,
 * returns HAL_CARD_RESET if the reader reset the card instead, or
 * HAL_ERR_LINK_DOWN when the reader disconnects / power drops.
 * The transport layer (T=0/T=1 on real hardware, a byte pipe in the
 * simulator) is entirely below this call: the OS never sees link framing. */
hal_status hal_card_receive(uint8_t *buf, uint32_t cap, uint32_t *out_len);

hal_status hal_card_send(const uint8_t *buf, uint32_t len);

/* Answer To Reset. Returned by the hardware/link layer, not by the OS, because
 * on real silicon the ATR is clocked out before any OS code runs.
 * See docs/simulator.md for a byte-by-byte description of the simulator ATR. */
const uint8_t *hal_card_atr(uint32_t *out_len);

#endif /* SCOS_HAL_H */
