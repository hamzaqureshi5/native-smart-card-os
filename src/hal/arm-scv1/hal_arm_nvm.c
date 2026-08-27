/* SPDX-License-Identifier: MIT
 *
 * hal_arm_nvm.c -- SCV1 non-volatile memory.
 *
 * The regions live at real, fixed addresses in the chip's memory map (see
 * scv1.h), so an NVM access here is a genuine memory access at a genuine
 * address -- not an array lookup as it is in the native simulator. Alignment
 * and endianness behave the way they will on hardware, which is the main reason
 * this target is worth having.
 *
 * WHAT IS STILL NOT REAL, AND MATTERS
 * On this development target the regions are backed by ordinary SRAM, so a
 * write takes effect immediately and always completely. A real SCV1 would
 * program flash through a flash controller: a write would take milliseconds,
 * would have to be issued a page at a time, and could be interrupted by power
 * loss half way through a page. That difference is exactly what the transaction
 * manager (M4) has to survive, so this file carries the same warning as the
 * simulator: nothing here yet justifies a tear-resistance claim.
 */
#include <stdbool.h>

#include "hal/hal.h"
#include "os/os_mem.h"
#include "scv1.h"
#include "scv1_internal.h"
#include "semihost.h"

/* Region bases as symbols from the linker script, so an address can never
 * drift out of step with scv1.ld. */
extern uint8_t _eeprom_base[];
extern uint8_t _dflash_base[];

static bool s_powered = false;

/* Backing-store names, matching the native simulator's so a card image made by
 * one is readable by the other. */
#define EEPROM_IMAGE "card_eeprom.bin"
#define DFLASH_IMAGE "card_flash.bin"

static uint8_t *region_base(hal_nvm_region region, uint32_t *out_size)
{
    switch (region) {
    case HAL_NVM_EEPROM:
        if (out_size != NULL) {
            *out_size = SCV1_EEPROM_SIZE;
        }
        return _eeprom_base;
    case HAL_NVM_FLASH:
        if (out_size != NULL) {
            *out_size = SCV1_DFLASH_SIZE;
        }
        return _dflash_base;
    default:
        if (out_size != NULL) {
            *out_size = 0u;
        }
        return NULL;
    }
}

uint32_t hal_nvm_size(hal_nvm_region region)
{
    uint32_t size = 0u;
    (void)region_base(region, &size);
    return size;
}

uint32_t hal_nvm_page_size(hal_nvm_region region)
{
    switch (region) {
    case HAL_NVM_EEPROM:
        return SCV1_EEPROM_PAGE;
    case HAL_NVM_FLASH:
        return SCV1_DFLASH_PAGE;
    default:
        return 0u;
    }
}

/* uint64_t so a hostile (offset=0xFFFFFFF0, len=0x20) cannot wrap into a small
 * number and pass. The native HAL does the same check independently -- each
 * implementation is responsible for its own bounds, because on hardware a bad
 * offset corrupts a neighbouring structure that fails a thousand power cycles
 * later. */
static bool in_range(uint32_t size, uint32_t offset, uint32_t len)
{
    const uint64_t end = (uint64_t)offset + (uint64_t)len;
    return end <= (uint64_t)size;
}

hal_status hal_nvm_read(hal_nvm_region region, uint32_t offset, void *dst,
                        uint32_t len)
{
    if (dst == NULL) {
        return HAL_ERR_PARAM;
    }
    if (len == 0u) {
        return HAL_OK;
    }
    if (!s_powered) {
        return HAL_ERR_POWER;
    }

    uint32_t       size = 0u;
    const uint8_t *base = region_base(region, &size);
    if (base == NULL) {
        return HAL_ERR_PARAM;
    }
    if (!in_range(size, offset, len)) {
        return HAL_ERR_RANGE;
    }

    if (!os_memcpy_checked(dst, len, base + offset, len)) {
        return HAL_ERR_IO;
    }
    return HAL_OK;
}

hal_status hal_nvm_write(hal_nvm_region region, uint32_t offset,
                         const void *src, uint32_t len)
{
    if (src == NULL) {
        return HAL_ERR_PARAM;
    }
    if (len == 0u) {
        return HAL_OK;
    }
    if (!s_powered) {
        return HAL_ERR_POWER;
    }

    uint32_t size = 0u;
    uint8_t *base = region_base(region, &size);
    if (base == NULL) {
        return HAL_ERR_PARAM;
    }
    if (!in_range(size, offset, len)) {
        return HAL_ERR_RANGE;
    }

    if (!os_memcpy_checked(base + offset, len, src, len)) {
        return HAL_ERR_IO;
    }
    return HAL_OK;
}

hal_status hal_nvm_sync(void)
{
    if (!s_powered) {
        return HAL_ERR_POWER;
    }
    /* SRAM-backed on this target, so writes are already durable within the
     * device. A real flash controller would block here until programming
     * completed and report a failure it could not retry. */
    return HAL_OK;
}

/* --------------------------------------------------- power-up / power-down -- */

void scv1_nvm_power_on(void)
{
    semihost_probe();

    uint32_t esize = 0u, fsize = 0u;
    uint8_t *eeprom = region_base(HAL_NVM_EEPROM, &esize);
    uint8_t *dflash = region_base(HAL_NVM_FLASH, &fsize);

    /*
     * POWER-ON MUST NOT DESTROY WHAT IS ALREADY THERE.
     *
     * This function originally erased both regions before trying to load them,
     * which was a real bug: booting a pre-programmed card image (code plus a
     * personalised filesystem, written in one pass by a programmer) wiped the
     * filesystem before the first instruction of the OS ran.
     *
     * On real silicon none of this code exists -- NVM simply retains its
     * contents, and blank cells read as 0xFF because that is what an erased
     * cell is. The three cases below reproduce that behaviour on a development
     * target where the regions are ordinary SRAM:
     *
     *   1. a semihosting host has image files      -> load them
     *   2. no files, but the region already holds  -> leave it ALONE; it was
     *      a filesystem                              programmed into the image
     *   3. neither                                 -> the region is
     *                                                 uninitialised SRAM, so
     *                                                 erase it to 0xFF to look
     *                                                 like a blank chip
     */
    bool eeprom_loaded = false;
    bool dflash_loaded = false;

    if (semihost_available()) {
        const long e = semihost_load(EEPROM_IMAGE, eeprom, esize);
        if (e > 0) {
            eeprom_loaded = true;
            if ((uint32_t)e < esize) {
                os_memset(eeprom + e, 0xFFu, esize - (uint32_t)e);
            }
        }
        const long f = semihost_load(DFLASH_IMAGE, dflash, fsize);
        if (f > 0) {
            dflash_loaded = true;
            if ((uint32_t)f < fsize) {
                os_memset(dflash + f, 0xFFu, fsize - (uint32_t)f);
            }
        }
    }

    /* Case 2 vs 3 for EEPROM: does it already carry a filesystem superblock?
     * The magic is checked here rather than in the filesystem because only the
     * platform knows whether the memory it is looking at is real content or
     * uninitialised SRAM. */
    if (!eeprom_loaded) {
        const bool has_fs = (eeprom[0] == 'S') && (eeprom[1] == 'C') &&
                            (eeprom[2] == 'O') && (eeprom[3] == 'S');
        if (!has_fs) {
            os_memset(eeprom, 0xFFu, esize);
            /* Data flash is only meaningful alongside its metadata, so if the
             * EEPROM was blank the file data is erased too. */
            if (!dflash_loaded) {
                os_memset(dflash, 0xFFu, fsize);
            }
        }
    }

    s_powered = true;
}

void scv1_nvm_power_off(void)
{
    if (!s_powered) {
        return;
    }
    if (semihost_available()) {
        uint32_t       esize = 0u, fsize = 0u;
        const uint8_t *eeprom = region_base(HAL_NVM_EEPROM, &esize);
        const uint8_t *dflash = region_base(HAL_NVM_FLASH, &fsize);
        (void)semihost_store(EEPROM_IMAGE, eeprom, esize);
        (void)semihost_store(DFLASH_IMAGE, dflash, fsize);
    }
    s_powered = false;
}
