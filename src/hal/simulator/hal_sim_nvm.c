/* SPDX-License-Identifier: MIT
 *
 * hal_sim_nvm.c -- Non-volatile memory HAL over the virtual chip.
 *
 * Bounds checking here is not defensive politeness: on real hardware a bad
 * NVM offset either faults or, worse, silently corrupts a neighbouring
 * structure that only fails a thousand power cycles later. Every access is
 * range-checked with arithmetic that cannot wrap.
 */
#include "hal/hal.h"
#include "hal/sim/vcard.h"

#include <string.h>

uint32_t hal_nvm_size(hal_nvm_region region)
{
    uint32_t size = 0u;
    (void)vcard_nvm_base(region, &size);
    return size;
}

uint32_t hal_nvm_page_size(hal_nvm_region region)
{ return vcard_nvm_page(region); }

/* Shared bounds check. offset + len is computed in uint64_t so that a hostile
 * (offset=0xFFFFFFF0, len=0x20) cannot wrap to a small number and pass. */
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
    if (vcard_power_get() != VCARD_POWER_ON) {
        return HAL_ERR_POWER;
    }

    uint32_t       size = 0u;
    const uint8_t *base = vcard_nvm_base(region, &size);
    if (base == NULL) {
        return HAL_ERR_PARAM;
    }
    if (!in_range(size, offset, len)) {
        return HAL_ERR_RANGE;
    }

    memcpy(dst, base + offset, (size_t)len);
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
    if (vcard_power_get() != VCARD_POWER_ON) {
        return HAL_ERR_POWER;
    }

    uint32_t size = 0u;
    uint8_t *base = vcard_nvm_base(region, &size);
    if (base == NULL) {
        return HAL_ERR_PARAM;
    }
    if (!in_range(size, offset, len)) {
        return HAL_ERR_RANGE;
    }

    /*
     * Milestone 4 hooks in here. A real write is not instantaneous: it is a
     * sequence of page programs, and power can be removed part way through,
     * leaving a page half-written. To test the transaction manager honestly
     * this function will gain a fault-injection hook that stops after N bytes
     * and marks the chip as having lost power. Today it is an atomic memcpy,
     * which is the OPTIMISTIC case -- so nothing in this project may yet claim
     * to have tested tear-resistance.
     */
    memcpy(base + offset, src, (size_t)len);
    return HAL_OK;
}

hal_status hal_nvm_sync(void)
{
    if (vcard_power_get() != VCARD_POWER_ON) {
        return HAL_ERR_POWER;
    }
    /* The virtual chip's writes hit the array immediately, so durability
     * within the simulated device is already guaranteed. Persisting to the
     * host filesystem happens at power-off. The call exists so that the OS is
     * written against a device that DOES buffer, which every real one does. */
    return HAL_OK;
}
