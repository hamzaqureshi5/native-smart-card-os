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
     * FAULT INJECTION, and this is the M4 hook the previous version of this
     * comment promised.
     *
     * A real write is not instantaneous: it is a sequence of page programs, and
     * power can be removed part way through, leaving the array partly updated.
     * An unconditional memcpy models the OPTIMISTIC case only -- every write
     * either happens completely or not at all -- and a transaction manager
     * tested against it has not been tested at all.
     *
     * When armed, the write stores the first `n` bytes and then reports
     * HAL_ERR_POWER. The bytes before the cut are REAL and stay in the array,
     * because that is what a half-programmed page looks like: the OS must
     * recover from partial data, not from an untouched region.
     *
     * The arming is one-shot. A test arms it for the write it wants to
     * interrupt rather than arming and disarming around it, which is the
     * version that leaves a fault armed for the next test.
     */
    uint32_t cut = 0u;
    if (vcard_fault_pending(&cut)) {
        const uint32_t stored = (cut < len) ? cut : len;
        if (stored > 0u) {
            memcpy(base + offset, src, (size_t)stored);
        }
        if (cut < len) {
            /*
             * HAL_ERR_POWER, not a write error. The distinction matters to the
             * OS: a write that failed because the device refused is something
             * to report, while a write that failed because the card is losing
             * power is something to recover from on the next boot. Reporting
             * the wrong one would send the OS down the wrong path.
             */
            vcard_fault_mark_fired();
            return HAL_ERR_POWER;
        }
        /* cut >= len: the arming did not reach this write, so it completed.
         * Left as a normal success, and the fault stays fired = false. */
    }

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
