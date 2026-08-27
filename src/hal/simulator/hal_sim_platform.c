/* SPDX-License-Identifier: MIT
 *
 * hal_sim_platform.c -- Lifecycle, entropy and time for the simulator HAL.
 */
#include "hal/hal.h"
#include "hal/sim/vcard.h"

#include <string.h>
#include <time.h>

/* ---------------------------------------------------------- lifecycle ---- */

hal_status hal_init(void)
{ return vcard_power_on(); }

void hal_reset(void)
{
    /* A warm reset re-initialises peripherals but must NOT touch NVM, and must
     * not re-load the backing store: that would resurrect data the card had
     * already overwritten in this session. */
}

void hal_shutdown(void)
{ vcard_power_off(); }

/* -------------------------------------------------------------- entropy -- */

hal_status hal_random_bytes(void *dst, size_t len)
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

    /*
     * WARNING, AND IT IS NOT A SMALL ONE.
     *
     * This is a seeded xorshift PRNG. It is reproducible on purpose so tests
     * are deterministic, and that same property makes it useless for security:
     * anyone who learns the seed predicts every challenge, nonce and key the
     * card will ever produce.
     *
     * On real hardware this function must be backed by a certified TRNG with
     * continuous health tests, and it must return HAL_ERR_IO when those tests
     * fail. Callers are written to check the return value for that reason.
     *
     * Consequence for the whole project: no security property that depends on
     * unpredictability can be validated in the simulator. Only the logic
     * around it can.
     */
    uint8_t *out = (uint8_t *)dst;
    size_t   i   = 0;
    while (i < len) {
        const uint64_t r = vcard_random_u64();
        const size_t   n = ((len - i) < 8u) ? (len - i) : 8u;
        for (size_t j = 0; j < n; j++) {
            out[i + j] = (uint8_t)((r >> (8u * j)) & 0xFFu);
        }
        i += n;
    }
    return HAL_OK;
}

/* ----------------------------------------------------------------- time -- */

uint32_t hal_timer_get_ms(void)
{
    /*
     * Host monotonic-ish time via clock(), converted to milliseconds.
     *
     * A smart card has NO trusted clock: it is powered by the reader, so an
     * attacker controls how fast it runs and can stop it entirely. The OS must
     * therefore never use time for a security decision -- no timeouts as a
     * defence, no rate limiting by elapsed time. PIN limits are counters in
     * NVM precisely because counters survive power loss and clocks do not.
     * This function exists for diagnostics only.
     */
    const clock_t c = clock();
    if (c == (clock_t)-1) {
        return 0u;
    }
    const double ms = ((double)c / (double)CLOCKS_PER_SEC) * 1000.0;
    return (uint32_t)ms;
}
