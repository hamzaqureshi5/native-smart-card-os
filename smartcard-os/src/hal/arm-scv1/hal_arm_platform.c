/* SPDX-License-Identifier: MIT
 *
 * hal_arm_platform.c -- SCV1 lifecycle, entropy and time.
 */
#include "hal/hal.h"
#include "scv1.h"
#include "scv1_internal.h"
#include "semihost.h"


/* ---------------------------------------------------------- lifecycle ----- */

hal_status hal_init(void)
{
    /* The link comes up FIRST, so that anything below can report a failure.
     * A HAL that cannot talk until the end of its own init has no way to tell
     * you why it failed. */
    scv1_uart_init();

    /* SysTick as a free-running millisecond source. CLKSOURCE selects the
     * processor clock; TICKINT stays off because we poll rather than take an
     * interrupt -- a card has one thread of control and nothing to preempt. */
    SCV1_SYSTICK_RVR = (SCV1_SYSCLK_HZ / 1000u) - 1u;
    SCV1_SYSTICK_CVR = 0u;
    SCV1_SYSTICK_CSR = SCV1_SYSTICK_ENABLE | SCV1_SYSTICK_CLKSOURCE;

    scv1_nvm_power_on();
    return HAL_OK;
}

void hal_reset(void)
{
    /* Warm reset: peripherals only. NVM must survive, and must NOT be reloaded
     * from the backing store -- that would resurrect data the card has already
     * overwritten in this power session. */
}

void hal_shutdown(void)
{
    scv1_nvm_power_off();
}

/* ------------------------------------------------------------- entropy ---- */

static uint64_t s_rng_state = 0x2545F4914F6CDD1DULL;

hal_status hal_random_bytes(void *dst, size_t len)
{
    if (dst == NULL) { return HAL_ERR_PARAM; }
    if (len == 0u)   { return HAL_OK; }

    /*
     * SCV1 HAS NO TRNG, AND THIS IS NOT ONE.
     *
     * A seeded xorshift, deterministic so that tests reproduce -- and therefore
     * worthless for security: anyone who knows the seed predicts every value
     * the card will ever produce. Identical in kind, and in danger, to the
     * native simulator's generator.
     *
     * A real secure MCU provides a certified TRNG with continuous health tests,
     * and this function must then return HAL_ERR_IO when those tests fail.
     * Callers check the return value for precisely that reason. Substituting a
     * software PRNG for a failed TRNG is how real products ship predictable
     * keys, so a future SCV1 revision with a TRNG must fail closed here rather
     * than fall back to this code.
     */
    uint8_t *out = (uint8_t *)dst;
    size_t   i   = 0;
    while (i < len) {
        uint64_t x = s_rng_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s_rng_state = x;
        const uint64_t r = x * 0x2545F4914F6CDD1DULL;

        const size_t n = ((len - i) < 8u) ? (len - i) : 8u;
        for (size_t j = 0; j < n; j++) {
            out[i + j] = (uint8_t)((r >> (8u * j)) & 0xFFu);
        }
        i += n;
    }
    return HAL_OK;
}

/* ---------------------------------------------------------------- time ---- */

uint32_t hal_timer_get_ms(void)
{
    /*
     * Polled SysTick. Counts down and sets a sticky COUNTFLAG on wrap, which we
     * accumulate. Good enough for diagnostics and nothing else.
     *
     * A smart card has NO TRUSTED CLOCK: it is clocked by the reader, so an
     * attacker controls how fast it runs and can stop it entirely. The OS must
     * therefore never make a security decision from time -- no timeout as a
     * defence, no rate limiting by elapsed time. PIN limits are counters in
     * NVM because counters survive power loss and clocks do not.
     */
    static uint32_t ms = 0u;
    if ((SCV1_SYSTICK_CSR & (1u << 16)) != 0u) { /* COUNTFLAG, read-clears */
        ms++;
    }
    return ms;
}
