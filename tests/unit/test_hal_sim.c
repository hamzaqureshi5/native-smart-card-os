/* SPDX-License-Identifier: MIT
 *
 * test_hal_sim.c -- The simulator HAL against the contract in hal.h.
 *
 * These are CONTRACT tests, not simulator tests. Every assertion here is a
 * statement about what include/hal/hal.h promises, so this file should pass
 * unchanged against a real hardware HAL. That is what makes it useful: it is
 * the beginning of the conformance suite for the eventual port.
 */
#include "hal/hal.h"
#include "hal/sim/vcard.h"
#include "os/os_mem.h"

#include "scos_test.h"

TEST(regions_report_plausible_geometry)
{
    CHECK_EQ(hal_nvm_size(HAL_NVM_EEPROM), SCOS_EEPROM_BYTES);
    CHECK_EQ(hal_nvm_size(HAL_NVM_FLASH), SCOS_FLASH_BYTES);

    /* Page size must be non-zero and a power of two: the transaction manager
     * will do modulo arithmetic with it. */
    for (int r = 0; r <= 1; r++) {
        const uint32_t p = hal_nvm_page_size((hal_nvm_region)r);
        CHECK(p > 0u);
        CHECK((p & (p - 1u)) == 0u);
    }
}

TEST(fresh_nvm_reads_as_erased)
{
    /* 0xFF is the erased state of real flash and EEPROM. A blank simulator
     * chip must look blank the same way, or filesystem code that treats FF as
     * "free" will behave differently on hardware. */
    uint8_t buf[64];
    CHECK_EQ(hal_nvm_read(HAL_NVM_FLASH, 0u, buf, sizeof(buf)), HAL_OK);
    for (unsigned i = 0; i < sizeof(buf); i++) {
        CHECK_HEX(buf[i], 0xFF);
    }
}

TEST(write_then_read_roundtrip)
{
    const uint8_t pattern[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02 };
    uint8_t       back[sizeof(pattern)];

    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, 100u, pattern, sizeof(pattern)),
             HAL_OK);
    CHECK_EQ(hal_nvm_sync(), HAL_OK);
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 100u, back, sizeof(back)), HAL_OK);
    CHECK(os_memeq_ct(pattern, back, sizeof(pattern)));

    /* A write must not disturb its neighbours -- the bug that page-granular
     * hardware makes easy to introduce. */
    uint8_t before = 0u, after = 0u;
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 99u, &before, 1u), HAL_OK);
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 107u, &after, 1u), HAL_OK);
    CHECK_HEX(before, 0xFF);
    CHECK_HEX(after, 0xFF);
}

TEST(regions_are_independent)
{
    const uint8_t a   = 0xAA;
    const uint8_t b   = 0xBB;
    uint8_t       got = 0u;

    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, 0u, &a, 1u), HAL_OK);
    CHECK_EQ(hal_nvm_write(HAL_NVM_FLASH, 0u, &b, 1u), HAL_OK);
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0u, &got, 1u), HAL_OK);
    CHECK_HEX(got, 0xAA);
    CHECK_EQ(hal_nvm_read(HAL_NVM_FLASH, 0u, &got, 1u), HAL_OK);
    CHECK_HEX(got, 0xBB);
}

/*
 * Bounds checking. The offsets below are chosen so that a naive
 * `if (offset + len > size)` written in uint32_t would WRAP and pass the
 * check, then memcpy out of bounds. Under ASan a regression here aborts.
 */
TEST(out_of_range_access_is_refused)
{
    uint8_t        buf[16];
    const uint32_t size = hal_nvm_size(HAL_NVM_EEPROM);

    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, size, buf, 1u), HAL_ERR_RANGE);
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, size - 1u, buf, 2u), HAL_ERR_RANGE);
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, size, buf, 1u), HAL_ERR_RANGE);

    /* The integer-overflow cases. */
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0xFFFFFFFFu, buf, 1u), HAL_ERR_RANGE);
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0xFFFFFFF0u, buf, 0x20u),
             HAL_ERR_RANGE);
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, 0xFFFFFFF0u, buf, 0x20u),
             HAL_ERR_RANGE);
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 4u, buf, 0xFFFFFFFFu), HAL_ERR_RANGE);

    /* Exactly at the boundary must SUCCEED -- an off-by-one in the other
     * direction is just as much a bug. */
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, size - 16u, buf, 16u), HAL_OK);
}

TEST(null_and_zero_length_are_handled)
{
    uint8_t buf[4];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0u, NULL, 4u), HAL_ERR_PARAM);
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, 0u, NULL, 4u), HAL_ERR_PARAM);
    /* Zero length is a no-op success, not an error: callers loop over ranges
     * that can legitimately be empty. */
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0u, buf, 0u), HAL_OK);
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, 0u, buf, 0u), HAL_OK);

    /* An undefined region must be refused, not silently mapped somewhere. */
    CHECK_EQ(hal_nvm_read((hal_nvm_region)99, 0u, buf, 1u), HAL_ERR_PARAM);
    CHECK_EQ(hal_nvm_size((hal_nvm_region)99), 0u);
}

TEST(rng_produces_output_and_respects_bounds)
{
    uint8_t a[32] = { 0 };
    uint8_t b[32] = { 0 };

    CHECK_EQ(hal_random_bytes(a, sizeof(a)), HAL_OK);
    CHECK_EQ(hal_random_bytes(b, sizeof(b)), HAL_OK);
    /* Two successive draws differing is a smoke test, not a randomness test.
     * The simulator RNG is a seeded PRNG and carries no security claim --
     * see hal_sim_platform.c. */
    CHECK(!os_memeq_ct(a, b, sizeof(a)));

    CHECK_EQ(hal_random_bytes(NULL, 4u), HAL_ERR_PARAM);
    CHECK_EQ(hal_random_bytes(a, 0u), HAL_OK);

    /* Odd sizes must not overrun: the generator works in 8-byte blocks, so a
     * length that is not a multiple of 8 is the interesting case. */
    for (size_t n = 1; n <= 17u; n++) {
        uint8_t small[24];
        os_memset(small, 0x5A, sizeof(small));
        CHECK_EQ(hal_random_bytes(small, n), HAL_OK);
        /* The byte just past the requested length must be untouched. */
        CHECK_HEX(small[n], 0x5A);
    }
}

TEST(atr_is_well_formed)
{
    uint32_t       len = 0u;
    const uint8_t *atr = hal_card_atr(&len);
    CHECK(atr != NULL);
    /* ISO 7816-3: the shortest legal ATR is TS + T0. */
    CHECK(len >= 2u);
    CHECK(len <= 33u);
    /* TS must be 3B (direct) or 3F (inverse) -- there is no third option. */
    CHECK(atr[0] == 0x3Bu || atr[0] == 0x3Fu);

    /* The historical-byte count in T0's low nibble must match what follows.
     * Our ATR declares TA1 and TD1 present, so: 2 header + 2 interface + K. */
    const uint8_t k = (uint8_t)(atr[1] & 0x0Fu);
    CHECK_EQ(len, 2u + 2u + k);
}

TEST(power_state_gates_nvm)
{
    uint8_t buf[4];
    CHECK_EQ(vcard_power_get(), VCARD_POWER_ON);

    vcard_power_off();
    CHECK_EQ(vcard_power_get(), VCARD_POWER_OFF);
    /* An unpowered chip cannot serve memory. Returning zeros instead would
     * let the OS mistake "no power" for "erased data". */
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0u, buf, 4u), HAL_ERR_POWER);
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, 0u, buf, 4u), HAL_ERR_POWER);
    CHECK_EQ(hal_nvm_sync(), HAL_ERR_POWER);
    CHECK_EQ(hal_random_bytes(buf, 4u), HAL_ERR_POWER);

    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0u, buf, 4u), HAL_OK);
}

/* Volatile (state_dir == NULL) NVM must NOT survive a power cycle. The
 * durable case needs a real directory and a second process, which is the
 * Python integration test's job in Milestone 2. */
TEST(volatile_nvm_is_lost_on_power_cycle)
{
    const uint8_t marker = 0x42;
    uint8_t       got    = 0u;

    CHECK_EQ(hal_nvm_write(HAL_NVM_FLASH, 4096u, &marker, 1u), HAL_OK);
    CHECK_EQ(hal_nvm_read(HAL_NVM_FLASH, 4096u, &got, 1u), HAL_OK);
    CHECK_HEX(got, 0x42);

    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);

    CHECK_EQ(hal_nvm_read(HAL_NVM_FLASH, 4096u, &got, 1u), HAL_OK);
    CHECK_HEX(got, 0xFF); /* erased again */
}

int main(void)
{
    vcard_config cfg;
    vcard_config_default(&cfg);
    cfg.state_dir = NULL; /* hermetic: no files, no shared state */
    cfg.quiet     = true;
    vcard_configure(&cfg);

    if (hal_init() != HAL_OK) {
        (void)printf("FATAL: hal_init failed\n");
        return EXIT_FAILURE;
    }

    RUN(regions_report_plausible_geometry);
    RUN(fresh_nvm_reads_as_erased);
    RUN(write_then_read_roundtrip);
    RUN(regions_are_independent);
    RUN(out_of_range_access_is_refused);
    RUN(null_and_zero_length_are_handled);
    RUN(rng_produces_output_and_respects_bounds);
    RUN(atr_is_well_formed);
    RUN(power_state_gates_nvm);
    RUN(volatile_nvm_is_lost_on_power_cycle);

    hal_shutdown();
    TEST_MAIN_END();
}
