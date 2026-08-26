/* SPDX-License-Identifier: MIT
 *
 * main.c -- Simulator entry point.
 *
 * Everything host-specific lives here and in the other two simulator files:
 * argument parsing, the banner, and the static allocation of the card's RAM.
 * The OS core has no main() and cannot have one -- on real silicon the reset
 * vector belongs to the chip's boot ROM, and the OS is entered from it.
 */
#include "hal/hal.h"
#include "hal/sim/vcard.h"
#include "os/kernel.h"
#include "os/scos_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The card's RAM.
 *
 * Statically allocated, exactly once, because there is no heap on a smart
 * card. This single object is the entire volatile state of the OS; its size is
 * held to the configured RAM budget by a _Static_assert in os/kernel.h.
 */
static scos_kernel s_card;

static void usage(const char *argv0)
{
    (void)fprintf(stderr,
        "usage: %s [options]\n"
        "\n"
        "  --state-dir DIR   persist virtual EEPROM/FLASH in DIR\n"
        "                    (default: none -- NVM is volatile)\n"
        "  --eeprom BYTES    usable EEPROM size (<= %u)\n"
        "  --flash BYTES     usable FLASH size  (<= %u)\n"
        "  --seed N          PRNG seed for reproducible runs (default 1)\n"
        "  --quiet           suppress the banner\n"
        "  --help            this text\n",
        argv0, (unsigned)SCOS_EEPROM_BYTES, (unsigned)SCOS_FLASH_BYTES);
}

/* strtoul with the error handling people usually skip. */
static int parse_u32(const char *s, uint32_t *out)
{
    if (s == NULL || *s == '\0') {
        return -1;
    }
    char           *end = NULL;
    unsigned long   v   = strtoul(s, &end, 0);
    if (end == NULL || *end != '\0' || v > 0xFFFFFFFFUL) {
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

int main(int argc, char **argv)
{
    vcard_config cfg;
    vcard_config_default(&cfg);

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int need_value = (strcmp(a, "--state-dir") == 0) ||
                         (strcmp(a, "--eeprom") == 0)    ||
                         (strcmp(a, "--flash") == 0)     ||
                         (strcmp(a, "--seed") == 0);
        if (need_value && i + 1 >= argc) {
            (void)fprintf(stderr, "%s: missing value for %s\n", argv[0], a);
            return 2;
        }

        if (strcmp(a, "--state-dir") == 0) {
            cfg.state_dir = argv[++i];
        } else if (strcmp(a, "--eeprom") == 0) {
            if (parse_u32(argv[++i], &cfg.eeprom_size) != 0) {
                (void)fprintf(stderr, "%s: bad --eeprom value\n", argv[0]);
                return 2;
            }
        } else if (strcmp(a, "--flash") == 0) {
            if (parse_u32(argv[++i], &cfg.flash_size) != 0) {
                (void)fprintf(stderr, "%s: bad --flash value\n", argv[0]);
                return 2;
            }
        } else if (strcmp(a, "--seed") == 0) {
            uint32_t seed = 0u;
            if (parse_u32(argv[++i], &seed) != 0) {
                (void)fprintf(stderr, "%s: bad --seed value\n", argv[0]);
                return 2;
            }
            cfg.rng_seed = (uint64_t)seed;
        } else if (strcmp(a, "--quiet") == 0) {
            cfg.quiet = true;
        } else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            (void)fprintf(stderr, "%s: unknown option '%s'\n", argv[0], a);
            usage(argv[0]);
            return 2;
        }
    }

    /* --- power-up sequence, in the order real silicon does it ------------- */

    /* 1. Configure and power the virtual chip; NVM becomes readable. */
    vcard_configure(&cfg);
    if (hal_init() != HAL_OK) {
        (void)fprintf(stderr, "fatal: HAL init failed\n");
        return 1;
    }

    /*
     * 2. Initialise the OS on top of it.
     *
     * A filesystem that will not mount is NOT a reason to stop. A real card
     * cannot exit -- it is a lump of silicon in a reader, and it must answer
     * something so the reader can tell "corrupt filesystem" from "dead card".
     * scos_init() leaves the kernel in SCOS_LC_FS_ERROR for exactly this case,
     * and scos_process() then answers 6581 (memory failure) to everything.
     *
     * Any other init failure is a genuine platform bug and is fatal.
     */
    const scos_status init_st = scos_init(&s_card);
    if (init_st != SCOS_OK) {
        if (s_card.lifecycle == SCOS_LC_FS_ERROR) {
            (void)fprintf(stderr,
                "WARNING: filesystem did not mount. The card will answer 6581 "
                "to every command.\n"
                "         It was NOT auto-formatted: that would destroy the "
                "data most worth\n"
                "         recovering. Use a fresh --state-dir to start over.\n");
        } else {
            (void)fprintf(stderr, "fatal: OS init failed (%d)\n", (int)init_st);
            hal_shutdown();
            return 1;
        }
    }

    /* 3. The reader would now read the ATR. */
    vcard_print_banner();

    /* 4. Serve APDUs until the reader disconnects. */
    scos_card_loop(&s_card);

    /* 5. Orderly power-down: NVM is flushed and made durable. */
    hal_shutdown();
    return 0;
}
