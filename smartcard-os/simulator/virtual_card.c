/* SPDX-License-Identifier: MIT
 *
 * virtual_card.c -- The virtual chip.
 *
 * This file is the pretend silicon: memory arrays, a backing store, a power
 * state machine and an ATR. It is the ONLY place in the simulator that is
 * allowed to know about files, and it is the file that becomes irrelevant when
 * real hardware arrives.
 *
 * WHAT A SIMULATOR CAN AND CANNOT MODEL
 * -------------------------------------
 * Faithfully: memory layout and sizes, page granularity, protocol behaviour,
 * persistence across power cycles, torn writes, and the logic of every OS
 * subsystem. That is the overwhelming majority of a card OS, which is why this
 * approach works.
 *
 * Not at all: real timing, power and EM emissions, glitch and laser fault
 * injection, memory encryption, sensor-triggered tamper response, and the true
 * quality of the random source. Those live in silicon. Anything in this project
 * claiming to test them would be lying, so nothing does.
 */
#include "hal/sim/vcard.h"

/* Host-side headers are allowed HERE and only here (plus transport.c and the
 * other src/hal/simulator files). The OS core links against none of them. */
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#  include <direct.h>
#  define VCARD_MKDIR(p) _mkdir(p)
#else
#  include <sys/stat.h>
#  include <sys/types.h>
#  define VCARD_MKDIR(p) mkdir((p), 0700)
#endif

/* --- virtual memory ------------------------------------------------------ */
/*
 * Two regions with different physical characters, mirroring how real secure
 * MCUs are built:
 *
 *   EEPROM  small, byte-writable, ~500k erase cycles. OS metadata, PIN
 *           counters, transaction journal. Byte-writability is what makes a
 *           reliable retry counter possible at all.
 *   FLASH   large, erased in pages, ~10k-100k cycles. File contents and code.
 *           Page granularity is why transactions need a journal: you cannot
 *           update 3 bytes of a 256-byte page without rewriting the page.
 *
 * The page sizes below are plausible, not authoritative. A real port replaces
 * them with values read out of a datasheet.
 */
#define VCARD_EEPROM_PAGE 4u
#define VCARD_FLASH_PAGE  256u

static uint8_t s_eeprom[SCOS_EEPROM_BYTES];
static uint8_t s_flash[SCOS_FLASH_BYTES];

static vcard_config s_cfg;
static bool         s_configured = false;
static vcard_power  s_power      = VCARD_POWER_OFF;

/* xorshift64*. DETERMINISTIC AND NOT CRYPTOGRAPHIC. It exists so tests are
 * reproducible. hal_random_bytes() documents the consequence: no security
 * claim in this project may rest on the simulator's RNG. */
static uint64_t s_rng_state = 0;

/*
 * Simulator ATR: 3B 94 11 00 53 43 4F 53
 *
 *   3B  TS   direct convention (bit order and polarity of the byte encoding)
 *   94  T0   Y1=1001 -> TA1 and TD1 present; K=4 -> four historical bytes
 *   11  TA1  FI=1 (F=372, f_max 5 MHz), DI=1 (D=1) -> the ISO default rate
 *   00  TD1  Y2=0 -> no further interface bytes; T=0 -> character protocol
 *   53 43 4F 53   historical bytes, ASCII "SCOS"
 *
 *   TCK is absent, which is correct: ISO/IEC 7816-3 requires the check byte
 *   only when a protocol other than T=0 is indicated.
 *
 * IMPORTANT: this ATR describes THIS SIMULATOR. It is not any real card's ATR
 * and it must not be copied onto real hardware, where the values have to be
 * derived from the actual clock, guard times and supported protocols. The
 * simulator does not implement T=0 character-level framing at all -- it moves
 * whole APDUs over a pipe -- so the protocol byte here is documentation of
 * intent rather than an emulated link layer. See docs/simulator.md.
 */
static const uint8_t s_atr[] = {
    0x3B, 0x94, 0x11, 0x00, 0x53, 0x43, 0x4F, 0x53
};

/* ------------------------------------------------------------- config ---- */

void vcard_config_default(vcard_config *cfg)
{
    if (cfg == NULL) {
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->state_dir   = NULL; /* RAM-backed by default: tests stay hermetic */
    cfg->eeprom_size = SCOS_EEPROM_BYTES;
    cfg->flash_size  = SCOS_FLASH_BYTES;
    cfg->rng_seed    = 1u;
    cfg->quiet       = false;
}

void vcard_configure(const vcard_config *cfg)
{
    if (cfg == NULL) {
        vcard_config_default(&s_cfg);
    } else {
        s_cfg = *cfg;
    }
    /* 0 means "use the compile-time capacity"; anything larger is clamped,
     * because we cannot conjure memory the virtual chip does not have. */
    if (s_cfg.eeprom_size == 0u || s_cfg.eeprom_size > SCOS_EEPROM_BYTES) {
        s_cfg.eeprom_size = SCOS_EEPROM_BYTES;
    }
    if (s_cfg.flash_size == 0u || s_cfg.flash_size > SCOS_FLASH_BYTES) {
        s_cfg.flash_size = SCOS_FLASH_BYTES;
    }
    s_configured = true;
}

static const vcard_config *cfg(void)
{
    if (!s_configured) {
        vcard_config_default(&s_cfg);
        s_configured = true;
    }
    return &s_cfg;
}

/* --------------------------------------------------------- backing store -- */

static void path_join(char *out, size_t cap, const char *dir, const char *name)
{
    /* snprintf truncates rather than overflowing; a truncated path fails to
     * open, which is the safe outcome. */
    (void)snprintf(out, cap, "%s/%s", dir, name);
}

static void region_load(const char *dir, const char *name,
                        uint8_t *buf, uint32_t size)
{
    char path[512];
    path_join(path, sizeof(path), dir, name);

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        /* No image yet: a factory-fresh chip. 0xFF is the erased state of real
         * flash and EEPROM, so starting there makes "blank" mean the same
         * thing in the simulator as on silicon. */
        memset(buf, 0xFF, size);
        return;
    }
    const size_t got = fread(buf, 1u, (size_t)size, f);
    (void)fclose(f);
    if (got < (size_t)size) {
        /* Short image (chip grew, or the file was truncated by an earlier
         * crash). Fill the tail as erased rather than leaving it undefined. */
        memset(buf + got, 0xFF, (size_t)size - got);
    }
}

static void region_store(const char *dir, const char *name,
                         const uint8_t *buf, uint32_t size)
{
    char path[512];
    path_join(path, sizeof(path), dir, name);

    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        (void)fprintf(stderr, "[vcard] cannot write %s\n", path);
        return;
    }
    (void)fwrite(buf, 1u, (size_t)size, f);
    (void)fflush(f);
    (void)fclose(f);
}

/* ------------------------------------------------------------- power ----- */

hal_status vcard_power_on(void)
{
    const vcard_config *c = cfg();

    if (c->state_dir != NULL) {
        (void)VCARD_MKDIR(c->state_dir); /* may already exist; that is fine */
        region_load(c->state_dir, "card_eeprom.bin", s_eeprom, c->eeprom_size);
        region_load(c->state_dir, "card_flash.bin",  s_flash,  c->flash_size);
    } else {
        memset(s_eeprom, 0xFF, c->eeprom_size);
        memset(s_flash,  0xFF, c->flash_size);
    }

    /* RAM is deliberately NOT restored. That is the whole point of RAM: a
     * power cycle must lose it. The card's RAM is the scos_kernel struct owned
     * by the platform, and scos_init() clears it -- so "volatile" is enforced
     * by construction rather than by anything this function does. */
    s_rng_state = (c->rng_seed != 0u) ? c->rng_seed : 0x2545F4914F6CDD1DULL;

    s_power = VCARD_POWER_ON;
    return HAL_OK;
}

void vcard_power_off(void)
{
    const vcard_config *c = cfg();
    if (s_power == VCARD_POWER_ON && c->state_dir != NULL) {
        region_store(c->state_dir, "card_eeprom.bin", s_eeprom, c->eeprom_size);
        region_store(c->state_dir, "card_flash.bin",  s_flash,  c->flash_size);
    }
    s_power = VCARD_POWER_OFF;
}

vcard_power vcard_power_get(void) { return s_power; }

/* --------------------------------------------------------------- NVM ----- */

uint8_t *vcard_nvm_base(hal_nvm_region region, uint32_t *out_size)
{
    const vcard_config *c = cfg();
    switch (region) {
    case HAL_NVM_EEPROM:
        if (out_size != NULL) { *out_size = c->eeprom_size; }
        return s_eeprom;
    case HAL_NVM_FLASH:
        if (out_size != NULL) { *out_size = c->flash_size; }
        return s_flash;
    default:
        if (out_size != NULL) { *out_size = 0u; }
        return NULL;
    }
}

uint32_t vcard_nvm_page(hal_nvm_region region)
{
    switch (region) {
    case HAL_NVM_EEPROM: return VCARD_EEPROM_PAGE;
    case HAL_NVM_FLASH:  return VCARD_FLASH_PAGE;
    default:             return 0u;
    }
}

/* --------------------------------------------------------------- RNG ----- */

uint64_t vcard_random_u64(void)
{
    /* xorshift64* -- statistically decent, cryptographically worthless. */
    uint64_t x = s_rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    s_rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

/* ------------------------------------------------------------- banner ---- */

const uint8_t *vcard_atr(uint32_t *out_len)
{
    if (out_len != NULL) {
        *out_len = (uint32_t)sizeof(s_atr);
    }
    return s_atr;
}

void vcard_print_banner(void)
{
    const vcard_config *c = cfg();
    if (c->quiet) {
        return;
    }

    (void)fprintf(stderr,
                  "SmartCard OS Simulator\n"
                  "Version: %s\n"
                  "\n"
                  "RAM:     %u KB   (budget; not enforced at run time)\n"
                  "ROM:     %u KB   (budget; checked against the build)\n"
                  "EEPROM:  %u KB   page %u B\n"
                  "FLASH:   %u KB   page %u B\n",
                  SCOS_VERSION_STRING,
                  (unsigned)SCOS_RAM_KB,
                  (unsigned)SCOS_ROM_KB,
                  (unsigned)(c->eeprom_size / 1024u), VCARD_EEPROM_PAGE,
                  (unsigned)(c->flash_size / 1024u),  VCARD_FLASH_PAGE);

    (void)fprintf(stderr, "State:   %s\n",
                  (c->state_dir != NULL) ? c->state_dir
                                         : "(volatile, RAM-backed)");

    (void)fprintf(stderr, "ATR:     ");
    for (size_t i = 0; i < sizeof(s_atr); i++) {
        (void)fprintf(stderr, "%02X%s", s_atr[i],
                      (i + 1u < sizeof(s_atr)) ? " " : "");
    }
    (void)fprintf(stderr, "\n\nWaiting for APDU...\n");
    (void)fflush(stderr);
}
