/* SPDX-License-Identifier: MIT
 *
 * vcard.h -- The virtual chip.
 *
 * SIMULATOR-ONLY. The OS core must never include this header; only
 * src/hal/simulator/ and simulator/ may. It exists so those two directories
 * share a model of "the silicon" without either including the other's private
 * headers.
 *
 * This is the layer that gets DELETED (not ported) when real hardware arrives:
 * src/hal/s3m228a/ will implement include/hal/hal.h directly against real
 * peripherals, and nothing here will be referenced.
 */
#ifndef SCOS_VCARD_H
#define SCOS_VCARD_H

#include <stdbool.h>
#include <stdint.h>

#include "hal/hal.h"
#include "os/scos_config.h"

/* Virtual power state. POWER_FAILURE (Milestone 4) will differ from POWER_OFF
 * by skipping the durability flush, so that an interrupted write stays
 * interrupted across a restart. */
typedef enum { VCARD_POWER_OFF = 0, VCARD_POWER_ON } vcard_power;

typedef struct {
    /* Directory holding card_eeprom.bin / card_flash.bin. If NULL, the virtual
     * NVM is RAM-backed and vanishes at exit -- which is what unit tests want. */
    const char *state_dir;

    /* Usable region sizes. 0 means "use the compile-time capacity". Present so
     * tests can model a smaller chip without rebuilding. */
    uint32_t eeprom_size;
    uint32_t flash_size;

    /* Deterministic RNG seed for reproducible tests. 0 selects a
     * non-deterministic seed. NOT SECURE EITHER WAY -- see vcard_random(). */
    uint64_t rng_seed;

    bool quiet; /* suppress the banner on stderr */
} vcard_config;

/* Must be called before hal_init(). Copies what it needs from *cfg except
 * state_dir, whose storage must outlive the process's use of the card. */
void vcard_configure(const vcard_config *cfg);

/* Defaults, for callers that want to override one field. */
void vcard_config_default(vcard_config *cfg);

hal_status vcard_power_on(void);  /* load NVM, init peripherals */
void       vcard_power_off(void); /* flush NVM durably          */

/*
 * POWER FAILURE, as distinct from power off.
 *
 * vcard_power_off() is the reader pulling the card out cleanly: the NVM is
 * flushed durably first, because a real chip's writes have already completed.
 * That models an orderly end of session and it CANNOT test tear resistance --
 * every write the OS thought it made is present.
 *
 * vcard_power_failure() models the card leaving the field mid-operation: the
 * durability flush is SKIPPED, so anything the OS wrote without a following
 * hal_nvm_sync() is lost. A card that appeared to survive power_off and
 * corrupts under power_failure is the normal outcome of getting transactions
 * wrong, which is why both exist.
 */
void vcard_power_failure(void);

/*
 * Fault injection: make the NEXT hal_nvm_write() stop after `n` bytes and
 * report that power was lost.
 *
 * This is the whole reason M4's claims are testable rather than asserted. A
 * transaction that survives an interruption at byte 0 and at byte N tells you
 * very little; one that survives interruption at EVERY byte offset of a
 * multi-byte write is a different kind of statement, and reaching each of those
 * instants needs the write itself to stop there on command.
 *
 * `n` counts bytes actually stored before the abort, so 0 means "fail before
 * writing anything" and a value >= the write length means "do not fail".
 * Cleared automatically once it has fired, so a test arms it per write rather
 * than remembering to disarm.
 *
 * SIMULATOR ONLY, and deliberately not in include/hal/hal.h: the OS must have
 * no way to ask whether it is being fault-injected, or a future version of it
 * could behave differently under test than in the field.
 */
void vcard_fault_after_bytes(uint32_t n);
void vcard_fault_clear(void);

/* True if a fault fired since the last clear. Lets a test assert that the
 * interruption it asked for actually happened, rather than passing because
 * nothing went wrong for a different reason. */
bool vcard_fault_fired(void);

/* Internal, for hal_sim_nvm.c. Consumes the arming: returns true once and
 * disarms, so an arming aimed at one write cannot silently apply to the next
 * and make the test that armed it pass for the wrong reason. */
bool        vcard_fault_pending(uint32_t *out_after);
void        vcard_fault_mark_fired(void);
vcard_power vcard_power_get(void);

/* Print the startup banner (RAM/ROM/EEPROM/FLASH/ATR) to stderr. On stderr,
 * not stdout, because stdout carries APDU responses to the test client. */
void vcard_print_banner(void);

/* --- primitives consumed by src/hal/simulator/ ------------------------- */

/* Backing store for the NVM HAL. */
uint8_t *vcard_nvm_base(hal_nvm_region region, uint32_t *out_size);
uint32_t vcard_nvm_page(hal_nvm_region region);

/* Raw output of the simulator PRNG. NOT CRYPTOGRAPHIC; see virtual_card.c. */
uint64_t vcard_random_u64(void);

const uint8_t *vcard_atr(uint32_t *out_len);

#endif /* SCOS_VCARD_H */
