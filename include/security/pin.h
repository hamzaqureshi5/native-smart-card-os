/* SPDX-License-Identifier: MIT
 *
 * pin.h -- cardholder verification.
 *
 * THE ONE PROPERTY THIS FILE EXISTS TO GUARANTEE
 *
 * A failed attempt must cost a try, and no sequence of power cuts may give it
 * back. That is not a nicety: a card that restores the try when power is
 * removed after a wrong PIN has a retry counter of infinity, and a 4-digit PIN
 * falls in ten thousand attempts. It is a real attack, it has been used
 * against real products, and defending against it decides the storage layout
 * rather than the other way round.
 *
 * So: the counter is decremented DURABLY BEFORE the PIN is compared, it lives
 * in byte-writable EEPROM so that decrement is a single-byte write, and it is
 * stored as a unary tally that only ever loses bits. See src/security/pin.c
 * for why each of those three is load-bearing.
 *
 * WHAT IS NOT CLAIMED
 *
 * The verifier is a salted SHA-256, so a single read of NVM does not hand over
 * the PIN. It does NOT make the PIN safe against an attacker who can read NVM
 * and compute: a 4-digit PIN is ten thousand hashes, which is instant. The
 * real protection is the retry counter plus the chip's memory protection, and
 * this project models neither the chip nor its protection. Do not read the
 * hash as making offline attack hard; read it as making casual disclosure
 * ineffective. docs/threat-model.md carries this as a limitation, not a
 * mitigation.
 */
#ifndef SCOS_PIN_H
#define SCOS_PIN_H

#include <stdbool.h>
#include <stdint.h>

/*
 * PIN references. P2 of VERIFY carries one of these.
 *
 * Two, because the PUK exists to unblock the PIN and therefore cannot be the
 * PIN. Only PIN_REF_USER is personalised in this milestone; PIN_REF_UNBLOCK is
 * reserved so the record layout and the NVM map do not have to change when
 * RESET RETRY COUNTER lands.
 */
#define PIN_REF_USER    0x01u
#define PIN_REF_UNBLOCK 0x02u

#define SEC_MAX_PIN_REFS 2u

/* Length limits on the value presented for verification. */
#define PIN_MIN_LEN 4u
#define PIN_MAX_LEN 16u

/*
 * The try limit cannot exceed 8, because the counter is a unary tally in one
 * byte -- eight bits, eight tries. Not a shortcoming: real cards use 3, and a
 * limit that needed more than a byte would give up the atomic single-byte
 * decrement this whole design turns on.
 */
#define PIN_MAX_TRY_LIMIT 8u

typedef enum {
    PIN_STATE_UNSET  = 0x01u, /* no PIN personalised; verification impossible */
    PIN_STATE_ACTIVE = 0x02u, /* usable                                       */
    PIN_STATE_BLOCKED = 0x03u /* tries exhausted                              */
} pin_state;

typedef struct {
    pin_state state;
    uint8_t   try_limit;
    uint8_t   tries_left;
} pin_info;

typedef enum {
    PIN_OK            = 0,
    PIN_ERR_PARAM     = -1,
    PIN_ERR_NOT_FOUND = -2, /* no such reference                          */
    PIN_ERR_WRONG     = -3, /* the value did not match; a try was spent   */
    PIN_ERR_BLOCKED   = -4, /* no tries remain                            */
    PIN_ERR_UNSET     = -5, /* nothing to verify against                   */
    PIN_ERR_NVM       = -6, /* the store refused a read or a write         */
    PIN_ERR_CORRUPT   = -7, /* the record failed its integrity check       */
    PIN_ERR_ENTROPY   = -8  /* no salt available, so no PIN can be set     */
} pin_status;

/* Format the security store. Called on a blank chip. DESTRUCTIVE. */
pin_status pin_personalise(void);

/* Load the store, or report that it is absent or damaged. */
pin_status pin_init(void);

/*
 * Set (or replace) the value for `ref`.
 *
 * Generates a fresh salt from the TRNG and REFUSES if entropy is unavailable
 * rather than falling back to something predictable: a card whose PIN salts
 * are guessable has, in effect, no salt at all, and the failure would be
 * invisible.
 *
 * Resets the try counter to `try_limit` and the state to ACTIVE, so this also
 * serves as the unblock primitive once RESET RETRY COUNTER exists.
 */
pin_status pin_set(uint8_t ref, const uint8_t *value, uint8_t len,
                   uint8_t try_limit);

/*
 * Verify `value` against `ref`.
 *
 * ALWAYS spends a try before comparing, and writes that to NVM first. On
 * success the counter is restored. `out` is filled in on every return except
 * PIN_ERR_PARAM/NOT_FOUND so a caller can build 63CX without a second read.
 */
pin_status pin_verify(uint8_t ref, const uint8_t *value, uint8_t len,
                      pin_info *out);

/* State without spending a try. This is what a VERIFY with an empty data
 * field answers, and it must not itself be usable as an oracle -- it reveals
 * only what the card would tell anyone. */
pin_status pin_get(uint8_t ref, pin_info *out);

#endif /* SCOS_PIN_H */
