/* SPDX-License-Identifier: MIT
 *
 * crypto.h -- the cryptographic seam.
 *
 * This is the same idea as include/hal/hal.h, one layer up: the OS states what
 * it needs and never learns what provides it. On this simulator the backend is
 * software; on a real secure MCU it should be the crypto accelerator, and on a
 * part with hardware key slots the key material should never enter RAM at all.
 *
 * WHY THERE IS A SOFTWARE SHA-256 IN THIS TREE, WHICH NEEDS JUSTIFYING
 *
 * The project's standing rule is: do not write AES/RSA/ECC implementations
 * from scratch. That rule exists because those primitives are where a
 * hand-written version goes quietly wrong -- secret-dependent branches,
 * incorrect field arithmetic, timing leaks -- and where an audited library is
 * strictly better.
 *
 * SHA-256 sits differently, for three reasons, and the M3 PIN verifier cannot
 * exist without one:
 *
 *   1. No library is available here, and installing one would not help. The
 *      card is bare-metal ARM with no libc beyond what we provide; OpenSSL
 *      cannot run on it. A library-backed hash would work on the simulator
 *      only, which breaks the property the whole project rests on -- that the
 *      OS is the same code on both targets.
 *   2. It takes no key. There is no secret-dependent control flow to get
 *      wrong: the compression function is the same sequence of operations for
 *      every input.
 *   3. It is checkable against something external. NIST FIPS 180-4 publishes
 *      known-answer vectors, and tests/unit/test_crypto.c uses them; the
 *      Python suite additionally cross-checks against hashlib, so the
 *      implementation is validated by two independent oracles rather than by
 *      its own author.
 *
 * NOT AUDITED, and not a claim that it is. On real silicon this should be
 * replaced by the part's hash accelerator -- see docs/hardware-port.md.
 */
#ifndef SCOS_CRYPTO_H
#define SCOS_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CRYPTO_SHA256_LEN   32u
#define CRYPTO_SHA256_BLOCK 64u

typedef enum {
    CRYPTO_OK              = 0,
    CRYPTO_ERR_PARAM       = -1,
    CRYPTO_ERR_UNSUPPORTED = -2, /* no backend provides this            */
    CRYPTO_ERR_ENTROPY     = -3  /* the TRNG failed or is unavailable   */
} crypto_status;

/* ------------------------------------------------------------- SHA-256 ---- */

/* Incremental state. Exposed so callers can hash without a buffer big enough
 * for the whole input -- which matters on a card, where "the whole input"
 * might be a 1 KB extended APDU and RAM is measured in kilobytes. */
typedef struct {
    uint32_t h[8];
    uint64_t bits;                     /* message length in BITS         */
    uint8_t  buf[CRYPTO_SHA256_BLOCK]; /* partial block                  */
    uint8_t  buf_len;
} crypto_sha256_ctx;

void crypto_sha256_init(crypto_sha256_ctx *c);
void crypto_sha256_update(crypto_sha256_ctx *c, const void *data, size_t len);
crypto_status crypto_sha256_final(crypto_sha256_ctx *c,
                                  uint8_t            out[CRYPTO_SHA256_LEN]);

/* One-shot convenience over the three above. */
crypto_status crypto_sha256(const void *data, size_t len,
                            uint8_t out[CRYPTO_SHA256_LEN]);

/* ---------------------------------------------------------- comparison ---- */

/*
 * Constant-time equality. Returns true if the buffers match.
 *
 * NOT memcmp, and the difference is the whole point. memcmp returns on the
 * first differing byte, so the time it takes reveals how many leading bytes
 * were right -- which turns a search over the whole secret into a search one
 * byte at a time. For a 32-byte verifier that is the difference between 2^256
 * and 32*256 attempts.
 *
 * A card is a particularly bad place to leak this: the attacker holds the
 * hardware, controls the clock, and can measure as precisely as they like.
 */
bool crypto_equal_ct(const void *a, const void *b, size_t len);

/* ------------------------------------------------------------- entropy ---- */

/*
 * Random bytes, from the platform's TRNG via the HAL.
 *
 * Returns CRYPTO_ERR_ENTROPY and writes NOTHING to dst if entropy is not
 * available. It never falls back to a software PRNG: a card that silently
 * substitutes predictable bytes for a missing TRNG is how real products ship
 * guessable keys and salts. A caller that cannot get entropy must fail, not
 * proceed.
 */
crypto_status crypto_random_bytes(void *dst, size_t len);

/* ------------------------------------------------------------- wiping ----- */

/*
 * Overwrite a buffer that held a secret.
 *
 * Not a plain loop, because a compiler is entitled to delete a write to
 * storage that is never read again -- and does, at -O2. This is the reason
 * memset_s and explicit_bzero exist; we have neither, so the barrier is here.
 */
void crypto_wipe(void *p, size_t len);

#endif /* SCOS_CRYPTO_H */
