/* SPDX-License-Identifier: MIT
 *
 * crypto_mbedtls.c -- the crypto seam, backed by mbedTLS.
 *
 * This is the ONLY file in the tree that includes an mbedTLS header. The OS
 * above it sees include/crypto/crypto.h and cannot tell what implements it --
 * the same arrangement as include/hal/hal.h, and for the same reason: when a
 * real part's hash accelerator replaces this, nothing above has to change.
 *
 * mbedTLS is vendored as a submodule at third_party/mbedtls, pinned to the
 * 3.6 LTS tag, and configured by config/scos_mbedtls_config.h -- which turns
 * off the heap, the filesystem, the clock, the entropy stack and the whole TLS
 * layer. Only the primitives are compiled in.
 *
 * WHY VENDORED RATHER THAN LINKED FROM THE DISTRIBUTION
 *
 * There is no distribution package for a bare-metal ARM card. Linking
 * libmbedtls.so would give the simulator a hash and the chip nothing, and the
 * property this project rests on is that the OS is the SAME CODE on both
 * targets. Compiling the sources into both builds keeps a passing host test
 * meaningful as evidence about the card.
 */
#include "crypto/crypto.h"

#include "os/os_mem.h"

#include "mbedtls/sha256.h"

/* --------------------------------------------------------------- SHA-256 -- */
/*
 * crypto_sha256_ctx deliberately does NOT contain an mbedtls_sha256_context.
 *
 * If it did, every translation unit that hashes anything would need mbedTLS's
 * headers on its include path, and the seam would exist in name only -- the
 * dependency would just be spelled differently. So our context carries the
 * SHA-256 state in its own documented layout and this file translates.
 *
 * The cost is one memcpy of 108 bytes per operation, on a path that runs a
 * handful of times per card session. The benefit is that the day this file is
 * replaced by a driver for a hash peripheral, nothing above it recompiles for
 * a different reason than the linker.
 */

/* Compile-time proof that our context can hold mbedTLS's. A card with a
 * mismatch here would corrupt whatever follows the context in RAM, which on a
 * statically-allocated OS is another subsystem's state. */
_Static_assert(sizeof(crypto_sha256_ctx) >= sizeof(mbedtls_sha256_context),
               "crypto_sha256_ctx is too small for the backend's state");

static mbedtls_sha256_context *backend(crypto_sha256_ctx *c)
{
    /* One object, viewed two ways. Alignment is satisfied because
     * crypto_sha256_ctx leads with uint64_t/uint32_t members, which are at
     * least as strictly aligned as anything in mbedtls_sha256_context. */
    return (mbedtls_sha256_context *)(void *)c;
}

void crypto_sha256_init(crypto_sha256_ctx *c)
{
    if (c == NULL) {
        return;
    }
    os_memset(c, 0, sizeof(*c));
    mbedtls_sha256_init(backend(c));
    /* 0 = SHA-256, not SHA-224. */
    (void)mbedtls_sha256_starts(backend(c), 0);
}

void crypto_sha256_update(crypto_sha256_ctx *c, const void *data, size_t len)
{
    if (c == NULL || (data == NULL && len > 0u)) {
        return;
    }
    if (len == 0u) {
        return;
    }
    (void)mbedtls_sha256_update(backend(c), (const unsigned char *)data, len);
}

crypto_status crypto_sha256_final(crypto_sha256_ctx *c,
                                  uint8_t            out[CRYPTO_SHA256_LEN])
{
    if (c == NULL || out == NULL) {
        return CRYPTO_ERR_PARAM;
    }
    if (mbedtls_sha256_finish(backend(c), out) != 0) {
        return CRYPTO_ERR_PARAM;
    }
    /* The context held the message schedule and chaining state. Neither is the
     * secret, but both are derived from it, and there is no reason to leave
     * them in RAM after the digest is out. */
    mbedtls_sha256_free(backend(c));
    crypto_wipe(c, sizeof(*c));
    return CRYPTO_OK;
}

crypto_status crypto_sha256(const void *data, size_t len,
                            uint8_t out[CRYPTO_SHA256_LEN])
{
    if (out == NULL || (data == NULL && len > 0u)) {
        return CRYPTO_ERR_PARAM;
    }
    crypto_sha256_ctx c;
    crypto_sha256_init(&c);
    crypto_sha256_update(&c, data, len);
    return crypto_sha256_final(&c, out);
}

/* ------------------------------------------------------------ comparison -- */

bool crypto_equal_ct(const void *a, const void *b, size_t len)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;

    /*
     * Accumulate every difference, then test once. No early exit, no branch on
     * a secret byte, and the loop runs a fixed number of times for a given
     * length.
     *
     * `volatile` on the accumulator is not decoration: without it a compiler
     * is free to notice that the result is a plain OR-reduction and rewrite
     * the loop -- including into a form that exits early. That optimisation is
     * correct and it destroys the only property this function has.
     */
    volatile uint8_t diff = 0u;
    for (size_t i = 0; i < len; i++) {
        diff = (uint8_t)(diff | (uint8_t)(x[i] ^ y[i]));
    }
    return diff == 0u;
}

/* ---------------------------------------------------------------- wiping -- */

void crypto_wipe(void *p, size_t len)
{
    if (p == NULL || len == 0u) {
        return;
    }
    /*
     * The pointer is read through a volatile view so the stores cannot be
     * dropped as dead. A plain memset() here IS removed at -O2 when the buffer
     * is not read afterwards, which is the entire situation this function is
     * for -- and the reason C11 added memset_s and platforms added
     * explicit_bzero. We have neither on a freestanding target.
     */
    volatile uint8_t *v = (volatile uint8_t *)p;
    for (size_t i = 0; i < len; i++) {
        v[i] = 0u;
    }
}
