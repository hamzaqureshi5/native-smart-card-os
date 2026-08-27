/* SPDX-License-Identifier: MIT
 *
 * scos_mbedtls_config.h -- mbedTLS configuration for a smart card.
 *
 * mbedTLS ships with a default config aimed at TLS on a hosted system. Almost
 * none of that belongs on a card, and the things it assumes -- a heap, a
 * filesystem, a clock, sockets, an operating system -- are exactly the things
 * include/hal/hal.h exists to keep out of the OS.
 *
 * So this file enables the primitives and NOTHING else. It is not a
 * minimisation for its own sake:
 *
 *   - MBEDTLS_PLATFORM_MEMORY / calloc: OFF. There is no heap. The OS is
 *     statically allocated by design, and the _Static_assert in
 *     include/os/kernel.h is what keeps its footprint honest -- a library that
 *     allocated would make that measurement a fiction.
 *   - MBEDTLS_FS_IO: OFF. src/hal exists precisely so nothing above it touches
 *     a file. tests/integration/check_core_deps.cmake enforces that with `nm`.
 *   - MBEDTLS_HAVE_TIME / TIME_DATE: OFF. The chip has no clock.
 *   - MBEDTLS_ENTROPY / CTR_DRBG: OFF. Entropy comes from the platform TRNG
 *     through hal_random_bytes(), and crypto_random_bytes() refuses rather
 *     than falling back to a software PRNG. Enabling mbedTLS's own entropy
 *     stack would give it a second, weaker path to the same job.
 *   - MBEDTLS_SELF_TEST: OFF. Our own known-answer tests use the NIST FIPS
 *     180-4 vectors directly and the Python suite cross-checks against
 *     hashlib, so validation comes from outside the library rather than from
 *     the library's opinion of itself.
 *
 * What IS enabled is the minimum M3 needs. M5 will add AES and ECC here, and
 * that is the intended way to grow this file: one primitive at a time, with a
 * reason.
 */
#ifndef SCOS_MBEDTLS_CONFIG_H
#define SCOS_MBEDTLS_CONFIG_H

/* --- the primitives we actually use ------------------------------------- */

#define MBEDTLS_SHA256_C

/* --- deliberate exclusions, stated rather than merely absent ------------ */
/*
 * Everything below is OFF. Listing it matters: a future reader comparing this
 * against mbedtls_config.h should be able to tell "considered and rejected"
 * from "not yet looked at".
 *
 *   MBEDTLS_PLATFORM_C           no heap, no printf, no exit
 *   MBEDTLS_FS_IO                no filesystem on a card
 *   MBEDTLS_HAVE_TIME            no clock
 *   MBEDTLS_ENTROPY_C            entropy is the HAL's job
 *   MBEDTLS_CTR_DRBG_C           ditto
 *   MBEDTLS_SELF_TEST            we test from outside
 *   MBEDTLS_SSL_*                there is no network
 *   MBEDTLS_X509_*               no certificates until M5 at the earliest
 *   MBEDTLS_PSA_CRYPTO_C         a second API surface we do not need
 *   MBEDTLS_THREADING_C          single-threaded by construction
 */

/*
 * No platform layer at all: mbedTLS must not reach for malloc, printf, exit,
 * time or a filesystem, and this is what makes that a build error rather than
 * a runtime surprise.
 */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

/*
 * Smaller code at a small speed cost. On a 14 MHz core with a 32 KB ROM budget
 * that is the right trade for a hash that runs a handful of times per session;
 * the OS is 18 KB of 32 KB and the boot ROM is at 94% of its 8 KB.
 */
#define MBEDTLS_SHA256_SMALLER

#endif /* SCOS_MBEDTLS_CONFIG_H */
