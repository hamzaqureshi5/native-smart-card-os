/* SPDX-License-Identifier: MIT
 *
 * fuzz_targets.h -- Fuzz entry points.
 *
 * Each target is one function of the libFuzzer shape:
 *
 *     int scos_fuzz_<name>(const uint8_t *data, size_t size);
 *
 * WHY THAT SHAPE, AND AN HONEST LABEL FOR WHAT WE RUN
 * --------------------------------------------------
 * This project's CI driver feeds these targets pseudo-random and
 * mutated-corpus input from a seeded generator. That is RANDOMISED STRESS
 * TESTING, not coverage-guided fuzzing: nothing measures which branches were
 * reached, so nothing steers input toward unexplored code. It finds shallow
 * bugs reliably and deep ones only by luck.
 *
 * Coverage-guided fuzzing (libFuzzer or AFL++) is strictly better and this
 * header exists so switching costs three lines -- the signature is already
 * LLVMFuzzerTestOneInput's:
 *
 *     int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
 *     { return scos_fuzz_apdu(d, n); }
 *
 * built with clang -fsanitize=fuzzer,address,undefined. It is not wired up
 * because this environment has no clang; see docs/fuzzing.md.
 *
 * THE PROPERTY EVERY TARGET ASSERTS
 * Not "the right answer" -- for random input there is no right answer. The
 * property is: NO CRASH, NO OUT-OF-BOUNDS ACCESS, NO UNDEFINED BEHAVIOUR, AND
 * ALWAYS A WELL-FORMED RESPONSE. ASan and UBSan turn a violation into a
 * non-zero exit, which is what the test harness checks.
 */
#ifndef SCOS_FUZZ_TARGETS_H
#define SCOS_FUZZ_TARGETS_H

#include <stddef.h>
#include <stdint.h>

/* Command APDU parser: the primary attack surface. */
int scos_fuzz_apdu(const uint8_t *data, size_t size);

/* BER-TLV parser, including descent into constructed objects. */
int scos_fuzz_tlv(const uint8_t *data, size_t size);

/* The whole command surface: input goes to scos_process() against a live
 * filesystem, so parser, dispatcher, handlers and NVM are all in scope. */
int scos_fuzz_command(const uint8_t *data, size_t size);

/* Filesystem metadata: the input is written over the descriptor table as raw
 * NVM, then the card is mounted and navigated. Models corrupted persistent
 * storage rather than a hostile reader. */
int scos_fuzz_fs_image(const uint8_t *data, size_t size);

#endif /* SCOS_FUZZ_TARGETS_H */
