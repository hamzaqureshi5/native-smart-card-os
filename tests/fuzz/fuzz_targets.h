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
#include <stdio.h>
#include <stdlib.h>

/*
 * FUZZ_CHECK -- an invariant that holds in EVERY build.
 *
 * Deliberately not assert(). Release defines NDEBUG, which compiles assert()
 * to nothing, so a fuzz target written with assert() still runs at -O2 and
 * still reports success while checking absolutely nothing. That is worse than
 * not running it: it is a green result that means nothing.
 *
 * It was not a hypothetical. Before tools/build.sh existed, no build used
 * -O2, so the Release configuration had never been compiled -- and when it
 * finally was, the only symptom was four unused-variable errors from
 * variables that existed solely to feed an assert. The errors were the lucky
 * part; without -Werror the build would have succeeded and the invariants
 * would have silently vanished.
 */
#define FUZZ_CHECK(cond)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            (void)fprintf(stderr, "FUZZ_CHECK failed: %s\n  at %s:%d in %s\n", \
                          #cond, __FILE__, __LINE__, __func__);                \
            abort();                                                           \
        }                                                                      \
    } while (0)

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

/* The boot loader, driven as a SEQUENCE of length-prefixed commands so that
 * ordering bugs are reachable. Asserts that an ACTIVE slot can never be a lie.
 * Highest-value target in the set: this code ships in unpatchable mask ROM. */
int scos_fuzz_boot(const uint8_t *data, size_t size);

/* CREATE FILE / DELETE FILE, with templates biased toward PARSING so the
 * mutating paths are actually reached -- fuzz_command emits INS E0 but its
 * random templates never form a valid FCP. Checks tree invariants rather than
 * status words: no overlapping EF data, no orphans, no duplicate FID or SFI
 * within a parent. */
int scos_fuzz_fcp(const uint8_t *data, size_t size);

#endif /* SCOS_FUZZ_TARGETS_H */
