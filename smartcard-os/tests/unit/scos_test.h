/* SPDX-License-Identifier: MIT
 *
 * scos_test.h -- A ~60-line test harness.
 *
 * No framework dependency, because the thing under test is a freestanding OS
 * and the build must stay trivially portable to a cross-toolchain later.
 * Prints one line per check so a failure names itself.
 */
#ifndef SCOS_TEST_H
#define SCOS_TEST_H

#include <stdio.h>
#include <stdlib.h>

static int g_checks;
static int g_failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_checks++;                                                           \
        if (!(cond)) {                                                        \
            g_failures++;                                                     \
            (void)printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
        }                                                                     \
    } while (0)

/* Compares as 16-bit hex, because almost everything we assert is a status
 * word and "expected 9000 got 6A82" is the message you want. */
#define CHECK_HEX(actual, expected)                                          \
    do {                                                                     \
        g_checks++;                                                           \
        const unsigned long _a = (unsigned long)(actual);                     \
        const unsigned long _e = (unsigned long)(expected);                   \
        if (_a != _e) {                                                       \
            g_failures++;                                                     \
            (void)printf("  FAIL %s:%d: %s == %04lX, expected %04lX\n",       \
                         __FILE__, __LINE__, #actual, _a, _e);                \
        }                                                                     \
    } while (0)

#define CHECK_EQ(actual, expected)                                           \
    do {                                                                     \
        g_checks++;                                                           \
        const long long _a = (long long)(actual);                             \
        const long long _e = (long long)(expected);                           \
        if (_a != _e) {                                                       \
            g_failures++;                                                     \
            (void)printf("  FAIL %s:%d: %s == %lld, expected %lld\n",         \
                         __FILE__, __LINE__, #actual, _a, _e);                \
        }                                                                     \
    } while (0)

#define TEST(name) static void name(void)

#define RUN(name)                                                            \
    do {                                                                     \
        const int _before = g_failures;                                       \
        (void)printf("[ RUN  ] %s\n", #name);                                 \
        name();                                                               \
        (void)printf("[ %s ] %s\n",                                           \
                     (g_failures == _before) ? " OK " : "FAIL", #name);       \
    } while (0)

#define TEST_MAIN_END()                                                      \
    do {                                                                     \
        (void)printf("\n%d checks, %d failures\n", g_checks, g_failures);     \
        return (g_failures == 0) ? EXIT_SUCCESS : EXIT_FAILURE;               \
    } while (0)

#endif /* SCOS_TEST_H */
