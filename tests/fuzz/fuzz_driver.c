/* SPDX-License-Identifier: MIT
 *
 * fuzz_driver.c -- Standalone driver for the fuzz targets.
 *
 *   fuzz_driver <target> [iterations] [seed]
 *   fuzz_driver <target> --file <path>       replay one input
 *
 * WHAT THIS IS, STATED PLAINLY
 * It generates input three ways -- a fixed list of hostile cases, structured
 * near-valid APDUs/TLVs, and pseudo-random bytes -- and feeds them to a target.
 * There is NO COVERAGE FEEDBACK, so it cannot steer toward unexplored branches.
 * It is randomised stress testing. Coverage-guided fuzzing would be better and
 * is three lines away; see tests/fuzz/fuzz_targets.h and docs/fuzzing.md.
 *
 * A failure shows up as an ASan/UBSan abort or a __builtin_trap in the target,
 * both of which kill the process -- so "exit 0" is the pass condition, and the
 * seed printed at startup makes any failure reproducible.
 */
#include "fuzz_targets.h"

#include "os/scos_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- corpus -- */

/*
 * The cases from the project brief, section 23: empty, truncated, huge Lc,
 * huge Le, invalid CLA/INS, malformed data, integer-overflow shapes. These run
 * first and every time, because a random generator reaches them only by
 * accident and they are exactly the inputs that have historically broken card
 * parsers.
 */
static const char *const k_corpus[] = {
    /* empty and truncated */
    "",
    "00",
    "0000",
    "000000",
    /* bare headers */
    "00A40000",
    "FFFFFFFF",
    "00000000",
    "FFFFFF00",
    /* huge Lc with no data */
    "00A40000FF",
    "00D60000FF",
    "00A4000080",
    /* Lc claiming more than present */
    "00A40000FF3F00",
    "00A400000A3F00",
    "00D60000FF0102",
    /* huge Le */
    "00B0000000",
    "00B00000FF",
    "00A4000002 3F00 00",
    /* extended-length shapes */
    "00A400000000023F00",
    "00A40000000000",
    "00A4000000FFFF",
    "00B0000000000000",
    "00A400000001",
    /* invalid CLA / INS */
    "FFA40000",
    "80EE0000",
    "0CA40000",
    "10A40000",
    "01A40000",
    /* TLV: truncated, indefinite, oversized, deep nesting */
    "62",
    "6205",
    "620582",
    "62058201",
    "3080820138 0000",
    "80FF01",
    "808301 0000",
    "5F",
    "5F812D01AA",
    "62 04 62 02 62 00",
    "62 06 62 04 62 02 62 00",
    /* all-padding and erased NVM */
    "FFFFFFFFFFFFFFFF",
    "0000000000000000",
    /* maximum-length short APDU boundary (Lc=255, with and without Le) */
    "00D60000FF" /* + filled below */,
};

/* ------------------------------------------------------------ generators -- */

/* xorshift64*, seeded, so every run is reproducible from the printed seed. */
static uint64_t s_state;

static uint64_t rnd(void)
{
    uint64_t x = s_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    s_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static uint32_t rnd_below(uint32_t n)
{ return (n == 0u) ? 0u : (uint32_t)(rnd() % (uint64_t)n); }

static size_t gen_random(uint8_t *buf, size_t cap)
{
    const size_t n = (size_t)rnd_below((uint32_t)cap + 1u);
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(rnd() & 0xFFu);
    }
    return n;
}

/*
 * Structured generation: build something that is nearly a valid APDU, then
 * corrupt one field. Purely random bytes almost never form a parseable APDU,
 * so without this the deeper code paths are never reached at all.
 */
static size_t gen_apdu_like(uint8_t *buf, size_t cap)
{
    if (cap < 6u) {
        return gen_random(buf, cap);
    }
    static const uint8_t inst[] = { 0xA4, 0xB0, 0xD6, 0xC0, 0x20, 0xCA,
                                    0xE0, 0xE4, 0x50, 0x54, 0xEE };
    buf[0] = (rnd_below(4u) == 0u) ? (uint8_t)(rnd() & 0xFFu) : 0x00u;
    buf[1] = inst[rnd_below((uint32_t)sizeof(inst))];
    buf[2] = (uint8_t)(rnd() & 0xFFu);
    buf[3] = (uint8_t)(rnd() & 0xFFu);

    const uint32_t lc = rnd_below(258u); /* deliberately can exceed 255 */
    buf[4]            = (uint8_t)lc;

    size_t n = 5u;
    /* Write a data field whose real length often DISAGREES with Lc -- the
     * mismatch is the bug class we care about. */
    uint32_t actual = lc;
    switch (rnd_below(4u)) {
    case 0:
        break; /* consistent */
    case 1:
        actual = (lc > 0u) ? lc - 1u : 0u;
        break; /* one short   */
    case 2:
        actual = lc + 1u;
        break; /* one long    */
    default:
        actual = rnd_below(262u);
        break; /* unrelated   */
    }
    for (uint32_t i = 0; i < actual && n < cap; i++) {
        buf[n++] = (uint8_t)(rnd() & 0xFFu);
    }
    if (rnd_below(2u) == 0u && n < cap) {
        buf[n++] = (uint8_t)(rnd() & 0xFFu); /* an Le byte */
    }
    return n;
}

/*
 * Extended-form APDUs: header, a zero introducer, then a 16-bit big-endian
 * length field.
 *
 * gen_apdu_like above can never produce this shape -- it writes Lc as one byte
 * at buf[4] -- so without a generator of its own the extended path gets only
 * the handful of fixed corpus entries. That is not enough for a second
 * untrusted-length parser.
 *
 * The declared length is drawn to land ON the interesting boundaries rather
 * than uniformly, because a uniform draw over 0..65535 would essentially never
 * hit the ceiling, the ceiling plus one, or a length that agrees with the
 * frame -- and those are the only values where the code branches.
 */
static size_t gen_ext_apdu_like(uint8_t *buf, size_t cap)
{
    if (cap < 8u) {
        return gen_random(buf, cap);
    }
    static const uint8_t inst[] = { 0xA4, 0xB0, 0xD6, 0xC0, 0xE0, 0xE4, 0xEE };

    buf[0] = (rnd_below(4u) == 0u) ? (uint8_t)(rnd() & 0xFFu) : 0x00u;
    buf[1] = inst[rnd_below((uint32_t)sizeof(inst))];
    buf[2] = (uint8_t)(rnd() & 0xFFu);
    buf[3] = (uint8_t)(rnd() & 0xFFu);
    buf[4] = 0x00; /* the extended introducer */

    /* The declared 16-bit length, biased onto the boundaries. */
    uint32_t declared;
    switch (rnd_below(8u)) {
    case 0:
        declared = 0u; /* not encodable as Lc; means 65536 as Le */
        break;
    case 1:
        declared = 1u;
        break;
    case 2:
        declared = SCOS_APDU_EXT_DATA_MAX; /* exactly the ceiling  */
        break;
    case 3:
        declared = SCOS_APDU_EXT_DATA_MAX + 1u; /* one over        */
        break;
    case 4:
        declared = 0xFFFFu; /* the ISO maximum      */
        break;
    case 5:
        declared = rnd_below(SCOS_APDU_EXT_DATA_MAX + 4u);
        break;
    default:
        declared = rnd_below(0x10000u);
        break;
    }
    buf[5] = (uint8_t)(declared >> 8);
    buf[6] = (uint8_t)(declared & 0xFFu);

    size_t n = 7u;

    /*
     * How many body bytes actually follow. The disagreement between declared
     * and actual is the bug class: a parser that trusts the declared length
     * reads past the frame, and one that trusts the frame accepts a command it
     * never validated.
     */
    uint32_t actual;
    switch (rnd_below(5u)) {
    case 0:
        actual = declared; /* consistent -> a valid Case 3E   */
        break;
    case 1:
        actual = declared + 2u; /* consistent -> a valid Case 4E   */
        break;
    case 2:
        actual = (declared > 0u) ? declared - 1u : 0u;
        break;
    case 3:
        actual = declared + 1u;
        break;
    default:
        actual = rnd_below(64u);
        break;
    }

    for (uint32_t i = 0; i < actual && n < cap; i++) {
        buf[n++] = (uint8_t)(rnd() & 0xFFu);
    }
    return n;
}

/* Near-valid TLV, with one field corrupted. */
static size_t gen_tlv_like(uint8_t *buf, size_t cap)
{
    if (cap < 8u) {
        return gen_random(buf, cap);
    }
    size_t         n       = 0u;
    const unsigned objects = 1u + rnd_below(4u);

    for (unsigned o = 0; o < objects && n + 4u < cap; o++) {
        static const uint8_t tags[] = { 0x80, 0x82, 0x83, 0x8A, 0x88, 0x62,
                                        0x6F, 0x5F, 0x30, 0xA5, 0x1F, 0xFF };
        buf[n++]                    = tags[rnd_below((uint32_t)sizeof(tags))];
        if ((buf[n - 1u] & 0x1Fu) == 0x1Fu && n < cap) {
            buf[n++] = (uint8_t)(rnd() & 0xFFu); /* tag continuation */
        }
        if (n >= cap) {
            break;
        }

        /* Length: short, long, indefinite, or reserved -- all four forms. */
        uint32_t claimed;
        switch (rnd_below(4u)) {
        case 0:
            claimed  = rnd_below(0x80u);
            buf[n++] = (uint8_t)claimed;
            break;
        case 1:
            buf[n++] = 0x81u;
            claimed  = rnd_below(256u);
            if (n < cap) {
                buf[n++] = (uint8_t)claimed;
            }
            break;
        case 2:
            buf[n++] = 0x82u;
            claimed  = rnd_below(0x10000u);
            if (n < cap) {
                buf[n++] = (uint8_t)(claimed >> 8);
            }
            if (n < cap) {
                buf[n++] = (uint8_t)(claimed & 0xFFu);
            }
            break;
        default:
            buf[n++] = (rnd_below(2u) == 0u) ? 0x80u : 0xFFu; /* illegal */
            claimed  = rnd_below(16u);
            break;
        }

        /* Again: the bytes actually present usually disagree with the claim. */
        const uint32_t actual =
            (rnd_below(3u) == 0u) ? claimed : rnd_below(64u);
        for (uint32_t i = 0; i < actual && n < cap; i++) {
            buf[n++] = (uint8_t)(rnd() & 0xFFu);
        }
    }
    return n;
}

/* ------------------------------------------------------------------ main -- */

typedef int (*fuzz_fn)(const uint8_t *, size_t);

static fuzz_fn pick_target(const char *name)
{
    if (strcmp(name, "apdu") == 0) {
        return scos_fuzz_apdu;
    }
    if (strcmp(name, "tlv") == 0) {
        return scos_fuzz_tlv;
    }
    if (strcmp(name, "command") == 0) {
        return scos_fuzz_command;
    }
    if (strcmp(name, "fs_image") == 0) {
        return scos_fuzz_fs_image;
    }
    if (strcmp(name, "boot") == 0) {
        return scos_fuzz_boot;
    }
    if (strcmp(name, "fcp") == 0) {
        return scos_fuzz_fcp;
    }
    return NULL;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t cap, size_t *n)
{
    size_t k  = 0u;
    int    hi = -1;
    for (const char *p = hex; *p != '\0'; p++) {
        int v;
        if (*p >= '0' && *p <= '9') {
            v = *p - '0';
        } else if (*p >= 'A' && *p <= 'F') {
            v = *p - 'A' + 10;
        } else if (*p >= 'a' && *p <= 'f') {
            v = *p - 'a' + 10;
        } else if (*p == ' ') {
            continue;
        } else {
            return -1;
        }
        if (hi < 0) {
            hi = v;
        } else {
            if (k >= cap) {
                return -1;
            }
            out[k++] = (uint8_t)((hi << 4) | v);
            hi       = -1;
        }
    }
    if (hi >= 0) {
        return -1;
    }
    *n = k;
    return 0;
}

/*
 * Must exceed the largest APDU the card will accept, or the boundary itself is
 * never fuzzed. SCOS_APDU_CMD_MAX is header + 3-byte Lc + data + 2-byte Le;
 * the slack lets the driver hand over frames that are deliberately too long.
 */
#define BUF_MAX (SCOS_APDU_CMD_MAX + 64u)

int main(int argc, char **argv)
{
    if (argc < 2) {
        (void)fprintf(
            stderr,
            "usage: %s <apdu|tlv|command|fs_image> [iterations] [seed]\n"
            "       %s <target> --file <path>\n",
            argv[0], argv[0]);
        return 2;
    }
    const fuzz_fn target = pick_target(argv[1]);
    if (target == NULL) {
        (void)fprintf(stderr, "%s: unknown target '%s'\n", argv[0], argv[1]);
        return 2;
    }

    static uint8_t buf[BUF_MAX];

    /* Replay mode: run one input from a file, for reproducing a finding. */
    if (argc >= 4 && strcmp(argv[2], "--file") == 0) {
        FILE *f = fopen(argv[3], "rb");
        if (f == NULL) {
            (void)fprintf(stderr, "%s: cannot open %s\n", argv[0], argv[3]);
            return 2;
        }
        const size_t n = fread(buf, 1u, sizeof(buf), f);
        (void)fclose(f);
        (void)target(buf, n);
        (void)printf("replayed %zu bytes from %s: no crash\n", n, argv[3]);
        return 0;
    }

    unsigned long iterations =
        (argc >= 3) ? strtoul(argv[2], NULL, 0) : 20000ul;
    unsigned long seed = (argc >= 4) ? strtoul(argv[3], NULL, 0) : 1ul;
    s_state            = (seed == 0ul) ? 1ull : (uint64_t)seed;

    (void)printf("fuzz target=%s iterations=%lu seed=%lu\n", argv[1],
                 iterations, seed);

    /* 1. The fixed hostile corpus, always, first. */
    unsigned corpus_run = 0u;
    for (unsigned i = 0; i < sizeof(k_corpus) / sizeof(k_corpus[0]); i++) {
        size_t n = 0u;
        if (hex_to_bytes(k_corpus[i], buf, sizeof(buf), &n) != 0) {
            continue; /* the padded entry; skip rather than guess */
        }
        (void)target(buf, n);
        corpus_run++;
    }

    /* The maximum-length short APDU, both cases, built rather than typed. */
    buf[0] = 0x00;
    buf[1] = 0xD6;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0xFF;
    for (unsigned i = 5; i < 260u; i++) {
        buf[i] = (uint8_t)i;
    }
    (void)target(buf, 260u); /* Case 3: 4+1+255      */
    buf[260] = 0x00;
    (void)target(buf, 261u); /* Case 4: 4+1+255+1    */
    (void)target(buf, 262u); /* one byte too many    */
    corpus_run += 3u;

    /*
     * The maximum-length EXTENDED APDU, and the frames either side of it.
     * Built, never typed: at 1033 bytes a hand-written hex string is not
     * reviewable, and the three lengths here are exactly where an off-by-one
     * in the ceiling check would show.
     */
    {
        const uint32_t lc = SCOS_APDU_EXT_DATA_MAX;
        buf[0]            = 0x00;
        buf[1]            = 0xD6;
        buf[2]            = 0x00;
        buf[3]            = 0x00;
        buf[4]            = 0x00;
        buf[5]            = (uint8_t)(lc >> 8);
        buf[6]            = (uint8_t)(lc & 0xFFu);
        for (uint32_t i = 0; i < lc; i++) {
            buf[7u + i] = (uint8_t)(i & 0xFFu);
        }
        (void)target(buf, 7u + lc); /* Case 3E at the ceiling  */
        buf[7u + lc] = 0x00;
        buf[8u + lc] = 0x00;
        (void)target(buf, 9u + lc);      /* Case 4E at the ceiling  */
        (void)target(buf, 7u + lc - 1u); /* one data byte short     */
        (void)target(buf, 8u + lc);      /* neither 3E nor 4E       */

        /* And a declared length one byte OVER the ceiling, which must be
         * refused by the ceiling check rather than by running out of frame. */
        const uint32_t over = SCOS_APDU_EXT_DATA_MAX + 1u;
        buf[5]              = (uint8_t)(over >> 8);
        buf[6]              = (uint8_t)(over & 0xFFu);
        (void)target(buf, 7u + lc);
        corpus_run += 5u;
    }

    /* 2. Structured and random generation. */
    for (unsigned long it = 0; it < iterations; it++) {
        size_t n;
        switch (it % 4ul) {
        case 0:
            n = gen_apdu_like(buf, sizeof(buf));
            break;
        case 1:
            n = gen_tlv_like(buf, sizeof(buf));
            break;
        case 2:
            n = gen_ext_apdu_like(buf, sizeof(buf));
            break;
        default:
            n = gen_random(buf, sizeof(buf));
            break;
        }
        (void)target(buf, n);
    }

    (void)printf("ok: %u corpus cases + %lu generated inputs, no crash\n",
                 corpus_run, iterations);
    return 0;
}
