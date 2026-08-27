/* SPDX-License-Identifier: MIT
 *
 * transport.c -- The reader-side link, implemented over stdin/stdout.
 *
 * This provides hal_card_receive() / hal_card_send() / hal_card_atr().
 *
 * WHAT IS NOT HERE, ON PURPOSE
 * ----------------------------
 * Real ISO/IEC 7816-3 T=0 is a half-duplex character protocol: the card echoes
 * a procedure byte per data byte, there are guard times, parity, and a NAK/retry
 * mechanism. T=1 is block-oriented with an epilogue checksum. Implementing
 * either buys us nothing right now -- they carry the same APDU either way, and
 * the OS above hal_card_* cannot tell the difference by design.
 *
 * So the simulator uses a line-oriented ASCII hex protocol, which has one large
 * advantage: a human can drive the card by typing, and a Python test can drive
 * it with two lines of code.
 *
 *   -> "00A40000023F00"    a command APDU, hex, whitespace ignored
 *   <- "9000"              the response APDU, hex
 *
 * Lines starting with '.' are simulator control, not card traffic. They model
 * things the reader does to the card electrically, which have no APDU:
 *
 *   .atr        print the ATR                     (reader reads it at power-up)
 *   .reset      warm reset                        (RST line asserted)
 *   .quit       power down and exit
 *   .help       list commands
 *   #...        comment, ignored
 *
 * Responses go to STDOUT; the banner, prompts and errors go to STDERR. The
 * split is what lets a test client read stdout as a pure response stream.
 */
#include "hal/hal.h"
#include "hal/sim/vcard.h"

#include <stdio.h>
#include <string.h>

/* Generous: 261 command bytes is 522 hex characters, plus whitespace. */
#define LINE_MAX 2048

static int hex_nibble(int ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

/* Decode ASCII hex, ignoring whitespace and ':' separators.
 * Returns the byte count, or -1 on a bad character / odd digit count /
 * overflow of the destination. */
static long hex_decode(const char *in, uint8_t *out, uint32_t cap)
{
    uint32_t n  = 0u;
    int      hi = -1;

    for (const char *p = in; *p != '\0'; p++) {
        const char ch = *p;
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ':') {
            continue;
        }
        const int v = hex_nibble((unsigned char)ch);
        if (v < 0) {
            return -1;
        }
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= cap) {
                return -1; /* would overflow: reject, never truncate */
            }
            out[n++] = (uint8_t)((hi << 4) | v);
            hi       = -1;
        }
    }
    if (hi >= 0) {
        return -1; /* odd number of hex digits */
    }
    return (long)n;
}

static void print_atr(void)
{
    uint32_t       len = 0u;
    const uint8_t *atr = vcard_atr(&len);
    for (uint32_t i = 0; i < len; i++) {
        (void)printf("%02X", atr[i]);
    }
    (void)printf("\n");
    (void)fflush(stdout);
}

static void print_help(void)
{
    (void)fprintf(stderr,
                  "Send an APDU as hex, e.g.  00 A4 00 00 02 3F 00\n"
                  "Control lines:\n"
                  "  .atr     print the Answer To Reset\n"
                  "  .reset   warm reset (clears volatile state, keeps NVM)\n"
                  "  .quit    power down and exit\n"
                  "  .help    this text\n"
                  "  #...     comment\n");
    (void)fflush(stderr);
}

/* Handle a control line.
 *   1  handled, keep waiting
 *   0  not a control line -- it is card traffic
 *  -1  the caller should shut down
 *  -2  the reader reset the card
 *
 * Note what this function does NOT do: call into the OS. The transport is
 * below the OS in the layering, so a reset is REPORTED upward and acted on by
 * scos_card_loop(). An earlier version called scos_reset() directly from here
 * and created a circular link dependency between the OS and the HAL -- the
 * linker caught it. */
static int handle_control(const char *line)
{
    if (line[0] == '#') {
        return 1;
    }
    if (line[0] != '.') {
        return 0;
    }
    if (strcmp(line, ".quit") == 0 || strcmp(line, ".exit") == 0) {
        return -1;
    }
    if (strcmp(line, ".atr") == 0) {
        print_atr();
        return 1;
    }
    if (strcmp(line, ".reset") == 0) {
        hal_reset();
        /* Per ISO 7816-3 a reset is answered by the ATR, and emitting it is
         * the LINK's job -- on real silicon the interface block clocks it out
         * before any OS code runs. */
        print_atr();
        return -2;
    }
    if (strcmp(line, ".help") == 0) {
        print_help();
        return 1;
    }
    (void)fprintf(stderr, "unknown control '%s' (try .help)\n", line);
    (void)fflush(stderr);
    return 1;
}

static void trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0u && (s[n - 1u] == '\n' || s[n - 1u] == '\r' ||
                      s[n - 1u] == ' ' || s[n - 1u] == '\t')) {
        s[--n] = '\0';
    }
}

hal_status hal_card_receive(uint8_t *buf, uint32_t cap, uint32_t *out_len)
{
    if (buf == NULL || out_len == NULL || cap == 0u) {
        return HAL_ERR_PARAM;
    }
    *out_len = 0u;

    char line[LINE_MAX];

    for (;;) {
        if (fgets(line, (int)sizeof(line), stdin) == NULL) {
            /* EOF: the reader is gone. On real hardware this is the card
             * being pulled out of the slot / moving out of the RF field. */
            return HAL_ERR_LINK_DOWN;
        }
        trim(line);
        if (line[0] == '\0') {
            continue;
        }

        const int ctl = handle_control(line);
        if (ctl == -1) {
            return HAL_ERR_LINK_DOWN;
        }
        if (ctl == -2) {
            return HAL_CARD_RESET;
        }
        if (ctl > 0) {
            continue;
        }

        const long n = hex_decode(line, buf, cap);
        if (n < 0) {
            /*
             * A malformed hex line is a TRANSPORT error, not a card error. On
             * real hardware the link layer would NAK it and the OS would never
             * see it -- so we must not hand it to the OS as an APDU, and we
             * must not answer with a status word either, because that would
             * teach the test client that garbage input produces 6700 from the
             * card. Report on stderr and wait for the next line.
             */
            (void)fprintf(stderr, "transport: not valid hex (or too long)\n");
            (void)fflush(stderr);
            continue;
        }

        *out_len = (uint32_t)n;
        return HAL_OK;
    }
}

hal_status hal_card_send(const uint8_t *buf, uint32_t len)
{
    if (buf == NULL && len > 0u) {
        return HAL_ERR_PARAM;
    }
    for (uint32_t i = 0; i < len; i++) {
        (void)printf("%02X", buf[i]);
    }
    (void)printf("\n");
    if (fflush(stdout) != 0) {
        return HAL_ERR_IO;
    }
    return HAL_OK;
}

const uint8_t *hal_card_atr(uint32_t *out_len)
{ return vcard_atr(out_len); }
