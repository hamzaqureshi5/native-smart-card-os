/* SPDX-License-Identifier: MIT
 *
 * hal_arm_io.c -- SCV1 card I/O over UART0.
 *
 * Real memory-mapped peripheral access: every byte in and out of the card goes
 * through the UART data register. Deliberately NOT semihosting -- semihosting
 * would be a debugger service, whereas this is the sort of driver a real port
 * has to write.
 *
 * The wire format is the same line-oriented hex protocol the native simulator
 * uses, which is the point: the identical Python test suite drives both, so the
 * tests become a conformance suite for the port rather than something that has
 * to be rewritten for it.
 */
#include "hal/hal.h"
#include "scv1.h"
#include "scv1_internal.h"

static bool s_initialised = false;
#include "semihost.h"

/* --------------------------------------------------------------- driver --- */

/* Must run before ANY output. The banner is printed before the first
 * hal_card_receive(), so initialising lazily inside the receive path left the
 * peripheral disabled and the banner went nowhere. hal_init() calls this. */
void scv1_uart_init(void)
{
    SCV1_UART_BAUDDIV = 16u; /* minimum legal divisor; timing is not modelled */
    SCV1_UART_CTRL    = SCV1_UART_CTRL_TX_EN | SCV1_UART_CTRL_RX_EN;
    s_initialised     = true;
}

static void uart_putc(char c)
{
    while ((SCV1_UART_STATE & SCV1_UART_STATE_TX_FULL) != 0u) {}
    SCV1_UART_DATA = (uint32_t)(unsigned char)c;
}

/* Blocking. A card has nothing else to do: it is powered by the reader and
 * exists to answer. Polling rather than interrupt-driven because there is no
 * concurrency to gain -- see docs/architecture.md. */
static int uart_getc(void)
{
    while ((SCV1_UART_STATE & SCV1_UART_STATE_RX_FULL) == 0u) {}
    return (int)(SCV1_UART_DATA & 0xFFu);
}

void scv1_uart_puts(const char *s)
{
    while (*s != '\0') {
        uart_putc(*s++);
    }
}

/* ------------------------------------------------------------- hex codec -- */

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

static void put_hex_byte(uint8_t b)
{
    static const char digits[] = "0123456789ABCDEF";
    uart_putc(digits[(b >> 4) & 0x0Fu]);
    uart_putc(digits[b & 0x0Fu]);
}

/* --------------------------------------------------------------- ATR ----- */

/*
 * The ATR is NOT defined here. It is supplied by whichever program is linked
 * against this transport -- the OS defines one, the boot loader another.
 *
 * That indirection is the mechanism behind a question worth being precise
 * about: does the ATR change when you load an OS? ISO/IEC 7816-3 does not
 * require it to. What actually happens on this chip is that a blank part runs
 * the boot loader, which answers with its own ATR, and a programmed part runs
 * the OS, which answers with the OS's. The bytes differ because DIFFERENT
 * CODE IS ANSWERING, not because loading an image rewrites an ATR somewhere.
 *
 * The rest of the caveat still stands: on real silicon the ATR is clocked out
 * by the interface block before any application code runs, and its interface
 * bytes must be derived from the actual clock and guard times. Documented
 * byte-by-byte in docs/simulator.md.
 */
extern const uint8_t  scv1_atr_bytes[];
extern const uint32_t scv1_atr_len;

const uint8_t *hal_card_atr(uint32_t *out_len)
{
    if (out_len != NULL) {
        *out_len = scv1_atr_len;
    }
    return scv1_atr_bytes;
}

static void send_atr(void)
{
    for (uint32_t i = 0; i < scv1_atr_len; i++) {
        put_hex_byte(scv1_atr_bytes[i]);
    }
    uart_putc('\n');
}

/* ------------------------------------------------------------ transport --- */

hal_status hal_card_receive(uint8_t *buf, uint32_t cap, uint32_t *out_len)
{
    if (buf == NULL || out_len == NULL || cap == 0u) {
        return HAL_ERR_PARAM;
    }
    *out_len = 0u;

    if (!s_initialised) {
        scv1_uart_init();
    }

    for (;;) {
        /* Collect one line. Decoding happens as bytes arrive so no separate
         * line buffer is needed beyond bounds tracking -- RAM is 16 KB. */
        uint32_t n          = 0u;
        int      hi         = -1;
        bool     bad        = false;
        uint32_t seen       = 0u;
        char     first      = '\0';
        bool     is_control = false;
        char     control[16];
        uint32_t clen = 0u;

        for (;;) {
            const int c = uart_getc();
            if (c < 0) {
                return HAL_ERR_LINK_DOWN;
            }
            if (c == '\n' || c == '\r') {
                break;
            }
            if (seen == 0u) {
                first      = (char)c;
                is_control = (first == '.' || first == '#');
            }
            seen++;

            if (is_control) {
                if (clen < sizeof(control) - 1u) {
                    control[clen++] = (char)c;
                }
                continue;
            }
            if (c == ' ' || c == '\t' || c == ':') {
                continue;
            }
            const int v = hex_nibble(c);
            if (v < 0) {
                bad = true;
                continue;
            }
            if (hi < 0) {
                hi = v;
            } else {
                if (n >= cap) {
                    bad = true;
                } else {
                    buf[n++] = (uint8_t)((hi << 4) | v);
                }
                hi = -1;
            }
        }

        if (seen == 0u) {
            continue; /* blank line */
        }

        if (is_control) {
            control[clen] = '\0';
            if (control[0] == '#') {
                continue;
            }
            /* Minimal string compares; no libc on this target. */
            if (control[1] == 'q') { /* .quit */
                return HAL_ERR_LINK_DOWN;
            }
            if (control[1] == 'a') { /* .atr */
                send_atr();
                continue;
            }
            if (control[1] == 'r') { /* .reset */
                /* The link answers a reset with the ATR -- that is the
                 * interface block's job on real silicon, not the OS's. The OS
                 * is told via HAL_CARD_RESET and clears its volatile state. */
                send_atr();
                return HAL_CARD_RESET;
            }
            scv1_uart_puts("transport: unknown control\n");
            continue;
        }

        if (n == 0u && !bad && hi < 0) {
            /* A line of nothing but whitespace or separators. It is not an
             * APDU, and handing the OS a zero-length command would make it
             * answer 6700 -- teaching a client that blank input is a card
             * error. Wait for the next line instead. */
            continue;
        }

        if (bad || hi >= 0) {
            /* A malformed frame is a TRANSPORT error. On real hardware the link
             * layer would reject it and the OS would never see it, so we must
             * not hand it up as an APDU nor answer it with a status word. */
            scv1_uart_puts("transport: not valid hex (or too long)\n");
            continue;
        }

        *out_len = n;
        return HAL_OK;
    }
}

hal_status hal_card_send(const uint8_t *buf, uint32_t len)
{
    if (buf == NULL && len > 0u) {
        return HAL_ERR_PARAM;
    }
    for (uint32_t i = 0; i < len; i++) {
        put_hex_byte(buf[i]);
    }
    uart_putc('\n');
    return HAL_OK;
}
