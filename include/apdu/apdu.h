/* SPDX-License-Identifier: MIT
 *
 * apdu.h -- Application Protocol Data Unit structures and parser.
 *
 * An APDU is the ONLY way the outside world talks to a smart card. See
 * docs/apdu.md for the tutorial. Structurally, a command APDU is:
 *
 *     CLA INS P1 P2 [Lc] [data ... ] [Le]
 *     \_____header___/  \__ body, whose shape depends on the "case" __/
 *
 * ISO/IEC 7816-4 defines four cases, because Lc and Le are both optional:
 *
 *   Case 1   4 bytes                 no data in, no data out
 *   Case 2   5 bytes                 no data in, up to Le bytes out
 *   Case 3   5 + Lc bytes            Lc bytes in,  no data out
 *   Case 4   5 + Lc + 1 bytes        Lc bytes in,  up to Le bytes out
 *
 * The single nastiest detail in the whole protocol: at 5 bytes, byte 5 is Le
 * (a Case 2 command), NOT Lc. Lc==0 is not encodable, because a command with
 * zero data bytes is by definition Case 1 or Case 2. Getting this backwards is
 * the classic smart-card parser bug, so apdu_parse() handles it explicitly and
 * tests/unit/test_apdu_parse.c pins the behaviour.
 *
 * Second nasty detail: Le==0 means 256, not 0. "Give me as much as you have,
 * up to the maximum a short response can hold." apdu_parse() normalises this,
 * so callers see le==256 and never have to remember.
 */
#ifndef SCOS_APDU_H
#define SCOS_APDU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APDU_HEADER_LEN     4u
#define APDU_SHORT_LC_MAX 255u
#define APDU_SHORT_LE_MAX 256u

typedef enum {
    APDU_CASE_1 = 1, /* header only            */
    APDU_CASE_2 = 2, /* header + Le            */
    APDU_CASE_3 = 3, /* header + Lc + data     */
    APDU_CASE_4 = 4  /* header + Lc + data + Le*/
} apdu_case;

typedef struct {
    uint8_t  cla;
    uint8_t  ins;
    uint8_t  p1;
    uint8_t  p2;

    /* Command data field. Points INTO the caller's receive buffer -- the
     * parser copies nothing. Valid only while that buffer lives, and only if
     * lc > 0; NULL otherwise. */
    const uint8_t *data;
    uint16_t lc;         /* 0..255 for short APDUs                          */

    /* Expected response length. Only meaningful when le_present is true.
     * Already normalised: a wire value of 0x00 arrives here as 256. */
    uint16_t le;         /* 1..256                                          */
    bool     le_present;

    apdu_case acase;
} apdu_command;

typedef enum {
    APDU_PARSE_OK = 0,
    APDU_PARSE_TOO_SHORT,     /* fewer than 4 bytes: not even a header       */
    APDU_PARSE_BAD_LENGTH,    /* Lc disagrees with the bytes actually present */
    APDU_PARSE_EXTENDED       /* extended-length APDU; not supported yet      */
} apdu_parse_status;

/* Parse buf[0..len) into *out. Never writes outside *out, never reads outside
 * buf[0..len), never allocates. On failure *out is zeroed so a caller that
 * ignores the return value cannot act on stale fields. */
apdu_parse_status apdu_parse(const uint8_t *buf, uint16_t len,
                             apdu_command *out);

/* Map a parse failure onto the ISO status word we must return for it. */
uint16_t apdu_parse_status_sw(apdu_parse_status st);

/* ----------------------------------------------------------------- CLA rules */

typedef enum {
    APDU_CLA_OK = 0,             /* first interindustry, channel 0, no SM     */
    APDU_CLA_INVALID,            /* 0xFF, or a class we do not implement      */
    APDU_CLA_CHANNEL_UNSUPPORTED,/* logical channel != 0                      */
    APDU_CLA_SM_UNSUPPORTED,     /* secure messaging bits set                 */
    APDU_CLA_CHAINING_UNSUPPORTED/* command-chaining bit set                  */
} apdu_cla_status;

/* Classify CLA per ISO/IEC 7816-4 s.5.4.1. This milestone accepts only
 * CLA==0x00 and reports precisely why anything else was rejected, so the
 * status word we return is diagnostic rather than a blanket 6E00. */
apdu_cla_status apdu_check_cla(uint8_t cla);
uint16_t apdu_cla_status_sw(apdu_cla_status st);

/* --------------------------------------------------------- response builder */

/* Accumulates response data into a caller-owned buffer, then appends SW1 SW2.
 * Overflow is recorded rather than trapped: a card must answer *something*, so
 * an over-long response degrades to 6F00 instead of truncating silently. */
typedef struct {
    uint8_t *buf;
    uint16_t cap;
    uint16_t len;
    bool     overflow;
} apdu_response;

void apdu_rsp_init(apdu_response *r, uint8_t *buf, uint16_t cap);
bool apdu_rsp_put(apdu_response *r, const uint8_t *src, uint16_t n);
bool apdu_rsp_put_u8(apdu_response *r, uint8_t b);
bool apdu_rsp_put_u16(apdu_response *r, uint16_t v); /* big-endian */

/* Append SW1 SW2 and return the total response length. If data overflowed the
 * buffer, the payload is discarded and the status becomes 6F00. Reserves two
 * bytes for SW, so this cannot itself overflow when cap >= 2. */
uint16_t apdu_rsp_finish(apdu_response *r, uint16_t sw);

#endif /* SCOS_APDU_H */
