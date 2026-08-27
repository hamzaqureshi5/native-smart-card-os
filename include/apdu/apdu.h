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
 *
 * EXTENDED LENGTH
 *
 * The short form caps Lc at 255 and Le at 256. ISO/IEC 7816-4 s.5.1 adds an
 * extended form, introduced by a FIRST LENGTH BYTE OF ZERO when more bytes
 * follow it:
 *
 *   Case 2E   CLA INS P1 P2 00 Le1 Le2                       7 bytes
 *   Case 3E   CLA INS P1 P2 00 Lc1 Lc2 <data>                7 + Lc
 *   Case 4E   CLA INS P1 P2 00 Lc1 Lc2 <data> Le1 Le2        9 + Lc
 *
 * There is no Case 1E: a header-only command is four bytes in both forms.
 *
 * The zero-byte introducer is the same trick as the short form's fifth-byte
 * ambiguity, one level up, and it is resolved the same way -- by total length:
 *
 *   len == 5   the byte is a short Le (Le=256). NOT extended: the extended
 *              form needs three bytes for its length field and there is only
 *              one byte here.
 *   len == 6   nothing legal. 00 introduces a 3-byte field and only two
 *              bytes follow. 6700.
 *   len == 7   Case 2E.
 *   len >= 8   Lc comes from bytes 5..6, and exactly one of 7+Lc (Case 3E) or
 *              9+Lc (Case 4E) can equal len, so the case is determined.
 *
 * Extended Le of 0x0000 means 65536, mirroring the short form's 0 meaning 256.
 * That is why le is uint32_t: 65536 does not fit in the uint16_t that holds Lc.
 *
 * WHAT THE CARD ACTUALLY ACCEPTS, AND WHY THE TWO DIRECTIONS DIFFER
 *
 * Lc costs RAM. The card must hold the whole command data field before it can
 * act on it, so Lc is bounded by the receive buffer -- SCOS_APDU_EXT_LC_MAX,
 * far below 65535 and documented in scos_config.h. Above it the parser reports
 * APDU_PARSE_LC_TOO_LARGE and the card answers 6700.
 *
 * Le costs nothing. It is a MAXIMUM, not a demand: ISO permits a card to
 * return fewer bytes than Le, and 61XX exists to announce the remainder. So
 * an extended Le of 65536 is parsed and honoured exactly as written -- the
 * card simply answers with what it has. No ceiling, no refusal, no RAM.
 */
#ifndef SCOS_APDU_H
#define SCOS_APDU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APDU_HEADER_LEN   4u
#define APDU_SHORT_LC_MAX 255u
#define APDU_SHORT_LE_MAX 256u

/* Extended form: a 3-byte length field (00 hi lo) instead of one byte. */
#define APDU_EXT_LEN_FIELD 3u
#define APDU_EXT_LC_MAX    65535u
#define APDU_EXT_LE_MAX    65536u /* wire 0x0000, mirroring short Le==0 */

/* Total wire length of each extended shape, given Lc. */
#define APDU_EXT_CASE2_LEN 7u /* header + 00 Le1 Le2                    */

typedef enum {
    APDU_CASE_1 = 1, /* header only            */
    APDU_CASE_2 = 2, /* header + Le            */
    APDU_CASE_3 = 3, /* header + Lc + data     */
    APDU_CASE_4 = 4  /* header + Lc + data + Le*/
} apdu_case;

typedef struct {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;

    /* Command data field. Points INTO the caller's receive buffer -- the
     * parser copies nothing. Valid only while that buffer lives, and only if
     * lc > 0; NULL otherwise. */
    const uint8_t *data;
    uint16_t       lc; /* 1..255 short, 1..65535 extended; 0 = absent      */

    /* Expected response length. Only meaningful when le_present is true.
     * Already normalised: a wire 0x00 arrives here as 256 (short form) and a
     * wire 0x0000 as 65536 (extended). uint32_t because 65536 does not fit in
     * sixteen bits -- the one place an APDU length exceeds uint16_t. */
    uint32_t le; /* 1..256 short, 1..65536 extended                 */
    bool     le_present;

    /* True when the length field used the extended encoding. Callers need it
     * even though lc/le are already normalised: the ENCODING is part of the
     * command's identity. GET RESPONSE announces a remainder in one byte, so
     * it can only answer a short Le, and a handler that cannot tell the forms
     * apart cannot enforce that. */
    bool extended;

    apdu_case acase;
} apdu_command;

typedef enum {
    APDU_PARSE_OK = 0,
    APDU_PARSE_TOO_SHORT,  /* fewer than 4 bytes: not even a header       */
    APDU_PARSE_BAD_LENGTH, /* Lc disagrees with the bytes actually present */
    /* Well-formed extended APDU whose Lc exceeds SCOS_APDU_EXT_LC_MAX. Kept
     * distinct from BAD_LENGTH even though both answer 6700, because they are
     * different facts: BAD_LENGTH means the reader sent a broken frame,
     * LC_TOO_LARGE means the reader sent a correct frame this card is too
     * small to accept. Only the second is fixed by a bigger buffer. */
    APDU_PARSE_LC_TOO_LARGE
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
    APDU_CLA_OK = 0,  /* first interindustry, channel 0, no SM     */
    APDU_CLA_INVALID, /* 0xFF, or a class we do not implement      */
    APDU_CLA_CHANNEL_UNSUPPORTED, /* logical channel != 0                      */
    APDU_CLA_SM_UNSUPPORTED, /* secure messaging bits set                 */
    APDU_CLA_CHAINING_UNSUPPORTED /* command-chaining bit set                  */
} apdu_cla_status;

/* Classify CLA per ISO/IEC 7816-4 s.5.4.1. This milestone accepts only
 * CLA==0x00 and reports precisely why anything else was rejected, so the
 * status word we return is diagnostic rather than a blanket 6E00. */
apdu_cla_status apdu_check_cla(uint8_t cla);
uint16_t        apdu_cla_status_sw(apdu_cla_status st);

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
