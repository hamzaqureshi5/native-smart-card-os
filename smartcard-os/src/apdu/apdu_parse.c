/* SPDX-License-Identifier: MIT
 *
 * apdu_parse.c -- Command APDU parser.
 *
 * This is the card's attack surface. Every byte here came from an untrusted
 * reader. The rules the code follows, deliberately and repetitively:
 *
 *   - Validate length BEFORE indexing. Never index then check.
 *   - Compute in a type wide enough to hold the result. All the length
 *     arithmetic is done in uint32_t even though the fields are uint16_t,
 *     because 5 + 255 + 1 must not be allowed to wrap anywhere.
 *   - Zero the output on every failure path, so a caller that forgets to check
 *     the return value cannot read a half-filled structure.
 *   - No copying. The data pointer aliases the caller's buffer.
 */
#include "apdu/apdu.h"
#include "apdu/sw.h"
#include "os/os_mem.h"

apdu_parse_status apdu_parse(const uint8_t *buf, uint16_t len,
                             apdu_command *out)
{
    if (out == NULL) {
        return APDU_PARSE_TOO_SHORT; /* nothing to report into */
    }
    os_memset(out, 0, sizeof(*out));

    if (buf == NULL || len < APDU_HEADER_LEN) {
        return APDU_PARSE_TOO_SHORT;
    }

    out->cla = buf[0];
    out->ins = buf[1];
    out->p1  = buf[2];
    out->p2  = buf[3];

    /* Case 1: header only. */
    if (len == APDU_HEADER_LEN) {
        out->acase = APDU_CASE_1;
        return APDU_PARSE_OK;
    }

    const uint8_t p3 = buf[4];

    /*
     * Exactly 5 bytes. THE CLASSIC TRAP: byte 5 is Le, not Lc.
     *
     * A command carrying zero data bytes cannot be Case 3, so an Lc field is
     * not encodable here; the standard assigns the fifth byte to Le. This is
     * why "00 A4 00 00 00" is "select, and return up to 256 bytes" rather than
     * "select with an empty data field".
     */
    if (len == APDU_HEADER_LEN + 1u) {
        out->acase      = APDU_CASE_2;
        out->le_present = true;
        /* Le == 0 on the wire means 256. */
        out->le = (p3 == 0u) ? (uint16_t)APDU_SHORT_LE_MAX : (uint16_t)p3;
        return APDU_PARSE_OK;
    }

    /*
     * More than 5 bytes, so an Lc field is present.
     *
     * p3 == 0 here signals the EXTENDED length encoding: the standard says a
     * zero Lc byte followed by more data introduces a 3-byte extended Lc
     * (00 Lc-hi Lc-lo). We detect it and refuse it explicitly rather than
     * misparsing it as a short APDU -- silently treating an extended APDU as
     * short would let a caller smuggle a length we never validated.
     */
    if (p3 == 0u) {
        os_memset(out, 0, sizeof(*out));
        return APDU_PARSE_EXTENDED;
    }

    const uint32_t lc        = (uint32_t)p3;
    const uint32_t total     = (uint32_t)len;
    const uint32_t case3_len = APDU_HEADER_LEN + 1u + lc;      /* no Le  */
    const uint32_t case4_len = APDU_HEADER_LEN + 1u + lc + 1u; /* with Le */

    if (total == case3_len) {
        out->acase = APDU_CASE_3;
        out->lc    = (uint16_t)lc;
        out->data  = &buf[APDU_HEADER_LEN + 1u];
        return APDU_PARSE_OK;
    }

    if (total == case4_len) {
        const uint8_t le_byte = buf[case4_len - 1u];
        out->acase      = APDU_CASE_4;
        out->lc         = (uint16_t)lc;
        out->data       = &buf[APDU_HEADER_LEN + 1u];
        out->le_present = true;
        out->le = (le_byte == 0u) ? (uint16_t)APDU_SHORT_LE_MAX
                                  : (uint16_t)le_byte;
        return APDU_PARSE_OK;
    }

    /* Lc claims a data field that is not the size actually delivered: either
     * truncated (total < case3_len) or trailing junk (total > case4_len). */
    os_memset(out, 0, sizeof(*out));
    return APDU_PARSE_BAD_LENGTH;
}

uint16_t apdu_parse_status_sw(apdu_parse_status st)
{
    switch (st) {
    case APDU_PARSE_OK:
        return SW_OK;
    case APDU_PARSE_TOO_SHORT:
    case APDU_PARSE_BAD_LENGTH:
        return SW_WRONG_LENGTH; /* 6700 */
    case APDU_PARSE_EXTENDED:
        /* Not "wrong length" -- the length is well-formed, we just do not
         * implement the function. 6A81 says exactly that. */
        return SW_FUNC_NOT_SUPPORTED; /* 6A81 */
    default:
        return SW_NO_PRECISE_DIAGNOSIS;
    }
}

/*
 * CLA classification, ISO/IEC 7816-4 s.5.4.1.
 *
 * For the "first interindustry" class the bits are:
 *   b8 b7 b6 = 0 0 0   first interindustry class
 *   b5       = 1       command chaining: more blocks follow
 *   b4 b3              secure messaging indication
 *   b2 b1              logical channel number
 *
 * 0xFF is reserved by ISO for protocol-level use and is never a valid CLA.
 *
 * We return a specific reason rather than a blanket rejection so the status
 * word is diagnostic. A reader that gets 6882 learns "the card understood my
 * class but has no secure messaging", which is true and useful; 6E00 would
 * have implied the class itself was unrecognised.
 */
apdu_cla_status apdu_check_cla(uint8_t cla)
{
    if (cla == 0xFFu) {
        return APDU_CLA_INVALID;
    }
    /* Only the first interindustry class (000x xxxx) is implemented. */
    if ((cla & 0xE0u) != 0x00u) {
        return APDU_CLA_INVALID;
    }
    if ((cla & 0x10u) != 0u) {
        return APDU_CLA_CHAINING_UNSUPPORTED;
    }
    if ((cla & 0x0Cu) != 0u) {
        return APDU_CLA_SM_UNSUPPORTED;
    }
    if ((cla & 0x03u) != 0u) {
        return APDU_CLA_CHANNEL_UNSUPPORTED;
    }
    return APDU_CLA_OK;
}

uint16_t apdu_cla_status_sw(apdu_cla_status st)
{
    switch (st) {
    case APDU_CLA_OK:
        return SW_OK;
    case APDU_CLA_CHANNEL_UNSUPPORTED:
        return SW_LOGICAL_CHANNEL_NOT_SUPPORTED;  /* 6881 */
    case APDU_CLA_SM_UNSUPPORTED:
        return SW_SECURE_MESSAGING_NOT_SUPPORTED; /* 6882 */
    case APDU_CLA_CHAINING_UNSUPPORTED:
        return SW_CHAINING_NOT_SUPPORTED;         /* 6884 */
    case APDU_CLA_INVALID:
    default:
        return SW_CLA_NOT_SUPPORTED;              /* 6E00 */
    }
}
