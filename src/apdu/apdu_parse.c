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
#include "os/scos_config.h"

/* Big-endian 16-bit read. Byte-wise on purpose: the wire is big-endian and
 * the host may not be, and a cast to uint16_t* would also be an alignment
 * fault on a core that does not permit unaligned access. */
static uint32_t be16(const uint8_t *p)
{ return ((uint32_t)p[0] << 8) | (uint32_t)p[1]; }

/*
 * Extended form, entered when byte 5 is 00 and at least one byte follows it.
 *
 *   Case 2E   header 00 Le1 Le2                    len == 7
 *   Case 3E   header 00 Lc1 Lc2 <data>             len == 7 + Lc
 *   Case 4E   header 00 Lc1 Lc2 <data> Le1 Le2     len == 9 + Lc
 *
 * The caller has already established len >= 6 and buf[4] == 0.
 */
static apdu_parse_status parse_extended(const uint8_t *buf, uint16_t len,
                                        apdu_command *out)
{
    const uint32_t total = (uint32_t)len;

    /*
     * len == 6: the 00 introduces a three-byte length field and only two
     * bytes are present. Nothing legal has this shape, so it is a malformed
     * frame -- 6700 -- and not "extended not supported".
     */
    if (total < APDU_EXT_CASE2_LEN) {
        os_memset(out, 0, sizeof(*out));
        return APDU_PARSE_BAD_LENGTH;
    }

    out->extended = true;

    /* Case 2E: no data field, so bytes 5..6 are Le. */
    if (total == APDU_EXT_CASE2_LEN) {
        const uint32_t le_wire = be16(&buf[5]);
        out->acase             = APDU_CASE_2;
        out->le_present        = true;
        /* 0x0000 means 65536, mirroring the short form's 0 meaning 256. */
        out->le = (le_wire == 0u) ? APDU_EXT_LE_MAX : le_wire;
        return APDU_PARSE_OK;
    }

    /* len >= 8: bytes 5..6 are Lc. */
    const uint32_t lc = be16(&buf[5]);

    /*
     * Lc == 0 with a body following is not encodable: zero data bytes means
     * Case 1 or Case 2, and both are shorter shapes. Reject before the
     * arithmetic below can produce a match by accident -- with lc == 0,
     * case4_len would be 9, so a nine-byte "00 00 00 <4 bytes>" frame would
     * otherwise parse as a Case 4E with an empty data field.
     */
    if (lc == 0u) {
        os_memset(out, 0, sizeof(*out));
        return APDU_PARSE_BAD_LENGTH;
    }

    /*
     * The ceiling check comes BEFORE the length arithmetic, and returns a
     * status of its own. Reason: for a huge Lc the frame is necessarily
     * shorter than Lc claims, so the arithmetic below would report
     * BAD_LENGTH -- blaming the reader for a truncated frame when in fact it
     * sent a correct one this card is too small to hold. Same status word,
     * 6700, but a diagnosis that would send someone debugging the wrong end
     * of the link.
     */
    if (lc > SCOS_APDU_EXT_DATA_MAX) {
        os_memset(out, 0, sizeof(*out));
        return APDU_PARSE_LC_TOO_LARGE;
    }

    /* All in uint32_t: 4 + 3 + 65535 + 2 must not be able to wrap. */
    const uint32_t case3_len = APDU_HEADER_LEN + APDU_EXT_LEN_FIELD + lc;
    const uint32_t case4_len = case3_len + 2u;

    if (total == case3_len) {
        out->acase = APDU_CASE_3;
        out->lc    = (uint16_t)lc;
        out->data  = &buf[APDU_HEADER_LEN + APDU_EXT_LEN_FIELD];
        return APDU_PARSE_OK;
    }

    if (total == case4_len) {
        const uint32_t le_wire = be16(&buf[case4_len - 2u]);
        out->acase             = APDU_CASE_4;
        out->lc                = (uint16_t)lc;
        out->data              = &buf[APDU_HEADER_LEN + APDU_EXT_LEN_FIELD];
        out->le_present        = true;
        out->le                = (le_wire == 0u) ? APDU_EXT_LE_MAX : le_wire;
        return APDU_PARSE_OK;
    }

    /* Lc claims a data field that is not the size delivered. */
    os_memset(out, 0, sizeof(*out));
    return APDU_PARSE_BAD_LENGTH;
}

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
     * More than 5 bytes, so a length field is present.
     *
     * p3 == 0 here introduces the EXTENDED encoding: 00 followed by a 16-bit
     * big-endian length. It cannot be a short Lc, because a short Lc of zero
     * is not encodable -- a command with no data field is Case 1 or Case 2,
     * both of which were handled above.
     */
    if (p3 == 0u) {
        return parse_extended(buf, len, out);
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
        out->acase            = APDU_CASE_4;
        out->lc               = (uint16_t)lc;
        out->data             = &buf[APDU_HEADER_LEN + 1u];
        out->le_present       = true;
        out->le =
            (le_byte == 0u) ? (uint16_t)APDU_SHORT_LE_MAX : (uint16_t)le_byte;
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
    case APDU_PARSE_LC_TOO_LARGE:
        /*
         * 6700 as well, and NOT 6A81 "function not supported": extended
         * length IS supported here, so claiming otherwise would send a
         * reader down the wrong recovery path -- it would stop using the
         * extended form entirely instead of sending a smaller Lc.
         *
         * ISO/IEC 7816-4 offers nothing more specific. 6A87 is "Lc
         * inconsistent with P1-P2", which is a different fault: our Lc is
         * consistent with everything, just larger than the card can hold.
         * A card announces its real maximum in EF.ATR, not in a status word.
         */
        return SW_WRONG_LENGTH; /* 6700 */
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
        return SW_LOGICAL_CHANNEL_NOT_SUPPORTED; /* 6881 */
    case APDU_CLA_SM_UNSUPPORTED:
        return SW_SECURE_MESSAGING_NOT_SUPPORTED; /* 6882 */
    case APDU_CLA_CHAINING_UNSUPPORTED:
        return SW_CHAINING_NOT_SUPPORTED; /* 6884 */
    case APDU_CLA_INVALID:
    default:
        return SW_CLA_NOT_SUPPORTED; /* 6E00 */
    }
}
