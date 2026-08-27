/* SPDX-License-Identifier: MIT
 *
 * tlv.h -- BER-TLV parser (ISO/IEC 7816-4 annex D, ASN.1 BER encoding rules).
 *
 * WHAT TLV IS AND WHY CARDS USE IT
 * --------------------------------
 * Tag-Length-Value: a self-describing byte encoding.
 *
 *     62 0B  82 01 01  83 02 6F 03  80 02 00 40
 *     |  |   \_______/ \__________/ \__________/
 *     |  |   descriptor  file id      file size
 *     |  length of everything inside: 3 + 4 + 4 = 11 = 0x0B
 *     tag: FCP template
 *
 * Cards use it because a card must parse messages from readers it has never
 * met, written against a spec that will gain fields later. TLV lets a card skip
 * objects it does not understand instead of rejecting the whole message -- and
 * lets a reader do the same with a card's response.
 *
 * THIS IS THE SECOND ATTACK SURFACE IN THE OS.
 * Every byte comes from an untrusted reader, and TLV is the classic place to go
 * wrong: nested lengths that claim more than exists, tags that never terminate,
 * length fields that overflow. The rules this parser follows:
 *
 *   - NO RECURSION. A constructed object's content is parsed by the caller
 *     making a new reader over its value. Recursion on attacker-controlled
 *     nesting depth is a stack overflow waiting to happen, and a card has
 *     kilobytes of stack.
 *   - BOUNDED TAGS AND LENGTHS. At most 2 tag bytes and 2 length bytes, which
 *     is everything ISO 7816-4 actually uses. Longer encodings are legal BER
 *     but a card has no use for them, and accepting them widens the surface
 *     for nothing.
 *   - INDEFINITE LENGTH IS REFUSED. BER's 0x80 "ends with 00 00 somewhere
 *     later" form cannot be validated up front, so it is rejected outright.
 *   - ARITHMETIC IN uint32_t so no length computation can wrap.
 *   - VALIDATE BEFORE INDEXING, every time.
 */
#ifndef SCOS_TLV_H
#define SCOS_TLV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ISO 7816-4 uses 1- and 2-byte tags. Packed big-endian into a uint16_t, so
 * tag 0x82 is 0x0082 and tag 0x5F2D is 0x5F2D. */
#define TLV_MAX_TAG_BYTES 2u
#define TLV_MAX_LEN_BYTES 2u

typedef enum {
    TLV_OK = 0,
    TLV_END, /* no more objects: normal end of the sequence */
    TLV_ERR_PARAM,
    TLV_ERR_TRUNCATED, /* an object claims more bytes than are present */
    TLV_ERR_TAG,       /* malformed tag, or longer than we accept          */
    TLV_ERR_LENGTH     /* malformed length, indefinite, or too long        */
} tlv_status;

typedef struct {
    const uint8_t *buf;
    uint16_t       len;
    uint16_t       pos;
} tlv_reader;

typedef struct {
    uint16_t       tag;
    const uint8_t *value; /* aliases the reader's buffer; no copy */
    uint16_t       length;
    bool           constructed; /* bit 6 of the first tag byte */
} tlv_object;

void tlv_reader_init(tlv_reader *r, const uint8_t *buf, uint16_t len);

/* True once the reader has consumed everything (padding aside). */
bool tlv_reader_done(const tlv_reader *r);

/*
 * Read the next object.
 *
 * Returns TLV_OK and fills *out, TLV_END at the end of the buffer, or an error.
 * On any error the reader is left EXHAUSTED, so a caller looping until
 * != TLV_OK cannot spin forever on a malformed object.
 *
 * ISO 7816-4 permits 0x00 and 0xFF bytes as padding between objects, so they
 * are skipped. That also means a template read out of erased NVM (all 0xFF)
 * parses as empty rather than as garbage.
 */
tlv_status tlv_next(tlv_reader *r, tlv_object *out);

/* Find the first object with `tag` at the TOP LEVEL of buf. Does not descend
 * into constructed objects -- the caller decides when to look inside one,
 * because that is where the nesting-depth risk lives. */
tlv_status tlv_find(const uint8_t *buf, uint16_t len, uint16_t tag,
                    tlv_object *out);

/* Read a big-endian unsigned integer from an object's value, for the many ISO
 * data objects that are 1- or 2-byte numbers. Refuses anything wider than 4
 * bytes, and refuses an empty value. */
tlv_status tlv_get_uint(const tlv_object *obj, uint32_t *out);

/* --- writing -------------------------------------------------------------- */

/* Append one primitive object. Returns false if it would not fit, having
 * written nothing -- a half-written template is worse than none. */
bool tlv_put(uint8_t *buf, uint16_t cap, uint16_t *pos, uint16_t tag,
             const uint8_t *value, uint16_t length);

#endif /* SCOS_TLV_H */
