/* SPDX-License-Identifier: MIT
 *
 * tlv.c -- BER-TLV parser. See tlv.h for the rules this code follows.
 */
#include "apdu/tlv.h"

#include "os/os_mem.h"

void tlv_reader_init(tlv_reader *r, const uint8_t *buf, uint16_t len)
{
    if (r == NULL) {
        return;
    }
    r->buf = buf;
    r->len = (buf == NULL) ? 0u : len;
    r->pos = 0u;
}

/* Skip ISO 7816-4 filler bytes. Returns the new position. */
static uint16_t skip_padding(const tlv_reader *r, uint16_t pos)
{
    while (pos < r->len && (r->buf[pos] == 0x00u || r->buf[pos] == 0xFFu)) {
        pos = (uint16_t)(pos + 1u);
    }
    return pos;
}

bool tlv_reader_done(const tlv_reader *r)
{
    if (r == NULL || r->buf == NULL) {
        return true;
    }
    return skip_padding(r, r->pos) >= r->len;
}

/* Exhaust the reader, so a caller looping on this reader cannot spin. */
static void exhaust(tlv_reader *r)
{
    r->pos = r->len;
}

tlv_status tlv_next(tlv_reader *r, tlv_object *out)
{
    if (r == NULL || out == NULL || r->buf == NULL) {
        return TLV_ERR_PARAM;
    }
    os_memset(out, 0, sizeof(*out));

    uint16_t pos = skip_padding(r, r->pos);
    if (pos >= r->len) {
        r->pos = r->len;
        return TLV_END;
    }

    /* --- tag ------------------------------------------------------------- */
    const uint8_t t0 = r->buf[pos];
    uint16_t      tag = (uint16_t)t0;
    const bool    constructed = (t0 & 0x20u) != 0u;
    pos = (uint16_t)(pos + 1u);

    /*
     * Low five bits all set means "high tag number form": the tag number
     * continues in following bytes, each with bit 8 set to say another follows.
     * ISO 7816-4 uses at most one continuation byte, so that is all we accept.
     * Refusing a longer tag is a deliberate narrowing: BER would allow an
     * unbounded chain, which is an unbounded read driven by the attacker.
     */
    if ((t0 & 0x1Fu) == 0x1Fu) {
        if (pos >= r->len) {
            exhaust(r);
            return TLV_ERR_TRUNCATED;
        }
        const uint8_t t1 = r->buf[pos];
        pos = (uint16_t)(pos + 1u);
        tag = (uint16_t)(((uint16_t)t0 << 8) | (uint16_t)t1);

        if ((t1 & 0x80u) != 0u) {
            /* A third tag byte would follow. Not accepted. */
            exhaust(r);
            return TLV_ERR_TAG;
        }
    }

    /* --- length ---------------------------------------------------------- */
    if (pos >= r->len) {
        exhaust(r);
        return TLV_ERR_TRUNCATED;
    }
    const uint8_t l0 = r->buf[pos];
    pos = (uint16_t)(pos + 1u);

    uint32_t length;
    if (l0 < 0x80u) {
        length = (uint32_t)l0;            /* short form: 0..127 */
    } else if (l0 == 0x80u) {
        /* Indefinite length: content runs until an end-of-contents marker
         * somewhere later. It cannot be bounds-checked before parsing the
         * content, so it is refused rather than trusted. */
        exhaust(r);
        return TLV_ERR_LENGTH;
    } else if (l0 == 0xFFu) {
        exhaust(r);
        return TLV_ERR_LENGTH;            /* reserved by BER */
    } else {
        const uint8_t nbytes = (uint8_t)(l0 & 0x7Fu);
        if (nbytes > TLV_MAX_LEN_BYTES) {
            /* 3+ length bytes could describe more data than a card could ever
             * hold. Refuse instead of computing a number we cannot honour. */
            exhaust(r);
            return TLV_ERR_LENGTH;
        }
        /* Bounds check BEFORE reading the length bytes themselves. */
        if ((uint32_t)pos + (uint32_t)nbytes > (uint32_t)r->len) {
            exhaust(r);
            return TLV_ERR_TRUNCATED;
        }
        length = 0u;
        for (uint8_t i = 0; i < nbytes; i++) {
            length = (length << 8) | (uint32_t)r->buf[pos];
            pos = (uint16_t)(pos + 1u);
        }
    }

    /* --- value ----------------------------------------------------------- */
    /* uint32_t so a length near 0xFFFF cannot wrap past r->len. */
    if ((uint32_t)pos + length > (uint32_t)r->len) {
        exhaust(r);
        return TLV_ERR_TRUNCATED;
    }

    out->tag         = tag;
    out->constructed = constructed;
    out->length      = (uint16_t)length;
    out->value       = (length > 0u) ? &r->buf[pos] : NULL;

    r->pos = (uint16_t)((uint32_t)pos + length);
    return TLV_OK;
}

tlv_status tlv_find(const uint8_t *buf, uint16_t len, uint16_t tag,
                    tlv_object *out)
{
    if (buf == NULL || out == NULL) {
        return TLV_ERR_PARAM;
    }
    tlv_reader r;
    tlv_reader_init(&r, buf, len);

    for (;;) {
        tlv_object obj;
        const tlv_status st = tlv_next(&r, &obj);
        if (st == TLV_OK) {
            if (obj.tag == tag) {
                *out = obj;
                return TLV_OK;
            }
            continue;   /* an object we are not looking for: skip it */
        }
        if (st == TLV_END) {
            return TLV_END;
        }
        /* A malformed object earlier in the sequence means we cannot trust the
         * rest of it, so the search fails rather than skipping ahead. */
        return st;
    }
}

tlv_status tlv_get_uint(const tlv_object *obj, uint32_t *out)
{
    if (obj == NULL || out == NULL) {
        return TLV_ERR_PARAM;
    }
    *out = 0u;
    if (obj->value == NULL || obj->length == 0u) {
        return TLV_ERR_LENGTH;  /* an empty integer is not a number */
    }
    if (obj->length > 4u) {
        return TLV_ERR_LENGTH;  /* would not fit the return type */
    }
    uint32_t v = 0u;
    for (uint16_t i = 0; i < obj->length; i++) {
        v = (v << 8) | (uint32_t)obj->value[i];
    }
    *out = v;
    return TLV_OK;
}

bool tlv_put(uint8_t *buf, uint16_t cap, uint16_t *pos,
             uint16_t tag, const uint8_t *value, uint16_t length)
{
    if (buf == NULL || pos == NULL) {
        return false;
    }
    if (length > 0u && value == NULL) {
        return false;
    }
    /* We only emit the encodings we accept: 1- or 2-byte tag, short-form
     * length. Anything a card needs to send fits. */
    if (length > 127u) {
        return false;
    }

    const uint16_t tag_bytes = (tag > 0xFFu) ? 2u : 1u;
    const uint32_t need = (uint32_t)tag_bytes + 1u + (uint32_t)length;
    if ((uint32_t)*pos + need > (uint32_t)cap) {
        return false;   /* nothing written */
    }

    uint16_t p = *pos;
    if (tag_bytes == 2u) {
        buf[p++] = (uint8_t)(tag >> 8);
    }
    buf[p++] = (uint8_t)(tag & 0xFFu);
    buf[p++] = (uint8_t)length;
    if (length > 0u) {
        if (!os_memcpy_checked(&buf[p], (size_t)(cap - p), value,
                               (size_t)length)) {
            return false;
        }
        p = (uint16_t)(p + length);
    }
    *pos = p;
    return true;
}
