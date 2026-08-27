/* SPDX-License-Identifier: MIT
 *
 * apdu_resp.c -- Response APDU builder.
 *
 * Invariant: a card ALWAYS answers with at least SW1 SW2. There is no such
 * thing as "no response" -- a reader waiting on a silent card just times out,
 * which is indistinguishable from a dead card and is a terrible failure mode.
 * So the builder is written to make an empty-but-valid response the fallback
 * for every error, including its own internal overflow.
 */
#include "apdu/apdu.h"
#include "apdu/sw.h"
#include "os/os_mem.h"

void apdu_rsp_init(apdu_response *r, uint8_t *buf, uint16_t cap)
{
    if (r == NULL) {
        return;
    }
    r->buf      = buf;
    r->cap      = (buf == NULL) ? 0u : cap;
    r->len      = 0u;
    r->overflow = false;
}

bool apdu_rsp_put(apdu_response *r, const uint8_t *src, uint16_t n)
{
    if (r == NULL) {
        return false;
    }
    if (n == 0u) {
        return true;
    }
    if (src == NULL) {
        r->overflow = true; /* treat as a builder failure, not a crash */
        return false;
    }
    /* Always keep two bytes in reserve for SW, so apdu_rsp_finish() cannot
     * fail after the payload has been accepted. Arithmetic in uint32_t: cap is
     * uint16_t and len + n could otherwise wrap. */
    const uint32_t reserve = 2u;
    const uint32_t available =
        (r->cap >= reserve) ? ((uint32_t)r->cap - reserve) : 0u;
    if ((uint32_t)r->len + (uint32_t)n > available) {
        r->overflow = true;
        return false;
    }
    if (!os_memcpy_checked(&r->buf[r->len], (size_t)(r->cap - r->len), src,
                           (size_t)n)) {
        r->overflow = true;
        return false;
    }
    r->len = (uint16_t)(r->len + n);
    return true;
}

bool apdu_rsp_put_u8(apdu_response *r, uint8_t b)
{ return apdu_rsp_put(r, &b, 1u); }

bool apdu_rsp_put_u16(apdu_response *r, uint16_t v)
{
    const uint8_t be[2] = { (uint8_t)(v >> 8), (uint8_t)(v & 0xFFu) };
    return apdu_rsp_put(r, be, 2u);
}

uint16_t apdu_rsp_finish(apdu_response *r, uint16_t sw)
{
    if (r == NULL || r->buf == NULL || r->cap < 2u) {
        /* Cannot even emit a status word. The caller must treat 0 as fatal;
         * scos_process() refuses to run with a buffer this small. */
        return 0u;
    }

    uint16_t status = sw;
    if (r->overflow) {
        /* We produced more data than the response buffer can carry. Returning
         * a truncated payload would be a correctness lie, so discard it and
         * report an internal error instead. */
        r->len = 0u;
        status = SW_NO_PRECISE_DIAGNOSIS; /* 6F00 */
    }

    r->buf[r->len]      = sw1(status);
    r->buf[r->len + 1u] = sw2(status);
    r->len              = (uint16_t)(r->len + 2u);
    return r->len;
}
