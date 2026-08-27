/* SPDX-License-Identifier: MIT */
#include "fuzz_targets.h"

#include "apdu/tlv.h"

/* Walk a TLV sequence, descending one level into constructed objects.
 * Depth is bounded by the CALLER here, not by the input -- which is the whole
 * reason the parser has no recursion. */
static void walk(const uint8_t *buf, uint16_t len, unsigned depth)
{
    if (depth > 4u) {
        return;
    }
    tlv_reader r;
    tlv_reader_init(&r, buf, len);

    unsigned guard = 0u;
    for (;;) {
        tlv_object       o;
        const tlv_status st = tlv_next(&r, &o);
        if (st != TLV_OK) {
            /* Any non-OK status must leave the reader exhausted, so this loop
             * terminates. The guard below proves it rather than assuming it. */
            break;
        }
        if (++guard > 4096u) {
            __builtin_trap(); /* the parser failed to make progress */
        }

        if (o.length > 0u) {
            if (o.value == NULL) {
                __builtin_trap();
            }
            if (o.value < buf || (size_t)(o.value - buf) + o.length > len) {
                __builtin_trap();
            }
            volatile uint8_t sink = 0u;
            for (uint16_t i = 0; i < o.length; i++) {
                sink = (uint8_t)(sink ^ o.value[i]);
            }
            (void)sink;

            uint32_t v = 0u;
            (void)tlv_get_uint(&o, &v);

            if (o.constructed) {
                walk(o.value, o.length, depth + 1u);
            }
        } else if (o.value != NULL) {
            __builtin_trap();
        }
    }
}

int scos_fuzz_tlv(const uint8_t *data, size_t size)
{
    if (size > 0xFFFFu) {
        return 0;
    }
    walk(data, (uint16_t)size, 0u);

    tlv_object o;
    (void)tlv_find(data, (uint16_t)size, 0x82u, &o);
    (void)tlv_find(data, (uint16_t)size, 0x5F2Du, &o);
    return 0;
}
