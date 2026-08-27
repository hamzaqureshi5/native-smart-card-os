/* SPDX-License-Identifier: MIT */
#include "fuzz_targets.h"

#include "apdu/apdu.h"
#include "apdu/sw.h"

int scos_fuzz_apdu(const uint8_t *data, size_t size)
{
    if (size > 0xFFFFu) {
        return 0;
    }
    apdu_command            cmd;
    const apdu_parse_status st = apdu_parse(data, (uint16_t)size, &cmd);

    /* Whatever the input, the parser must report a defined status and never
     * describe a data field outside the buffer we handed it. */
    switch (st) {
    case APDU_PARSE_OK:
        if (cmd.lc > 0u) {
            /* The data pointer must lie inside data[0..size). Comparing
             * pointers into the same array is defined; ASan catches the rest. */
            if (cmd.data == NULL) {
                __builtin_trap();
            }
            if (cmd.data < data) {
                __builtin_trap();
            }
            if ((size_t)(cmd.data - data) + cmd.lc > size) {
                __builtin_trap();
            }
            /* Touch every byte, so ASan validates the range rather than us. */
            volatile uint8_t sink = 0u;
            for (uint16_t i = 0; i < cmd.lc; i++) {
                sink = (uint8_t)(sink ^ cmd.data[i]);
            }
            (void)sink;
        } else if (cmd.data != NULL) {
            __builtin_trap(); /* no data field, so no pointer to one */
        }
        if (cmd.le_present && (cmd.le == 0u || cmd.le > APDU_SHORT_LE_MAX)) {
            __builtin_trap(); /* Le is normalised to 1..256 */
        }
        break;
    case APDU_PARSE_TOO_SHORT:
    case APDU_PARSE_BAD_LENGTH:
    case APDU_PARSE_EXTENDED:
        /* Failure must zero the output, so a caller ignoring the status cannot
         * act on stale fields. */
        if (cmd.data != NULL || cmd.lc != 0u) {
            __builtin_trap();
        }
        break;
    default:
        __builtin_trap(); /* undefined status */
    }

    /* Every status must map to a real status word. */
    if (apdu_parse_status_sw(st) == 0u) {
        __builtin_trap();
    }
    if (size > 0u) {
        (void)apdu_cla_status_sw(apdu_check_cla(data[0]));
    }
    return 0;
}
