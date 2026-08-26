/* SPDX-License-Identifier: MIT
 *
 * card_loop.c -- The APDU pump.
 *
 * WHY THIS IS A SEPARATE TRANSLATION UNIT
 * ---------------------------------------
 * This file is the ONLY part of the OS core that calls the HAL. Everything
 * else -- parsing, dispatch, command handlers, the kernel state machine -- is
 * pure computation over buffers.
 *
 * That split is not cosmetic. Because the pump lives in its own object file, a
 * test that links libscos_core and uses only scos_process() never pulls in a
 * single HAL reference, so the whole command surface can be tested with no
 * hardware, no simulator and no I/O of any kind. The split was in fact forced
 * by the linker: when the pump shared kernel.c with scos_process(), every unit
 * test needed a HAL to link. The build system caught the layering mistake.
 *
 * On real silicon this loop is entered from the chip's boot code after the ATR
 * has been clocked out, and it never returns while the card is powered.
 */
#include "hal/hal.h"
#include "os/kernel.h"

void scos_card_loop(scos_kernel *k)
{
    if (k == NULL) {
        return;
    }

    for (;;) {
        uint32_t received = 0u;
        const hal_status hs =
            hal_card_receive(k->cmd, (uint32_t)sizeof(k->cmd), &received);

        if (hs == HAL_ERR_LINK_DOWN) {
            return; /* reader gone / power removed: stop cleanly */
        }
        if (hs == HAL_CARD_RESET) {
            /* The reader asserted RST. Drop all volatile state. The link layer
             * has already answered with the ATR -- that is its job, not ours. */
            scos_reset(k);
            continue;
        }
        if (hs != HAL_OK) {
            /* A link error is not something the card can report over the same
             * broken link. Drop the exchange and resynchronise. */
            continue;
        }
        if (received > sizeof(k->cmd)) {
            continue; /* HAL contract violation; defend anyway */
        }

        k->cmd_len = (uint16_t)received;
        k->rsp_len = 0u;

        if (scos_process(k, k->cmd, k->cmd_len,
                         k->rsp, (uint16_t)sizeof(k->rsp),
                         &k->rsp_len) != SCOS_OK) {
            continue;
        }

        (void)hal_card_send(k->rsp, (uint32_t)k->rsp_len);
    }
}
