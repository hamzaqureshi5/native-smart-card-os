/* SPDX-License-Identifier: MIT */
#include "fuzz_targets.h"

#include "filesystem/fs.h"
#include "hal/hal.h"
#include "hal/sim/vcard.h"
#include "os/kernel.h"

static scos_kernel g_card;
static bool        g_ready = false;

/* One card, reused across inputs. Deliberate: it means state accumulates the
 * way it does on a real card, so an input can be affected by everything before
 * it. That finds order-dependent bugs a fresh-card-per-input harness cannot.
 * The cost is reduced reproducibility, which the driver offsets by replaying
 * from a fixed seed. */
static void ensure_card(void)
{
    if (g_ready) {
        return;
    }
    vcard_config cfg;
    vcard_config_default(&cfg);
    cfg.state_dir = NULL;   /* in-RAM NVM: hermetic, no files */
    cfg.quiet     = true;
    vcard_configure(&cfg);
    if (vcard_power_on() != HAL_OK) {
        __builtin_trap();
    }
    (void)scos_init(&g_card);
    g_ready = true;
}

int scos_fuzz_command(const uint8_t *data, size_t size)
{
    ensure_card();

    if (size > SCOS_APDU_CMD_MAX) {
        size = SCOS_APDU_CMD_MAX;
    }

    uint8_t  rsp[SCOS_APDU_RSP_MAX];
    uint16_t rsp_len = 0u;

    /* Poison the response buffer, so a handler that reports a length it did
     * not write is caught by the SW1 check below rather than reading as zeros. */
    for (unsigned i = 0; i < sizeof(rsp); i++) {
        rsp[i] = 0xA5u;
    }

    const scos_status st = scos_process(&g_card, data, (uint16_t)size,
                                        rsp, (uint16_t)sizeof(rsp), &rsp_len);
    if (st != SCOS_OK) {
        __builtin_trap();   /* a valid buffer must always be serviceable */
    }

    /* THE core invariant: always a well-formed response. */
    if (rsp_len < 2u || rsp_len > sizeof(rsp)) {
        __builtin_trap();
    }
    const uint8_t sw1 = rsp[rsp_len - 2u];
    if ((sw1 & 0xF0u) != 0x60u && (sw1 & 0xF0u) != 0x90u) {
        __builtin_trap();   /* not a valid ISO status class */
    }

    /* The filesystem must still be structurally intact: the MF is always slot
     * 0 and always a DF. If a hostile APDU can break that, the card is
     * corruptible from outside, which is the bug worth finding. */
    fs_descriptor mf;
    if (fs_get(0u, &mf) != FS_OK) {
        __builtin_trap();
    }
    if (mf.file_id != FS_FID_MF || !fs_is_df(&mf)) {
        __builtin_trap();
    }
    return 0;
}
