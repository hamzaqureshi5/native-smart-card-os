/* SPDX-License-Identifier: MIT
 *
 * fuzz_fs_image.c -- Corrupted persistent storage.
 *
 * Unlike the other targets, the input here is not a message from a reader: it
 * is written directly over NVM, then the card is booted and navigated. That
 * models a card whose flash has been damaged -- by a torn write, a worn cell,
 * or someone with the chip and a probe.
 *
 * The property: the OS must never crash, never read out of bounds, and never
 * act on a descriptor that failed its integrity check. It is allowed to refuse
 * to mount -- refusing is the correct answer to corruption.
 */
#include "fuzz_targets.h"

#include "filesystem/fs.h"
#include "filesystem/fs_store.h"
#include "hal/hal.h"
#include "hal/sim/vcard.h"
#include "os/kernel.h"

static bool g_ready = false;

static void ensure_powered(void)
{
    if (g_ready) {
        return;
    }
    vcard_config cfg;
    vcard_config_default(&cfg);
    cfg.state_dir = NULL;
    cfg.quiet     = true;
    vcard_configure(&cfg);
    g_ready = true;
}

int scos_fuzz_fs_image(const uint8_t *data, size_t size)
{
    ensure_powered();

    /* Fresh chip each time: a filesystem image is whole-card state, so reusing
     * a corrupted one would make every later input meaningless. */
    vcard_power_off();
    if (vcard_power_on() != HAL_OK) {
        __builtin_trap();
    }

    /* Lay down a valid filesystem first, then damage it. Starting from a valid
     * image is what makes the corruption interesting -- random bytes alone
     * almost never produce a mountable superblock, so the mount path would
     * never be reached. */
    if (fs_personalise() != FS_OK) {
        __builtin_trap();
    }

    /* Overwrite the superblock and descriptor table region with the input. */
    const uint32_t region = 16u + (32u * 20u); /* superblock + 32 slots */
    uint32_t       n      = (size < region) ? (uint32_t)size : region;
    if (n > 0u) {
        if (hal_nvm_write(HAL_NVM_EEPROM, 0u, data, n) != HAL_OK) {
            __builtin_trap();
        }
    }

    /* Now boot on it. Any outcome is acceptable except crashing or lying. */
    scos_kernel       card;
    const scos_status st = scos_init(&card);

    if (st != SCOS_OK) {
        /* Refused to mount. It must say so, not pretend to work. */
        if (card.lifecycle != SCOS_LC_FS_ERROR) {
            __builtin_trap();
        }
        /* And it must still answer, so a reader can diagnose it. */
        uint8_t       rsp[SCOS_APDU_RSP_MAX];
        uint16_t      rsp_len = 0u;
        const uint8_t sel[]   = { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00 };
        if (scos_process(&card, sel, sizeof(sel), rsp, (uint16_t)sizeof(rsp),
                         &rsp_len) != SCOS_OK) {
            __builtin_trap();
        }
        if (rsp_len < 2u) {
            __builtin_trap();
        }
        return 0;
    }

    /*
     * It mounted. Now walk the tree and read every file. Every descriptor was
     * either CRC-valid or rejected, so nothing here may run off the end of a
     * region -- ASan is the judge.
     */
    const uint16_t slots = fs_store_max_files();
    for (uint16_t i = 0; i < slots; i++) {
        fs_descriptor d;
        if (fs_get(i, &d) != FS_OK) {
            continue; /* free or corrupt: both fine */
        }
        (void)fs_child_count(i);

        if (fs_is_ef(&d)) {
            uint8_t  buf[64];
            uint16_t got = 0u;
            (void)fs_ef_read(i, 0u, (uint16_t)sizeof(buf), buf, &got);
            if (got > sizeof(buf)) {
                __builtin_trap(); /* reported more than the buffer holds */
            }
            /* And near the declared end, where an off-by-one would show. */
            if (d.size > 4u) {
                (void)fs_ef_read(i, (uint16_t)(d.size - 4u), 16u, buf, &got);
            }
        }
    }

    /* Drive the command surface over the damaged filesystem. */
    static const uint8_t apdus[][8] = {
        { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00, 0x00 },
        { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x10, 0x00 },
        { 0x00, 0xA4, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x00, 0xB0, 0x81, 0x00, 0x10, 0x00, 0x00, 0x00 },
    };
    static const uint16_t lens[] = { 7u, 7u, 4u, 5u };
    for (unsigned i = 0; i < 4u; i++) {
        uint8_t  rsp[SCOS_APDU_RSP_MAX];
        uint16_t rsp_len = 0u;
        if (scos_process(&card, apdus[i], lens[i], rsp, (uint16_t)sizeof(rsp),
                         &rsp_len) != SCOS_OK) {
            __builtin_trap();
        }
        if (rsp_len < 2u) {
            __builtin_trap();
        }
    }
    return 0;
}
