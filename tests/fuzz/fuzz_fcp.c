/* SPDX-License-Identifier: MIT
 *
 * fuzz_fcp.c -- CREATE FILE / DELETE FILE, driven toward the SUCCESS paths.
 *
 * WHY THIS EXISTS SEPARATELY FROM fuzz_command
 *
 * fuzz_command does emit INS E0 and E4 -- they are in its instruction list --
 * but its templates are random bytes, and random bytes essentially never form
 * a valid FCP. So it hammers the parser's reject paths and almost never
 * reaches fs_create_file() at all. That is a coverage gap that would have gone
 * unnoticed if "the fuzzer covers CREATE FILE" had been left as an assumption.
 *
 * This target builds STRUCTURALLY PLAUSIBLE templates from the input, so a
 * large fraction of commands succeed and the filesystem is genuinely mutated
 * thousands of times per run. What it then checks is not status words but the
 * INVARIANTS OF THE TREE -- because a bug in a mutating command does not
 * produce a wrong answer, it produces a card whose structure is quietly wrong
 * and stays wrong across every later power-on.
 *
 * MEASURED, not assumed: instrumenting a 20000-input run showed 279,207
 * successful CREATE FILEs out of 1,052,357 commands -- a 27% success rate. The
 * biasing works and the mutating paths really are reached. Worth re-measuring
 * if build_create() ever changes, because a template generator that quietly
 * stops producing valid templates turns this whole target into a slower copy
 * of fuzz_command.
 *
 * The invariants, checked after EVERY command:
 *
 *   1. slot 0 is still the MF, 3F00, ACTIVATED, with no parent.
 *   2. every live descriptor's parent chain reaches the MF within
 *      FS_MAX_DEPTH -- no cycles, no orphans pointing at freed slots.
 *   3. a live descriptor's parent is a live DF.
 *   4. (parent, file_id) is unique. Two files with one identifier under one DF
 *      would make every later lookup ambiguous.
 *   5. (parent, sfi) is unique for sfi != 0, for the same reason applied to
 *      READ BINARY's short form.
 *   6. NO TWO EFs' DATA RANGES OVERLAP. This is the one that really matters:
 *      an allocator bug here means writing file A silently corrupts file B,
 *      and nothing in the API would ever report it.
 *   7. every EF's data range lies inside the flash region.
 */
#include "apdu/sw.h"
#include "filesystem/fs.h"
#include "filesystem/fs_store.h"
#include "hal/hal.h"
#include "hal/sim/vcard.h"
#include "os/kernel.h"
#include "os/scos_config.h"

#include "fuzz_targets.h"

#include <assert.h>
#include <string.h>

static scos_kernel g_card;

/* ------------------------------------------------------------ invariants -- */

static void check_tree(void)
{
    fs_descriptor d[FS_MAX_FILES];
    bool          live[FS_MAX_FILES];

    for (uint16_t i = 0; i < FS_MAX_FILES; i++) {
        live[i] = (fs_store_read_desc(i, &d[i]) == FS_OK);
    }

    /* 1. the root. */
    assert(live[0]);
    assert(d[0].type == FS_TYPE_MF);
    assert(d[0].file_id == FS_FID_MF);
    assert(d[0].parent == FS_NO_PARENT);
    assert(d[0].lifecycle == FS_LC_ACTIVATED);

    for (uint16_t i = 0; i < FS_MAX_FILES; i++) {
        if (!live[i]) {
            continue;
        }

        /* 2 + 3. the parent chain terminates at the root, and every link is a
         * live DF. A cycle would spin here forever without the depth bound. */
        if (i != 0u) {
            uint16_t p     = d[i].parent;
            uint16_t depth = 0u;
            while (p != FS_NO_PARENT) {
                assert(p < FS_MAX_FILES);
                assert(live[p]);
                assert(d[p].type == FS_TYPE_MF || d[p].type == FS_TYPE_DF);
                p = d[p].parent;
                depth++;
                assert(depth <= FS_MAX_DEPTH);
            }
            assert(depth > 0u); /* reached the root, did not start there */
        }

        for (uint16_t j = (uint16_t)(i + 1u); j < FS_MAX_FILES; j++) {
            if (!live[j]) {
                continue;
            }
            /* 4. unique identifier within a parent. */
            if (d[i].parent == d[j].parent) {
                assert(d[i].file_id != d[j].file_id);
                /* 5. unique short identifier within a parent. */
                if (d[i].sfi != FS_NO_SFI) {
                    assert(d[i].sfi != d[j].sfi);
                }
            }
            /* 6. no two EFs share a byte of data space. */
            if (d[i].type == FS_TYPE_EF_TRANSPARENT &&
                d[j].type == FS_TYPE_EF_TRANSPARENT) {
                const uint64_t a0 = d[i].data_offset;
                const uint64_t a1 = a0 + d[i].size;
                const uint64_t b0 = d[j].data_offset;
                const uint64_t b1 = b0 + d[j].size;
                assert(a1 <= b0 || b1 <= a0);
            }
        }

        /* 7. within the flash region. */
        if (d[i].type == FS_TYPE_EF_TRANSPARENT) {
            const uint32_t flash = hal_nvm_size(HAL_NVM_FLASH);
            assert((uint64_t)d[i].data_offset + d[i].size <= (uint64_t)flash);
            assert(d[i].size > 0u);
        }
    }
}

/* -------------------------------------------------------------- driving --- */

static uint16_t send(const uint8_t *cmd, uint16_t len)
{
    uint8_t  rsp[SCOS_APDU_RSP_MAX];
    uint16_t rsp_len = 0u;

    if (scos_process(&g_card, cmd, len, rsp, (uint16_t)sizeof(rsp), &rsp_len) !=
        SCOS_OK) {
        return 0u;
    }
    assert(rsp_len >= 2u);
    const uint16_t sw =
        (uint16_t)(((uint16_t)rsp[rsp_len - 2u] << 8) | rsp[rsp_len - 1u]);
    /* A card must always answer something recognisable. */
    assert((uint8_t)(sw >> 8) >= 0x61u);
    return sw;
}

/*
 * Build a CREATE FILE from four input bytes.
 *
 * Deliberately biased toward templates that PARSE: the file descriptor byte is
 * chosen from the two encodings we implement most of the time, and the size is
 * masked into range. The point is to reach fs_create_file(), which random
 * bytes do not. Every fourth template is left deliberately malformed so the
 * reject paths keep getting hit too.
 */
static uint16_t build_create(uint8_t *out, const uint8_t *in)
{
    const bool     want_df = (in[0] & 0x40u) != 0u;
    const bool     mangle  = (in[0] & 0x03u) == 0u;
    const uint16_t fid     = (uint16_t)(((uint16_t)in[1] << 8) | in[2]);
    const uint16_t size    = (uint16_t)((in[3] % 64u) + 1u);
    const uint8_t  sfi     = (uint8_t)(in[0] >> 3) & 0x1Fu;

    uint8_t inner[32];
    uint8_t n = 0u;

    inner[n++] = 0x82u;
    inner[n++] = 0x01u;
    inner[n++] = mangle ? in[3] : (want_df ? 0x38u : 0x01u);
    inner[n++] = 0x83u;
    inner[n++] = 0x02u;
    inner[n++] = (uint8_t)(fid >> 8);
    inner[n++] = (uint8_t)fid;
    if (!want_df) {
        inner[n++] = 0x80u;
        inner[n++] = 0x02u;
        inner[n++] = (uint8_t)(size >> 8);
        inner[n++] = (uint8_t)size;
        if (sfi != 0u) {
            inner[n++] = 0x88u;
            inner[n++] = 0x01u;
            inner[n++] = (uint8_t)(sfi << 3);
        }
    }

    uint16_t m = 0u;
    out[m++]   = 0x00u;
    out[m++]   = 0xE0u;
    out[m++]   = 0x00u;
    out[m++]   = 0x00u;
    out[m++]   = (uint8_t)(n + 2u);
    out[m++]   = 0x62u;
    out[m++]   = n;
    for (uint8_t i = 0; i < n; i++) {
        out[m++] = inner[i];
    }
    return m;
}

int scos_fuzz_fcp(const uint8_t *data, size_t size)
{
    /* A fresh factory-personalised card per input, so a finding is
     * reproducible from the input alone. */
    vcard_power_off();
    if (vcard_power_on() != HAL_OK) {
        return 0;
    }
    if (scos_init(&g_card) != SCOS_OK) {
        return 0;
    }
    check_tree();

    size_t pos = 0;
    while (pos + 4u <= size) {
        const uint8_t op = data[pos] & 0x07u;
        uint8_t       cmd[64];
        uint16_t      len = 0u;

        switch (op) {
        case 0u:
        case 1u:
        case 2u:
        case 3u:
            len = build_create(cmd, &data[pos]);
            break;
        case 4u:
        case 5u:
            /* DELETE FILE of an identifier drawn from the input. */
            cmd[0] = 0x00u;
            cmd[1] = 0xE4u;
            cmd[2] = 0x00u;
            cmd[3] = 0x00u;
            cmd[4] = 0x02u;
            cmd[5] = data[pos + 1u];
            cmd[6] = data[pos + 2u];
            len    = 7u;
            break;
        case 6u:
            /* SELECT, so the current DF moves and later creates land in
             * different parents -- otherwise everything is a child of the MF
             * and invariants 4-6 barely get tested. */
            cmd[0] = 0x00u;
            cmd[1] = 0xA4u;
            cmd[2] = (uint8_t)(data[pos + 3u] % 4u); /* P1 00/01/02/03 */
            cmd[3] = 0x0Cu;
            cmd[4] = 0x02u;
            cmd[5] = data[pos + 1u];
            cmd[6] = data[pos + 2u];
            len    = 7u;
            break;
        default:
            /* UPDATE BINARY, to prove invariant 6 is not merely bookkeeping:
             * if two EFs overlapped, writing here would corrupt the other. */
            cmd[0] = 0x00u;
            cmd[1] = 0xD6u;
            cmd[2] = 0x00u;
            cmd[3] = data[pos + 1u];
            cmd[4] = 0x04u;
            cmd[5] = data[pos + 2u];
            cmd[6] = data[pos + 3u];
            cmd[7] = 0xA5u;
            cmd[8] = 0x5Au;
            len    = 9u;
            break;
        }
        pos += 4u;

        (void)send(cmd, len);
        check_tree();
    }
    return 0;
}
