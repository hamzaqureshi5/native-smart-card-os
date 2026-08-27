/* SPDX-License-Identifier: MIT
 *
 * test_boot_loader.c -- the SCV1 boot loader.
 *
 * This code will sit in mask ROM. It cannot be patched after the part is made,
 * and it is the only thing standing between a blank chip and a usable one, so
 * the tests lean hard on the failure paths: wrong order, wrong length, double
 * writes, damaged headers, images that pass CRC but are not code.
 */
#include "boot/boot_loader.h"
#include "boot/cflash.h"
#include "os/crc16.h"

#include "scos_test.h"

#include <string.h>

/* A miniature SCV1: same page size and geometry shape, small enough to make a
 * whole-region test fast. Addresses match the real chip so that the
 * plausibility check is exercised with the values it will actually see. */
#define T_PAGE      1024u
#define T_OSFLASH   (8u * 1024u)
#define T_OSHDR     1024u
#define T_LOAD_ADDR 0x00002000u
#define T_SRAM_BASE 0x20000000u
#define T_SRAM_SIZE (16u * 1024u)

static uint8_t g_osflash[T_OSFLASH];
static uint8_t g_oshdr[T_OSHDR];

static void chip_blank(boot_ctx *ctx)
{
    memset(g_osflash, 0xFF, sizeof(g_osflash));
    memset(g_oshdr,   0xFF, sizeof(g_oshdr));
    boot_ctx_init(ctx, g_osflash, T_OSFLASH, g_oshdr, T_OSHDR, T_PAGE,
                  T_LOAD_ADDR, T_SRAM_BASE, T_SRAM_SIZE);
}

/* Build a minimal image that looks like ARMv7-M firmware: SP at the top of
 * SRAM, reset vector into the image with the Thumb bit set. */
static uint32_t make_image(uint8_t *out, uint32_t n)
{
    const uint32_t sp = T_SRAM_BASE + T_SRAM_SIZE;
    /* Entry at offset 8 -- immediately after the two vectors -- so that even
     * the smallest test image contains its own entry point. An earlier version
     * used offset 0x40 and the 64-byte image legitimately failed the bounds
     * check; the check was right and the test data was wrong. */
    const uint32_t pc = T_LOAD_ADDR + 0x09u; /* offset 8, Thumb bit set */
    out[0] = (uint8_t)sp;         out[1] = (uint8_t)(sp >> 8);
    out[2] = (uint8_t)(sp >> 16); out[3] = (uint8_t)(sp >> 24);
    out[4] = (uint8_t)pc;         out[5] = (uint8_t)(pc >> 8);
    out[6] = (uint8_t)(pc >> 16); out[7] = (uint8_t)(pc >> 24);
    for (uint32_t i = 8; i < n; i++) {
        out[i] = (uint8_t)(i * 7u);
    }
    return n;
}

/* Response buffer poisoned before every call so a command that claims to
 * return data but does not is caught. */
static uint8_t  g_rsp[64];
static uint32_t g_rsp_len;

static uint16_t send(boot_ctx *ctx, const uint8_t *cmd, uint32_t len, boot_action *act)
{
    boot_action local = BOOT_ACT_NONE;
    memset(g_rsp, 0xA5, sizeof(g_rsp));
    g_rsp_len = 0xFFFFFFFFu;
    const uint16_t sw = boot_handle(ctx, cmd, len, g_rsp, sizeof(g_rsp),
                                    &g_rsp_len, (act != NULL) ? act : &local);
    return sw;
}

static uint16_t send_erase(boot_ctx *ctx)
{
    const uint8_t c[] = { 0x80, 0x0E, 0x00, 0x00, 0x00 };
    return send(ctx, c, sizeof(c), NULL);
}

/* Load `img` in 128-byte blocks. Returns the first non-9000 SW, or 0x9000. */
static uint16_t send_image(boot_ctx *ctx, const uint8_t *img, uint32_t n)
{
    uint8_t cmd[5 + BOOT_BLOCK_SIZE];
    for (uint32_t off = 0, blk = 0; off < n; off += BOOT_BLOCK_SIZE, blk++) {
        uint32_t chunk = n - off;
        if (chunk > BOOT_BLOCK_SIZE) { chunk = BOOT_BLOCK_SIZE; }
        cmd[0] = 0x80; cmd[1] = 0x54;
        cmd[2] = (uint8_t)(blk >> 8); cmd[3] = (uint8_t)blk;
        cmd[4] = (uint8_t)chunk;
        memcpy(&cmd[5], &img[off], chunk);
        const uint16_t sw = send(ctx, cmd, 5u + chunk, NULL);
        if (sw != 0x9000u) { return sw; }
    }
    return 0x9000u;
}

static uint16_t send_verify(boot_ctx *ctx, uint32_t len, uint16_t crc)
{
    const uint8_t c[] = { 0x80, 0xA0, 0x00, 0x00, 0x06,
                          (uint8_t)(len >> 24), (uint8_t)(len >> 16),
                          (uint8_t)(len >> 8),  (uint8_t)len,
                          (uint8_t)(crc >> 8),  (uint8_t)crc };
    return send(ctx, c, sizeof(c), NULL);
}

static uint16_t send_activate(boot_ctx *ctx)
{
    const uint8_t c[] = { 0x80, 0x44, 0x00, 0x00, 0x00 };
    return send(ctx, c, sizeof(c), NULL);
}

/* ------------------------------------------------------- the happy path --- */

TEST(blank_chip_reports_blank)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    CHECK_EQ(boot_slot_check(g_oshdr, T_OSHDR, g_osflash, T_OSFLASH, NULL),
             BOOT_SLOT_BLANK);
}

TEST(full_load_sequence)
{
    boot_ctx ctx;
    chip_blank(&ctx);

    uint8_t img[600];
    const uint32_t n = make_image(img, sizeof(img));
    const uint16_t crc = crc16(img, n);

    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_HEX(send_image(&ctx, img, n), 0x9000);
    CHECK_HEX(send_verify(&ctx, n, crc), 0x9000);

    /* Verified but NOT yet active: a half-finished load must never boot. */
    CHECK_EQ(boot_slot_check(g_oshdr, T_OSHDR, g_osflash, T_OSFLASH, NULL),
             BOOT_SLOT_LOADED);

    CHECK_HEX(send_activate(&ctx), 0x9000);
    CHECK_EQ(boot_slot_check(g_oshdr, T_OSHDR, g_osflash, T_OSFLASH, NULL),
             BOOT_SLOT_ACTIVE);

    /* The image really is in flash, byte for byte. */
    CHECK(memcmp(g_osflash, img, n) == 0);
}

TEST(activate_is_idempotent)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    uint8_t img[256];
    const uint32_t n = make_image(img, sizeof(img));
    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_HEX(send_image(&ctx, img, n), 0x9000);
    CHECK_HEX(send_verify(&ctx, n, crc16(img, n)), 0x9000);
    CHECK_HEX(send_activate(&ctx), 0x9000);
    CHECK_HEX(send_activate(&ctx), 0x9000);
}

TEST(get_status_reports_the_slot)
{
    boot_ctx ctx;
    chip_blank(&ctx);

    const uint8_t c[] = { 0x80, 0xF2, 0x00, 0x00, 0x00 };
    CHECK_HEX(send(&ctx, c, sizeof(c), NULL), 0x9000);
    CHECK_EQ(g_rsp_len, BOOT_STATUS_RSP_LEN);
    CHECK_EQ(g_rsp[0], 1);                       /* protocol version        */
    CHECK_EQ(g_rsp[1], BOOT_SLOT_BLANK);
    CHECK_EQ(((uint32_t)g_rsp[2] << 24) | ((uint32_t)g_rsp[3] << 16) |
             ((uint32_t)g_rsp[4] << 8)  | g_rsp[5], T_OSFLASH);
    CHECK_EQ(g_rsp[12], BOOT_BLOCK_SIZE);
    CHECK_EQ(g_rsp[13], 0);                      /* not erased yet          */

    uint8_t img[256];
    const uint32_t n = make_image(img, sizeof(img));
    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_HEX(send_image(&ctx, img, n), 0x9000);
    CHECK_HEX(send_verify(&ctx, n, crc16(img, n)), 0x9000);
    CHECK_HEX(send_activate(&ctx), 0x9000);

    CHECK_HEX(send(&ctx, c, sizeof(c), NULL), 0x9000);
    CHECK_EQ(g_rsp[1], BOOT_SLOT_ACTIVE);
    CHECK_EQ(((uint32_t)g_rsp[6] << 24) | ((uint32_t)g_rsp[7] << 16) |
             ((uint32_t)g_rsp[8] << 8)  | g_rsp[9], n);
    CHECK_EQ(g_rsp[13], 1);
}

/* ------------------------------------------------------- ordering rules --- */

TEST(load_before_erase_is_refused)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    uint8_t img[128];
    (void)make_image(img, sizeof(img));
    /* 6985: an implicit erase here would silently destroy a working OS. */
    CHECK_HEX(send_image(&ctx, img, sizeof(img)), 0x6985);
}

TEST(verify_before_erase_is_refused)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    CHECK_HEX(send_verify(&ctx, 128u, 0x1234u), 0x6985);
}

TEST(activate_with_no_image_is_refused)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    CHECK_HEX(send_activate(&ctx), 0x6A82);
    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_HEX(send_activate(&ctx), 0x6A82);
}

TEST(restart_needs_an_active_image)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    const uint8_t c[] = { 0x80, 0xF0, 0x00, 0x00, 0x00 };
    boot_action act = BOOT_ACT_RESTART;
    CHECK_HEX(send(&ctx, c, sizeof(c), &act), 0x6A82);
    CHECK_EQ(act, BOOT_ACT_NONE);

    uint8_t img[128];
    const uint32_t n = make_image(img, sizeof(img));
    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_HEX(send_image(&ctx, img, n), 0x9000);
    CHECK_HEX(send_verify(&ctx, n, crc16(img, n)), 0x9000);

    /* Loaded but not active: still refuses. */
    CHECK_HEX(send(&ctx, c, sizeof(c), &act), 0x6A82);
    CHECK_EQ(act, BOOT_ACT_NONE);

    CHECK_HEX(send_activate(&ctx), 0x9000);
    CHECK_HEX(send(&ctx, c, sizeof(c), &act), 0x9000);
    CHECK_EQ(act, BOOT_ACT_RESTART);
}

/* --------------------------------------------------------- flash physics -- */

TEST(rewriting_a_block_with_different_data_is_refused)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    CHECK_HEX(send_erase(&ctx), 0x9000);

    uint8_t cmd[5 + 8] = { 0x80, 0x54, 0x00, 0x00, 0x08,
                           0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    CHECK_HEX(send(&ctx, cmd, sizeof(cmd), NULL), 0x9000);

    /* Sending the IDENTICAL block again succeeds, and that is correct: at the
     * cell level it re-clears bits that are already clear, which real flash
     * permits. Modelling it as an error would be inventing hardware behaviour.
     * The loader therefore does not promise to detect a duplicate block; what
     * it promises is never to produce a wrong image. */
    CHECK_HEX(send(&ctx, cmd, sizeof(cmd), NULL), 0x9000);
    CHECK_HEX(g_osflash[0], 0x11);

    /* Different data over the same block is the case that matters. Flash
     * cannot set a bit back to 1, so the loader must refuse rather than write
     * the AND of the two blocks and report success. */
    cmd[5] = 0x22;
    CHECK_HEX(send(&ctx, cmd, sizeof(cmd), NULL), 0x6985);
    CHECK_HEX(g_osflash[0], 0x11);      /* untouched */
    CHECK_HEX(g_osflash[7], 0x88);
}

TEST(program_only_clears_bits)
{
    uint8_t f[16];
    memset(f, 0xFF, sizeof(f));
    const uint8_t a[2] = { 0xF0, 0x0F };
    CHECK_EQ(cf_program(f, sizeof(f), 0u, a, 2u), CF_OK);
    /* 0x0F over 0xF0 needs bits 4..7 to go 0 -> 1. Refused, nothing written. */
    const uint8_t b[1] = { 0x0F };
    CHECK_EQ(cf_program(f, sizeof(f), 0u, b, 1u), CF_ERR_NOT_ERASED);
    CHECK_HEX(f[0], 0xF0);
    /* But clearing further bits within an already-programmed byte is legal. */
    const uint8_t c[1] = { 0x50 };
    CHECK_EQ(cf_program(f, sizeof(f), 0u, c, 1u), CF_OK);
    CHECK_HEX(f[0], 0x50);
}

TEST(erase_rejects_unaligned_and_out_of_range)
{
    uint8_t f[2048];
    memset(f, 0x00, sizeof(f));
    CHECK_EQ(cf_erase_page(f, sizeof(f), 1024u, 1u), CF_ERR_ALIGN);
    CHECK_EQ(cf_erase_page(f, sizeof(f), 1024u, 2048u), CF_ERR_RANGE);
    CHECK_EQ(cf_erase_page(f, sizeof(f), 1024u, 1024u), CF_OK);
    CHECK_HEX(f[1024], 0xFF);
    CHECK_HEX(f[1023], 0x00);          /* the other page untouched */
}

TEST(program_bounds_cannot_wrap)
{
    uint8_t f[64];
    memset(f, 0xFF, sizeof(f));
    const uint8_t src[4] = { 0, 0, 0, 0 };
    /* off + n overflows 32 bits if the arithmetic is done in uint32_t. */
    CHECK_EQ(cf_program(f, sizeof(f), 0xFFFFFFFFu, src, 4u), CF_ERR_RANGE);
    CHECK(cf_is_erased(f, sizeof(f)));
}

/* ----------------------------------------------------- damaged and hostile - */

TEST(verify_rejects_a_wrong_crc)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    uint8_t img[256];
    const uint32_t n = make_image(img, sizeof(img));
    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_HEX(send_image(&ctx, img, n), 0x9000);
    CHECK_HEX(send_verify(&ctx, n, (uint16_t)(crc16(img, n) ^ 0x0001u)),
              0x6A80);
    /* A failed VERIFY must not leave a header behind. */
    CHECK_EQ(boot_slot_check(g_oshdr, T_OSHDR, g_osflash, T_OSFLASH, NULL),
             BOOT_SLOT_BLANK);
}

TEST(verify_rejects_a_length_never_written)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    uint8_t img[128];
    const uint32_t n = make_image(img, sizeof(img));
    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_HEX(send_image(&ctx, img, n), 0x9000);
    CHECK_HEX(send_verify(&ctx, n + 1u, 0x0000u), 0x6A80);
    CHECK_HEX(send_verify(&ctx, T_OSFLASH + 1u, 0x0000u), 0x6A84);
    CHECK_HEX(send_verify(&ctx, 0u, 0x0000u), 0x6A84);
}

TEST(verify_rejects_a_valid_crc_over_non_code)
{
    /* The exact trap the plausibility check exists for: the bytes arrived
     * perfectly, the CRC matches, and jumping to them would fault. */
    boot_ctx ctx;
    chip_blank(&ctx);
    uint8_t junk[128];
    for (uint32_t i = 0; i < sizeof(junk); i++) { junk[i] = (uint8_t)i; }
    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_HEX(send_image(&ctx, junk, sizeof(junk)), 0x9000);
    CHECK_HEX(send_verify(&ctx, sizeof(junk), crc16(junk, sizeof(junk))),
              0x6984);
}

TEST(plausibility_checks_both_vectors)
{
    uint8_t img[64];
    (void)make_image(img, sizeof(img));
    CHECK(boot_image_plausible(img, sizeof(img), T_LOAD_ADDR,
                               T_SRAM_BASE, T_SRAM_SIZE));

    /* Stack pointer below SRAM. */
    uint8_t bad_sp[64];
    (void)make_image(bad_sp, sizeof(bad_sp));
    bad_sp[3] = 0x1F;
    CHECK(!boot_image_plausible(bad_sp, sizeof(bad_sp), T_LOAD_ADDR,
                                T_SRAM_BASE, T_SRAM_SIZE));

    /* Thumb bit clear -- an ARM-state vector, impossible on ARMv7-M. */
    uint8_t bad_thumb[64];
    (void)make_image(bad_thumb, sizeof(bad_thumb));
    bad_thumb[4] &= (uint8_t)0xFEu;
    CHECK(!boot_image_plausible(bad_thumb, sizeof(bad_thumb), T_LOAD_ADDR,
                                T_SRAM_BASE, T_SRAM_SIZE));

    /* Entry point past the end of the image. */
    uint8_t bad_pc[64];
    (void)make_image(bad_pc, sizeof(bad_pc));
    bad_pc[4] = 0x01; bad_pc[5] = 0xF0;   /* 0x0000F001 -> entry 0xF000 */
    CHECK(!boot_image_plausible(bad_pc, sizeof(bad_pc), T_LOAD_ADDR,
                                T_SRAM_BASE, T_SRAM_SIZE));

    /* Truncated. */
    CHECK(!boot_image_plausible(img, 7u, T_LOAD_ADDR, T_SRAM_BASE, T_SRAM_SIZE));
    CHECK(!boot_image_plausible(NULL, 64u, T_LOAD_ADDR, T_SRAM_BASE, T_SRAM_SIZE));
}

TEST(a_corrupted_image_stops_the_boot)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    uint8_t img[256];
    const uint32_t n = make_image(img, sizeof(img));
    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_HEX(send_image(&ctx, img, n), 0x9000);
    CHECK_HEX(send_verify(&ctx, n, crc16(img, n)), 0x9000);
    CHECK_HEX(send_activate(&ctx), 0x9000);
    CHECK_EQ(boot_slot_check(g_oshdr, T_OSHDR, g_osflash, T_OSFLASH, NULL),
             BOOT_SLOT_ACTIVE);

    /* One bit rots in the image. The header still says ACTIVE.
     * Use XOR, not AND: byte 100 of this image is 0xBC, whose bit 0 is already
     * clear, so the obvious "&= 0xFE" corrupted nothing and the test passed a
     * card that had not actually been damaged. */
    g_osflash[100] ^= (uint8_t)0x01u;
    CHECK_EQ(boot_slot_check(g_oshdr, T_OSHDR, g_osflash, T_OSFLASH, NULL),
             BOOT_SLOT_DAMAGED);
}

TEST(a_corrupted_header_reads_as_blank)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    uint8_t img[128];
    const uint32_t n = make_image(img, sizeof(img));
    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_HEX(send_image(&ctx, img, n), 0x9000);
    CHECK_HEX(send_verify(&ctx, n, crc16(img, n)), 0x9000);

    g_oshdr[7] ^= 0x01u;                  /* damage the length field */
    CHECK_EQ(boot_slot_check(g_oshdr, T_OSHDR, g_osflash, T_OSFLASH, NULL),
             BOOT_SLOT_BLANK);
}

TEST(malformed_apdus_never_succeed)
{
    boot_ctx ctx;
    chip_blank(&ctx);

    struct { const uint8_t *c; uint32_t n; uint16_t sw; const char *why; } cases[] = {
        { (const uint8_t[]){ 0x00, 0xF2, 0x00, 0x00, 0x00 }, 5, 0x6E00, "wrong CLA" },
        { (const uint8_t[]){ 0x80, 0xFF, 0x00, 0x00, 0x00 }, 5, 0x6D00, "unknown INS" },
        { (const uint8_t[]){ 0x80, 0xF2, 0x01, 0x00, 0x00 }, 5, 0x6A86, "P1 not 0" },
        { (const uint8_t[]){ 0x80, 0x0E, 0x00, 0x01, 0x00 }, 5, 0x6A86, "P2 not 0" },
        { (const uint8_t[]){ 0x80, 0x0E, 0x00 },             3, 0x6700, "short header" },
        { (const uint8_t[]){ 0x80, 0x0E, 0x00, 0x00, 0x05 }, 5, 0x6700, "Lc with no body" },
        { (const uint8_t[]){ 0x80, 0x54, 0x00, 0x00, 0x05, 0x01 }, 6, 0x6700, "Lc > body" },
        { (const uint8_t[]){ 0x80, 0x54, 0x00, 0x00, 0x01, 0x01, 0x02 }, 7, 0x6700, "Lc < body" },
        { (const uint8_t[]){ 0x80, 0xA0, 0x00, 0x00, 0x02, 0x01, 0x02 }, 7, 0x6700, "VERIFY Lc != 6" },
        { (const uint8_t[]){ 0x80, 0x54, 0x00, 0x00, 0x00 }, 5, 0x6700, "LOAD with no data" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const uint16_t sw = send(&ctx, cases[i].c, cases[i].n, NULL);
        if (sw != cases[i].sw) {
            (void)printf("      case '%s': got %04X want %04X\n",
                         cases[i].why, sw, cases[i].sw);
        }
        CHECK_HEX(sw, cases[i].sw);
    }
    /* None of that touched the flash. */
    CHECK(cf_is_erased(g_osflash, T_OSFLASH));
    CHECK(cf_is_erased(g_oshdr, T_OSHDR));
}

TEST(block_index_cannot_reach_past_the_slot)
{
    boot_ctx ctx;
    chip_blank(&ctx);
    CHECK_HEX(send_erase(&ctx), 0x9000);
    /* Block 0xFFFF -> offset 8,388,480, far outside an 8 KB slot. */
    const uint8_t c[] = { 0x80, 0x54, 0xFF, 0xFF, 0x01, 0xAA };
    CHECK_HEX(send(&ctx, c, sizeof(c), NULL), 0x6A84);
    CHECK(cf_is_erased(g_osflash, T_OSFLASH));

    /* The last legal block, and the first illegal one. */
    const uint32_t last = (T_OSFLASH / BOOT_BLOCK_SIZE) - 1u;
    uint8_t ok[5 + BOOT_BLOCK_SIZE];
    ok[0] = 0x80; ok[1] = 0x54;
    ok[2] = (uint8_t)(last >> 8); ok[3] = (uint8_t)last;
    ok[4] = (uint8_t)BOOT_BLOCK_SIZE;
    memset(&ok[5], 0x5A, BOOT_BLOCK_SIZE);
    CHECK_HEX(send(&ctx, ok, sizeof(ok), NULL), 0x9000);

    ok[2] = (uint8_t)((last + 1u) >> 8); ok[3] = (uint8_t)(last + 1u);
    CHECK_HEX(send(&ctx, ok, sizeof(ok), NULL), 0x6A84);
}

TEST(erase_recycles_a_loaded_card)
{
    /* This is what recycle.ldr does: put a fully loaded, active card back to
     * the state it left the factory in. */
    boot_ctx ctx;
    chip_blank(&ctx);
    uint8_t img[512];
    const uint32_t n = make_image(img, sizeof(img));
    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_HEX(send_image(&ctx, img, n), 0x9000);
    CHECK_HEX(send_verify(&ctx, n, crc16(img, n)), 0x9000);
    CHECK_HEX(send_activate(&ctx), 0x9000);
    CHECK_EQ(boot_slot_check(g_oshdr, T_OSHDR, g_osflash, T_OSFLASH, NULL),
             BOOT_SLOT_ACTIVE);

    CHECK_HEX(send_erase(&ctx), 0x9000);
    CHECK_EQ(boot_slot_check(g_oshdr, T_OSHDR, g_osflash, T_OSFLASH, NULL),
             BOOT_SLOT_BLANK);
    CHECK(cf_is_erased(g_osflash, T_OSFLASH));
    CHECK(cf_is_erased(g_oshdr, T_OSHDR));

    /* And it can be reloaded with something different afterwards. */
    uint8_t img2[256];
    const uint32_t n2 = make_image(img2, sizeof(img2));
    img2[100] = 0xC3;
    CHECK_HEX(send_image(&ctx, img2, n2), 0x9000);
    CHECK_HEX(send_verify(&ctx, n2, crc16(img2, n2)), 0x9000);
    CHECK_HEX(send_activate(&ctx), 0x9000);
    CHECK_HEX(g_osflash[100], 0xC3);
}

int main(void)
{
    RUN(blank_chip_reports_blank);
    RUN(full_load_sequence);
    RUN(activate_is_idempotent);
    RUN(get_status_reports_the_slot);
    RUN(load_before_erase_is_refused);
    RUN(verify_before_erase_is_refused);
    RUN(activate_with_no_image_is_refused);
    RUN(restart_needs_an_active_image);
    RUN(rewriting_a_block_with_different_data_is_refused);
    RUN(program_only_clears_bits);
    RUN(erase_rejects_unaligned_and_out_of_range);
    RUN(program_bounds_cannot_wrap);
    RUN(verify_rejects_a_wrong_crc);
    RUN(verify_rejects_a_length_never_written);
    RUN(verify_rejects_a_valid_crc_over_non_code);
    RUN(plausibility_checks_both_vectors);
    RUN(a_corrupted_image_stops_the_boot);
    RUN(a_corrupted_header_reads_as_blank);
    RUN(malformed_apdus_never_succeed);
    RUN(block_index_cannot_reach_past_the_slot);
    RUN(erase_recycles_a_loaded_card);
    TEST_MAIN_END();
}
