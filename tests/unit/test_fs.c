/* SPDX-License-Identifier: MIT
 *
 * test_fs.c -- The filesystem: both layers, plus READ/UPDATE BINARY.
 *
 * Structured to mirror the layering: physical-layer tests first (descriptors,
 * CRC, allocation), then logical (tree, selection), then the command surface.
 * A failure's position tells you which layer broke.
 */
#include "apdu/sw.h"
#include "filesystem/fs.h"
#include "filesystem/fs_store.h"
#include "hal/hal.h"
#include "hal/sim/vcard.h"
#include "os/crc16.h"
#include "os/kernel.h"
#include "os/os_mem.h"

#include "scos_test.h"

static scos_kernel g_card;

static void fresh(void)
{
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(scos_init(&g_card), SCOS_OK);
}

static uint16_t send(const uint8_t *cmd, uint16_t len, uint8_t *out_data,
                     uint16_t *out_data_len)
{
    uint8_t  rsp[SCOS_APDU_RSP_MAX];
    uint16_t rsp_len = 0u;

    CHECK_EQ(
        scos_process(&g_card, cmd, len, rsp, (uint16_t)sizeof(rsp), &rsp_len),
        SCOS_OK);
    CHECK(rsp_len >= 2u);
    if (rsp_len < 2u) {
        return 0u;
    }
    const uint16_t dlen = (uint16_t)(rsp_len - 2u);
    if (out_data != NULL && dlen > 0u) {
        (void)os_memcpy_checked(out_data, dlen, rsp, dlen);
    }
    if (out_data_len != NULL) {
        *out_data_len = dlen;
    }
    return (uint16_t)(((uint16_t)rsp[rsp_len - 2u] << 8) | rsp[rsp_len - 1u]);
}

/* ======================================================= physical layer === */

TEST(crc16_known_answer)
{
    /* The CCITT-FALSE check value. A CRC implementation that is subtly wrong
     * still "works" until an image written by one build is read by another. */
    CHECK_HEX(crc16("123456789", 9u), 0x29B1);
    CHECK_HEX(crc16("", 0u), 0xFFFF);
    /* A single-bit change must alter the CRC -- the whole point. */
    CHECK(crc16("\x01", 1u) != crc16("\x00", 1u));
}

TEST(format_produces_an_empty_table)
{
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);

    /* A blank chip is not formatted. */
    CHECK_EQ(fs_store_mount(), FS_ERR_NOT_FORMATTED);

    CHECK_EQ(fs_store_format(), FS_OK);
    CHECK(fs_store_is_mounted());
    CHECK_EQ(fs_store_max_files(), FS_MAX_FILES);

    for (uint16_t i = 0; i < FS_MAX_FILES; i++) {
        CHECK(fs_store_slot_is_free(i));
        fs_descriptor d;
        CHECK_EQ(fs_store_read_desc(i, &d), FS_ERR_NOT_FOUND);
    }
    CHECK_EQ(fs_store_find_free_slot(), 0);
}

TEST(descriptor_roundtrip_survives_serialisation)
{
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(fs_store_format(), FS_OK);

    fs_descriptor in;
    os_memset(&in, 0, sizeof(in));
    in.file_id     = 0xABCDu;
    in.type        = FS_TYPE_EF_TRANSPARENT;
    in.lifecycle   = FS_LC_ACTIVATED;
    in.parent      = 0x0007u;
    in.size        = 1234u;
    in.data_offset = 0x00012345u;
    in.ac_read     = 0x11u;
    in.ac_update   = 0x22u;
    in.sfi         = 9u;
    in.flags       = 0x44u;

    CHECK_EQ(fs_store_write_desc(5u, &in), FS_OK);
    CHECK(!fs_store_slot_is_free(5u));

    fs_descriptor out;
    CHECK_EQ(fs_store_read_desc(5u, &out), FS_OK);

    /* Every field, because a serialisation bug typically loses exactly one. */
    CHECK_HEX(out.file_id, 0xABCD);
    CHECK_EQ(out.type, FS_TYPE_EF_TRANSPARENT);
    CHECK_EQ(out.lifecycle, FS_LC_ACTIVATED);
    CHECK_HEX(out.parent, 0x0007);
    CHECK_EQ(out.size, 1234);
    CHECK_EQ(out.data_offset, 0x00012345u);
    CHECK_HEX(out.ac_read, 0x11);
    CHECK_HEX(out.ac_update, 0x22);
    CHECK_EQ(out.sfi, 9);
    CHECK_HEX(out.flags, 0x44);

    /* Freeing must make it unreadable again. */
    CHECK_EQ(fs_store_free_desc(5u), FS_OK);
    CHECK(fs_store_slot_is_free(5u));
    CHECK_EQ(fs_store_read_desc(5u, &out), FS_ERR_NOT_FOUND);
}

/*
 * Corruption detection. Reach around the filesystem and flip a byte in NVM
 * directly, exactly as a torn write or a worn-out cell would.
 */
TEST(corrupt_descriptor_is_detected_not_used)
{
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(fs_personalise(), FS_OK);

    fs_descriptor d;
    CHECK_EQ(fs_store_read_desc(1u, &d), FS_OK);
    CHECK_HEX(d.file_id, 0x2F00);

    /* Descriptor 1 lives at EEPROM offset 16 + 1*20 = 36. Flip its size field
     * without fixing the CRC -- which is what corruption looks like. */
    uint8_t byte = 0u;
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 36u + 6u, &byte, 1u), HAL_OK);
    byte = (uint8_t)(byte ^ 0xFFu);
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, 36u + 6u, &byte, 1u), HAL_OK);

    /* It must be reported as corrupt, NOT returned with a wrong size. */
    CHECK_EQ(fs_store_read_desc(1u, &d), FS_ERR_CORRUPT);

    /* And one corrupt descriptor must not make the rest of the card
     * unreachable: the DF and its children are still findable. */
    uint16_t idx = FS_INVALID_INDEX;
    CHECK_EQ(fs_find_child(0u, 0x7F10u, &idx), FS_OK);
    CHECK_EQ(idx, 2);
}

TEST(corrupt_superblock_refuses_to_mount)
{
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(fs_personalise(), FS_OK);

    uint8_t byte = 0u;
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 8u, &byte, 1u), HAL_OK);
    byte = (uint8_t)(byte ^ 0x55u);
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, 8u, &byte, 1u), HAL_OK);

    /* Refused, NOT silently reformatted. Auto-formatting would destroy the
     * data most worth recovering and would give anyone able to corrupt one
     * byte a reliable card-wipe primitive. */
    CHECK_EQ(fs_store_mount(), FS_ERR_CORRUPT);

    /* And the OS must come up dead-but-answering rather than pretend. */
    CHECK_EQ(scos_init(&g_card), SCOS_ERR_STATE);
    CHECK_EQ(g_card.lifecycle, SCOS_LC_FS_ERROR);
    const uint8_t sel[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00 };
    CHECK_HEX(send(sel, sizeof(sel), NULL, NULL), SW_MEMORY_FAILURE);
}

TEST(unknown_layout_version_refuses_to_mount)
{
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(fs_personalise(), FS_OK);

    /* Bump the version and fix the CRC, as a future firmware would. */
    uint8_t sb[FS_SUPERBLOCK_SIZE];
    CHECK_EQ(hal_nvm_read(HAL_NVM_EEPROM, 0u, sb, sizeof(sb)), HAL_OK);
    sb[4]            = 0x00u;
    sb[5]            = 0x63u; /* version 99 */
    const uint16_t c = crc16(sb, 14u);
    sb[14]           = (uint8_t)(c >> 8);
    sb[15]           = (uint8_t)(c & 0xFFu);
    CHECK_EQ(hal_nvm_write(HAL_NVM_EEPROM, 0u, sb, sizeof(sb)), HAL_OK);

    /* A valid image of a layout we do not understand. Guessing at it would be
     * worse than declining. */
    CHECK_EQ(fs_store_mount(), FS_ERR_VERSION);
}

TEST(allocation_finds_a_free_extent_and_reserves_nothing)
{
    /*
     * REWRITTEN, because the previous version hung for ten minutes.
     *
     * It called fs_store_alloc_data() repeatedly without ever writing a
     * descriptor, relying on the old bump allocator's side effect of advancing
     * `data_top`. The allocator now derives its answer from the live
     * descriptors and reserves nothing, so every call returned offset 0, the
     * free count never moved, and `while (free >= 30000)` never ended.
     *
     * The hang was the test's assumption, not a bug in the allocator -- but the
     * old NAME invited the assumption, which is why the function is now
     * fs_store_find_free_data(). This test pins the real contract.
     */
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(fs_store_format(), FS_OK);

    /* Nothing is allocated, so the first fit is offset 0 -- and asking twice
     * gives the SAME answer, because asking is not taking. */
    uint32_t a = 0xFFFFFFFFu, b = 0xFFFFFFFFu;
    CHECK_EQ(fs_store_find_free_data(100u, &a), FS_OK);
    CHECK_EQ(fs_store_find_free_data(100u, &b), FS_OK);
    CHECK_EQ(a, 0);
    CHECK_EQ(b, 0);
    CHECK_EQ(fs_store_data_free(), SCOS_FLASH_BYTES);

    /* Writing a descriptor is what takes the space. */
    fs_descriptor d;
    os_memset(&d, 0, sizeof(d));
    d.file_id   = 0x3F00u;
    d.type      = FS_TYPE_MF;
    d.lifecycle = FS_LC_ACTIVATED;
    d.parent    = FS_NO_PARENT;
    d.sfi       = FS_NO_SFI;
    CHECK_EQ(fs_store_write_desc(0u, &d), FS_OK);

    os_memset(&d, 0, sizeof(d));
    d.file_id     = 0x2A01u;
    d.type        = FS_TYPE_EF_TRANSPARENT;
    d.lifecycle   = FS_LC_ACTIVATED;
    d.parent      = 0u;
    d.size        = 100u;
    d.data_offset = a;
    d.sfi         = FS_NO_SFI;
    CHECK_EQ(fs_store_write_desc(1u, &d), FS_OK);

    CHECK_EQ(fs_store_data_free(), SCOS_FLASH_BYTES - 100u);

    /* Now the next fit is past it. */
    uint32_t c = 0u;
    CHECK_EQ(fs_store_find_free_data(100u, &c), FS_OK);
    CHECK_EQ(c, 100);
}

TEST(a_deleted_extent_is_reused_rather_than_leaked)
{
    /*
     * THE M4 FIX, and the reason the allocator changed at all.
     *
     * With the bump allocator, DELETE FILE freed the descriptor slot and
     * stranded the EF's data bytes for good -- so 32 slots against a 256 KB
     * data area meant repeated create/delete cycles exhausted the space.
     * test_create.c asserted that leak as a known limitation from M2b onward,
     * waiting for transactions to make a fix safe.
     */
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(fs_store_format(), FS_OK);

    fs_descriptor mf;
    os_memset(&mf, 0, sizeof(mf));
    mf.file_id   = 0x3F00u;
    mf.type      = FS_TYPE_MF;
    mf.lifecycle = FS_LC_ACTIVATED;
    mf.parent    = FS_NO_PARENT;
    mf.sfi       = FS_NO_SFI;
    CHECK_EQ(fs_store_write_desc(0u, &mf), FS_OK);

    /* Two EFs, back to back. */
    uint32_t o1 = 0u, o2 = 0u;
    CHECK_EQ(fs_store_find_free_data(500u, &o1), FS_OK);
    fs_descriptor e1;
    os_memset(&e1, 0, sizeof(e1));
    e1.file_id     = 0x2A01u;
    e1.type        = FS_TYPE_EF_TRANSPARENT;
    e1.lifecycle   = FS_LC_ACTIVATED;
    e1.parent      = 0u;
    e1.size        = 500u;
    e1.data_offset = o1;
    e1.sfi         = FS_NO_SFI;
    CHECK_EQ(fs_store_write_desc(1u, &e1), FS_OK);

    CHECK_EQ(fs_store_find_free_data(500u, &o2), FS_OK);
    CHECK_EQ(o2, 500); /* past the first */
    fs_descriptor e2 = e1;
    e2.file_id       = 0x2A02u;
    e2.data_offset   = o2;
    CHECK_EQ(fs_store_write_desc(2u, &e2), FS_OK);

    CHECK_EQ(fs_store_data_free(), SCOS_FLASH_BYTES - 1000u);

    /* Free the FIRST one. Its extent must become available again. */
    CHECK_EQ(fs_store_free_desc(1u), FS_OK);
    CHECK_EQ(fs_store_data_free(), SCOS_FLASH_BYTES - 500u);

    uint32_t o3 = 0u;
    CHECK_EQ(fs_store_find_free_data(500u, &o3), FS_OK);
    CHECK_HEX(o3, o1); /* THE POINT: the hole is reused, not skipped */

    /* And a request too big for the hole goes past the second file rather than
     * overlapping it -- first fit means first that FITS. */
    uint32_t o4 = 0u;
    CHECK_EQ(fs_store_find_free_data(600u, &o4), FS_OK);
    CHECK_EQ(o4, 1000);
}

TEST(exhaustion_is_reported_not_wrapped)
{
    /* A size that cannot fit must be refused, never wrapped into a small
     * offset that overlaps a live file. */
    vcard_power_off();
    CHECK_EQ(vcard_power_on(), HAL_OK);
    CHECK_EQ(fs_store_format(), FS_OK);

    fs_descriptor mf;
    os_memset(&mf, 0, sizeof(mf));
    mf.file_id   = 0x3F00u;
    mf.type      = FS_TYPE_MF;
    mf.lifecycle = FS_LC_ACTIVATED;
    mf.parent    = FS_NO_PARENT;
    mf.sfi       = FS_NO_SFI;
    CHECK_EQ(fs_store_write_desc(0u, &mf), FS_OK);

    /* Fill the data area with max-size EFs until the slots run out, writing a
     * descriptor each time so the space is genuinely taken. Bounded by
     * FS_MAX_FILES, so this cannot loop for ever the way its predecessor did. */
    uint16_t placed = 0u;
    for (uint16_t idx = 1u; idx < FS_MAX_FILES; idx++) {
        uint32_t off = 0u;
        if (fs_store_find_free_data(FS_MAX_EF_SIZE, &off) != FS_OK) {
            break;
        }
        fs_descriptor e;
        os_memset(&e, 0, sizeof(e));
        e.file_id     = (uint16_t)(0x2B00u + idx);
        e.type        = FS_TYPE_EF_TRANSPARENT;
        e.lifecycle   = FS_LC_ACTIVATED;
        e.parent      = 0u;
        e.size        = FS_MAX_EF_SIZE;
        e.data_offset = off;
        e.sfi         = FS_NO_SFI;
        CHECK_EQ(fs_store_write_desc(idx, &e), FS_OK);
        placed++;
    }
    CHECK(placed > 0u);

    /* Whatever is left, one more max-size EF must not fit -- and asking must
     * not corrupt anything. */
    const uint32_t left = fs_store_data_free();
    uint32_t       off  = 0u;
    if (left < FS_MAX_EF_SIZE) {
        CHECK_EQ(fs_store_find_free_data(FS_MAX_EF_SIZE, &off),
                 FS_ERR_NO_SPACE);
        CHECK_EQ(off, 0); /* zeroed on failure, not left as a stale offset */
    }
    CHECK_EQ(fs_store_data_free(), left); /* asking consumes nothing */
}

/* ======================================================== logical layer === */

TEST(factory_layout_is_as_documented)
{
    fresh();

    struct {
        uint16_t idx;
        uint16_t fid;
        uint16_t parent;
        uint16_t size;
    } const expect[] = {
        { 0u, 0x3F00u, FS_NO_PARENT, 0u }, { 1u, 0x2F00u, 0u, 32u },
        { 2u, 0x7F10u, 0u, 0u },           { 3u, 0x6F01u, 2u, 64u },
        { 4u, 0x6F02u, 2u, 16u },
    };

    for (unsigned i = 0; i < sizeof(expect) / sizeof(expect[0]); i++) {
        fs_descriptor d;
        CHECK_EQ(fs_get(expect[i].idx, &d), FS_OK);
        CHECK_HEX(d.file_id, expect[i].fid);
        CHECK_HEX(d.parent, expect[i].parent);
        CHECK_EQ(d.size, expect[i].size);
        CHECK_EQ(d.lifecycle, FS_LC_ACTIVATED);
    }
    CHECK_EQ(fs_child_count(0u), 3); /* 2F00, 7F10 and EF.ATR 2F01 */
    CHECK_EQ(fs_child_count(2u), 2); /* 6F01 and 6F02 */
    CHECK_EQ(fs_child_count(3u), 0); /* an EF has no children */
}

TEST(ef_atr_says_what_the_card_can_do)
{
    fresh();

    /*
     * EF.ATR is the one file whose contents are a CLAIM about the card, so the
     * test asserts the bytes rather than just that the file exists. A wrong
     * byte here does not break the card -- it makes the card lie to every
     * reader that asks, which is worse and much harder to notice.
     */
    fs_selection sel;
    fs_selection_reset(&sel);
    CHECK_EQ(fs_select_by_fid(&sel, FS_EF_ATR_FID), FS_OK);

    fs_descriptor d;
    CHECK_EQ(fs_get(sel.cur_ef, &d), FS_OK);
    CHECK_EQ(d.size, FS_EF_ATR_SIZE);
    CHECK_EQ(d.parent, 0u); /* directly under the MF, as ISO reserves */
    /* No SFI: 1..30 is a scarce range and 2F01 is already well known. */
    CHECK_EQ(d.sfi, FS_NO_SFI);

    uint8_t  buf[FS_EF_ATR_SIZE];
    uint16_t got = 0u;
    CHECK_EQ(fs_ef_read(sel.cur_ef, 0u, FS_EF_ATR_SIZE, buf, &got), FS_OK);
    CHECK_EQ(got, FS_EF_ATR_SIZE);

    CHECK_HEX(buf[0], 0x47); /* card capabilities data object     */
    CHECK_HEX(buf[1], 0x03); /* three bytes of value              */
    CHECK_HEX(buf[2], 0x00); /* DF selection methods: not claimed */
    CHECK_HEX(buf[3], 0x00); /* data coding byte:     not claimed */

    /* Extended Lc/Le supported... */
    CHECK((buf[4] & FS_CARD_CAP_EXTENDED_LENGTH) != 0u);
    /* ...and NOTHING else. In particular the command-chaining bit must stay
     * clear, because apdu_check_cla() refuses chaining with 6884 and a card
     * that advertises a command it rejects is worse than one that advertises
     * nothing. */
    CHECK_HEX(buf[4], FS_CARD_CAP_EXTENDED_LENGTH);

    /* The file is exactly as long as its content. Trailing 0xFF would read to
     * a BER-TLV parser as the start of a malformed object rather than as
     * end-of-data. */
    CHECK_EQ(fs_ef_read(sel.cur_ef, 0u, 64u, buf, &got), FS_OK);
    CHECK_EQ(got, FS_EF_ATR_SIZE);
}

TEST(sfi_is_scoped_to_its_parent_df)
{
    fresh();
    uint16_t idx = FS_INVALID_INDEX;

    /* SFI 1 exists under the MF (2F00) and again under 7F10 (6F01). They must
     * resolve differently -- short identifiers are per-DF, not global, and that
     * scoping is what stops one application reaching another's files. */
    CHECK_EQ(fs_find_by_sfi(0u, 1u, &idx), FS_OK);
    CHECK_EQ(idx, 1);
    CHECK_EQ(fs_find_by_sfi(2u, 1u, &idx), FS_OK);
    CHECK_EQ(idx, 3);
    CHECK_EQ(fs_find_by_sfi(2u, 2u, &idx), FS_OK);
    CHECK_EQ(idx, 4);

    CHECK_EQ(fs_find_by_sfi(0u, 2u, &idx), FS_ERR_NOT_FOUND);
    /* ISO reserves 0 and limits SFIs to 30. */
    CHECK_EQ(fs_find_by_sfi(0u, 0u, &idx), FS_ERR_PARAM);
    CHECK_EQ(fs_find_by_sfi(0u, 31u, &idx), FS_ERR_PARAM);
}

TEST(selecting_a_df_clears_the_current_ef)
{
    fresh();
    fs_selection sel;
    fs_selection_reset(&sel);

    /* Select an EF under the MF. */
    CHECK_EQ(fs_select_by_fid(&sel, 0x2F00u), FS_OK);
    CHECK_EQ(sel.cur_df, 0);
    CHECK_EQ(sel.cur_ef, 1);

    /* Now select a DF. The EF must be dropped -- otherwise a later READ BINARY
     * would act on a file belonging to a different DF than the one selected. */
    CHECK_EQ(fs_select_by_fid(&sel, 0x7F10u), FS_OK);
    CHECK_EQ(sel.cur_df, 2);
    CHECK_EQ(sel.cur_ef, FS_INVALID_INDEX);
}

TEST(selection_search_order_is_scoped)
{
    fresh();
    fs_selection sel;
    fs_selection_reset(&sel);

    /* From the MF, 6F01 is NOT reachable by identifier: it is a child of 7F10,
     * not of the MF. There is deliberately no global search -- that would let
     * one application reach another's files by FID alone. */
    CHECK_EQ(fs_select_by_fid(&sel, 0x6F01u), FS_ERR_NOT_FOUND);

    /* Enter the DF, and now it is reachable. */
    CHECK_EQ(fs_select_by_fid(&sel, 0x7F10u), FS_OK);
    CHECK_EQ(fs_select_by_fid(&sel, 0x6F01u), FS_OK);
    CHECK_EQ(sel.cur_ef, 3);

    /* And 2F00, a child of the MF, is no longer reachable from inside 7F10. */
    CHECK_EQ(fs_select_by_fid(&sel, 0x2F00u), FS_ERR_NOT_FOUND);

    /* The parent is reachable by identifier (rule 4), and by P1=03. */
    CHECK_EQ(fs_select_by_fid(&sel, 0x3F00u), FS_OK);
    CHECK_EQ(sel.cur_df, 0);
}

TEST(select_parent_and_typed_children)
{
    fresh();
    fs_selection sel;
    fs_selection_reset(&sel);

    CHECK_EQ(fs_select_child_df(&sel, 0x7F10u), FS_OK);
    CHECK_EQ(sel.cur_df, 2);
    /* Asking for a child DF but naming an EF must fail loudly, not succeed. */
    CHECK_EQ(fs_select_child_df(&sel, 0x6F01u), FS_ERR_WRONG_TYPE);
    CHECK_EQ(fs_select_child_ef(&sel, 0x6F01u), FS_OK);

    CHECK_EQ(fs_select_parent(&sel), FS_OK);
    CHECK_EQ(sel.cur_df, 0);
    /* The MF has no parent. Silently staying put would hide a caller's bug. */
    CHECK_EQ(fs_select_parent(&sel), FS_ERR_NOT_FOUND);
}

TEST(select_by_path)
{
    fresh();
    fs_selection sel;
    fs_selection_reset(&sel);

    /* From the MF: 7F10 / 6F02 */
    const uint8_t path[] = { 0x7F, 0x10, 0x6F, 0x02 };
    CHECK_EQ(fs_select_by_path(&sel, path, sizeof(path), true), FS_OK);
    CHECK_EQ(sel.cur_df, 2);
    CHECK_EQ(sel.cur_ef, 4);

    /* A path whose interior component is an EF is invalid: an EF has no
     * children. */
    const uint8_t bad[] = { 0x2F, 0x00, 0x6F, 0x02 };
    fs_selection  s2;
    fs_selection_reset(&s2);
    CHECK_EQ(fs_select_by_path(&s2, bad, sizeof(bad), true), FS_ERR_WRONG_TYPE);

    /* Malformed lengths. */
    CHECK_EQ(fs_select_by_path(&s2, path, 3u, true), FS_ERR_PARAM);
    CHECK_EQ(fs_select_by_path(&s2, path, 0u, true), FS_ERR_PARAM);
    CHECK_EQ(fs_select_by_path(&s2, path, 100u, true), FS_ERR_PARAM);
}

/* A path that fails half way must leave the selection completely untouched --
 * otherwise an attacker chooses which intermediate DF the card lands in. */
TEST(failed_path_walk_is_atomic)
{
    fresh();
    fs_selection sel;
    fs_selection_reset(&sel);
    CHECK_EQ(fs_select_by_fid(&sel, 0x2F00u), FS_OK);
    const fs_selection before = sel;

    /* 7F10 exists; DEAD does not. The walk enters 7F10 then fails. */
    const uint8_t path[] = { 0x7F, 0x10, 0xDE, 0xAD };
    CHECK_EQ(fs_select_by_path(&sel, path, sizeof(path), true),
             FS_ERR_NOT_FOUND);
    CHECK_EQ(sel.cur_df, before.cur_df);
    CHECK_EQ(sel.cur_ef, before.cur_ef);
}

TEST(deactivated_file_is_selectable_but_not_readable)
{
    fresh();

    /* Deactivate 2F00 by rewriting its descriptor. */
    fs_descriptor d;
    CHECK_EQ(fs_get(1u, &d), FS_OK);
    d.lifecycle = FS_LC_DEACTIVATED;
    CHECK_EQ(fs_store_write_desc(1u, &d), FS_OK);

    fs_selection sel;
    fs_selection_reset(&sel);

    /*
     * SELECTION SUCCEEDS, and this assertion is the reverse of what it used to
     * be. The old rule refused it, which made deactivation a ONE-WAY DOOR:
     * ACTIVATE FILE addresses the currently selected file, so a file that
     * could not be selected could never be reactivated by any APDU. The test
     * that pinned the old behaviour even carried a comment claiming the state
     * was reversible -- it was reversible only from inside the OS.
     *
     * Selection is navigation and inspection. It grants nothing.
     */
    CHECK_EQ(fs_select_by_fid(&sel, 0x2F00u), FS_OK);
    CHECK_EQ(sel.cur_ef, 1u);

    /* DATA ACCESS is refused, which is the property that was always the point.
     * NOT_USABLE, distinct from NOT_FOUND: the file exists, it is just not
     * available. Merging them would hide the difference from an administrator
     * trying to work out why a card stopped working. */
    uint8_t  buf[8];
    uint16_t got = 0u;
    CHECK_EQ(fs_ef_read(1u, 0u, 4u, buf, &got), FS_ERR_NOT_USABLE);
    CHECK_EQ(got, 0);
    const uint8_t src[4] = { 1u, 2u, 3u, 4u };
    CHECK_EQ(fs_ef_write(1u, 0u, 4u, src), FS_ERR_NOT_USABLE);

    /* Reactivate and it works again -- deactivation is reversible; only
     * TERMINATED is not. */
    d.lifecycle = FS_LC_ACTIVATED;
    CHECK_EQ(fs_store_write_desc(1u, &d), FS_OK);
    CHECK_EQ(fs_select_by_fid(&sel, 0x2F00u), FS_OK);
    CHECK_EQ(fs_ef_read(1u, 0u, 4u, buf, &got), FS_OK);
    CHECK_EQ(got, 4);
}

TEST(terminated_file_is_not_selectable)
{
    fresh();

    /* TERMINATED stays unselectable, and the reason is different from
     * DEACTIVATED's: termination is irreversible by design, so there is no
     * administrative action left that needs to name the file. Keeping it
     * refused is also what preserves the 6A82 / 6985 distinction as
     * meaningful. */
    fs_descriptor d;
    CHECK_EQ(fs_get(1u, &d), FS_OK);
    d.lifecycle = FS_LC_TERMINATED;
    CHECK_EQ(fs_store_write_desc(1u, &d), FS_OK);

    fs_selection sel;
    fs_selection_reset(&sel);
    CHECK_EQ(fs_select_by_fid(&sel, 0x2F00u), FS_ERR_NOT_USABLE);
}

TEST(a_deactivated_df_blocks_the_files_inside_it)
{
    fresh();

    /*
     * The property that makes DEACTIVATE FILE on a directory mean anything.
     *
     * Before ancestors_usable() existed, fs_ef_read() checked only the EF's
     * own lifecycle -- so deactivating a DF refused operations on the DF while
     * every EF inside it stayed perfectly readable. An administrator who
     * deactivated a directory to take an application out of service would
     * have taken nothing out of service, and the card would have reported
     * success for the command that did nothing.
     */
    fs_selection sel;
    fs_selection_reset(&sel);

    /* Build MF/7F01/6F01 and put a byte in the EF. */
    fs_descriptor df = { 0 };
    df.file_id       = 0x7F01u;
    df.type          = FS_TYPE_DF;
    df.lifecycle     = FS_LC_ACTIVATED;
    uint16_t df_idx  = FS_INVALID_INDEX;
    CHECK_EQ(fs_create_file(&sel, &df, &df_idx), FS_OK);

    CHECK_EQ(fs_select_child_df(&sel, 0x7F01u), FS_OK);
    fs_descriptor ef = { 0 };
    ef.file_id       = 0x6F01u;
    ef.type          = FS_TYPE_EF_TRANSPARENT;
    ef.lifecycle     = FS_LC_ACTIVATED;
    ef.size          = 8u;
    ef.sfi           = FS_NO_SFI;
    uint16_t ef_idx  = FS_INVALID_INDEX;
    CHECK_EQ(fs_create_file(&sel, &ef, &ef_idx), FS_OK);

    const uint8_t src[4] = { 0xDEu, 0xADu, 0xBEu, 0xEFu };
    CHECK_EQ(fs_ef_write(ef_idx, 0u, 4u, src), FS_OK);

    uint8_t  buf[8];
    uint16_t got = 0u;
    CHECK_EQ(fs_ef_read(ef_idx, 0u, 4u, buf, &got), FS_OK);
    CHECK_EQ(got, 4);

    /* Now deactivate the PARENT. The EF itself is untouched and still
     * ACTIVATED, so only the ancestor walk can catch this. */
    CHECK_EQ(fs_set_lifecycle(df_idx, FS_LC_DEACTIVATED), FS_OK);

    fs_descriptor check;
    CHECK_EQ(fs_get(ef_idx, &check), FS_OK);
    CHECK_EQ(check.lifecycle, FS_LC_ACTIVATED); /* the EF really is active */

    CHECK_EQ(fs_ef_read(ef_idx, 0u, 4u, buf, &got), FS_ERR_NOT_USABLE);
    CHECK_EQ(fs_ef_write(ef_idx, 0u, 4u, src), FS_ERR_NOT_USABLE);

    /* Reactivating the DF restores access to the whole subtree. */
    CHECK_EQ(fs_set_lifecycle(df_idx, FS_LC_ACTIVATED), FS_OK);
    CHECK_EQ(fs_ef_read(ef_idx, 0u, 4u, buf, &got), FS_OK);
    CHECK_EQ(got, 4);
    CHECK_EQ(buf[0], 0xDE);
}

TEST(set_lifecycle_refuses_what_it_must)
{
    fresh();

    /* Only ACTIVATED and DEACTIVATED are reachable. */
    CHECK_EQ(fs_set_lifecycle(1u, FS_LC_TERMINATED), FS_ERR_PARAM);
    CHECK_EQ(fs_set_lifecycle(1u, FS_LC_CREATION), FS_ERR_PARAM);
    CHECK_EQ(fs_set_lifecycle(1u, FS_LC_INITIALISED), FS_ERR_PARAM);

    /* Idempotent: repeating a state change must succeed, because a reader
     * whose response was lost has no recourse but to send it again. */
    CHECK_EQ(fs_set_lifecycle(1u, FS_LC_ACTIVATED), FS_OK);
    CHECK_EQ(fs_set_lifecycle(1u, FS_LC_DEACTIVATED), FS_OK);
    CHECK_EQ(fs_set_lifecycle(1u, FS_LC_DEACTIVATED), FS_OK);
    CHECK_EQ(fs_set_lifecycle(1u, FS_LC_ACTIVATED), FS_OK);

    /* Out of TERMINATED: never. */
    fs_descriptor d;
    CHECK_EQ(fs_get(1u, &d), FS_OK);
    d.lifecycle = FS_LC_TERMINATED;
    CHECK_EQ(fs_store_write_desc(1u, &d), FS_OK);
    CHECK_EQ(fs_set_lifecycle(1u, FS_LC_ACTIVATED), FS_ERR_NOT_USABLE);
    CHECK_EQ(fs_set_lifecycle(1u, FS_LC_DEACTIVATED), FS_ERR_NOT_USABLE);

    /* The MF can never be deactivated: it is the only entry point to the tree,
     * so turning it off is bricking the card, not administering it. */
    const uint16_t root = fs_root_index();
    CHECK_EQ(fs_set_lifecycle(root, FS_LC_DEACTIVATED), FS_ERR_NOT_USABLE);
    CHECK_EQ(fs_set_lifecycle(root, FS_LC_ACTIVATED), FS_OK); /* already so */
}

/* ============================================================== EF data === */

TEST(ef_read_write_within_bounds)
{
    fresh();
    const uint8_t pattern[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t       back[8];
    uint16_t      got = 0u;

    /* Fresh EFs read as erased. */
    CHECK_EQ(fs_ef_read(1u, 0u, 4u, back, &got), FS_OK);
    CHECK_EQ(got, 4);
    for (unsigned i = 0; i < 4u; i++) {
        CHECK_HEX(back[i], 0xFF);
    }

    CHECK_EQ(fs_ef_write(1u, 4u, 4u, pattern), FS_OK);
    CHECK_EQ(fs_ef_read(1u, 4u, 4u, back, &got), FS_OK);
    CHECK_EQ(got, 4);
    CHECK(os_memeq_ct(back, pattern, 4u));

    /* Neighbouring bytes untouched. */
    CHECK_EQ(fs_ef_read(1u, 0u, 8u, back, &got), FS_OK);
    CHECK_HEX(back[3], 0xFF);
}

/*
 * The bounds tests that matter most: a file must not be readable or writable
 * past its own end, even though the bytes beyond it exist in FLASH and belong
 * to a different file.
 */
TEST(ef_access_cannot_escape_the_file)
{
    fresh();
    uint8_t  buf[300];
    uint16_t got = 0u;
    os_memset(buf, 0xAA, sizeof(buf));

    /* 2F00 is 32 bytes. */
    /* Reading past the end SHORT-READS rather than failing (ISO requires it). */
    CHECK_EQ(fs_ef_read(1u, 30u, 100u, buf, &got), FS_OK);
    CHECK_EQ(got, 2);
    /* Exactly at the end reads zero bytes and is legal. */
    CHECK_EQ(fs_ef_read(1u, 32u, 10u, buf, &got), FS_OK);
    CHECK_EQ(got, 0);
    /* Past the end is a range error. */
    CHECK_EQ(fs_ef_read(1u, 33u, 1u, buf, &got), FS_ERR_RANGE);
    CHECK_EQ(fs_ef_read(1u, 0xFFFFu, 1u, buf, &got), FS_ERR_RANGE);

    /* Writes must be refused ENTIRELY, not truncated: without transactions a
     * partial write cannot be undone. */
    CHECK_EQ(fs_ef_write(1u, 30u, 4u, buf), FS_ERR_RANGE);
    CHECK_EQ(fs_ef_write(1u, 0u, 33u, buf), FS_ERR_RANGE);
    CHECK_EQ(fs_ef_write(1u, 0xFFFFu, 4u, buf), FS_ERR_RANGE);
    /* And nothing was written. */
    CHECK_EQ(fs_ef_read(1u, 30u, 2u, buf, &got), FS_OK);
    CHECK_HEX(buf[0], 0xFF);

    /* Exactly filling the file is legal. */
    CHECK_EQ(fs_ef_write(1u, 0u, 32u, buf), FS_OK);

    /* A DF is not readable as data. */
    CHECK_EQ(fs_ef_read(2u, 0u, 4u, buf, &got), FS_ERR_WRONG_TYPE);
    CHECK_EQ(fs_ef_write(2u, 0u, 4u, buf), FS_ERR_WRONG_TYPE);
}

/* Files must be isolated from each other in FLASH. Fill one completely and
 * check its neighbours are untouched -- catches an allocation overlap. */
TEST(files_do_not_overlap_in_flash)
{
    fresh();
    uint8_t  fill[64];
    uint8_t  back[64];
    uint16_t got = 0u;

    os_memset(fill, 0x11, sizeof(fill));
    CHECK_EQ(fs_ef_write(1u, 0u, 32u, fill), FS_OK); /* 2F00, 32 B */
    os_memset(fill, 0x22, sizeof(fill));
    CHECK_EQ(fs_ef_write(3u, 0u, 64u, fill), FS_OK); /* 6F01, 64 B */
    os_memset(fill, 0x33, sizeof(fill));
    CHECK_EQ(fs_ef_write(4u, 0u, 16u, fill), FS_OK); /* 6F02, 16 B */

    CHECK_EQ(fs_ef_read(1u, 0u, 32u, back, &got), FS_OK);
    for (unsigned i = 0; i < 32u; i++) {
        CHECK_HEX(back[i], 0x11);
    }
    CHECK_EQ(fs_ef_read(3u, 0u, 64u, back, &got), FS_OK);
    for (unsigned i = 0; i < 64u; i++) {
        CHECK_HEX(back[i], 0x22);
    }
    CHECK_EQ(fs_ef_read(4u, 0u, 16u, back, &got), FS_OK);
    for (unsigned i = 0; i < 16u; i++) {
        CHECK_HEX(back[i], 0x33);
    }
}

/* ========================================================= command layer == */

TEST(select_returns_fci_when_le_present)
{
    fresh();
    uint8_t  data[64];
    uint16_t len = 0u;

    /* Case 4: SELECT MF with Le. P2=00 asks for the FCI, and because Le is
     * present the card can return it directly -- no 61XX needed. */
    const uint8_t cmd[] = { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00, 0x20 };
    CHECK_HEX(send(cmd, sizeof(cmd), data, &len), SW_OK);
    CHECK(len > 0);
    /* FCI template tag. */
    CHECK_HEX(data[0], 0x6F);
    CHECK_EQ(data[1], len - 2u);
    /* 82 01 38 : file descriptor byte, DF. */
    CHECK_HEX(data[2], 0x82);
    CHECK_HEX(data[4], 0x38);
    /* 83 02 3F 00 : file identifier. */
    CHECK_HEX(data[5], 0x83);
    CHECK_HEX(data[7], 0x3F);
    CHECK_HEX(data[8], 0x00);
}

TEST(select_ef_fci_reports_size_and_sfi)
{
    fresh();
    uint8_t  data[64];
    uint16_t len = 0u;

    /* SELECT 2F00 (32 bytes, SFI 1), FCP template (P2=04). */
    const uint8_t cmd[] = { 0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00, 0x20 };
    CHECK_HEX(send(cmd, sizeof(cmd), data, &len), SW_OK);
    CHECK_HEX(data[0], 0x62); /* FCP template */
    CHECK_HEX(data[2], 0x82);
    CHECK_HEX(data[4], 0x01); /* transparent working EF */

    /* Scan for tag 80 (size) and tag 88 (SFI). */
    bool saw_size = false, saw_sfi = false;
    for (uint16_t i = 2u; i + 2u < len; i++) {
        if (data[i] == 0x80u && data[i + 1u] == 0x02u) {
            CHECK_EQ(((uint16_t)data[i + 2u] << 8) | data[i + 3u], 32);
            saw_size = true;
        }
        if (data[i] == 0x88u && data[i + 1u] == 0x01u) {
            CHECK_HEX(data[i + 2u], 1u << 3); /* SFI 1, ISO bit placement */
            saw_sfi = true;
        }
    }
    CHECK(saw_size);
    CHECK(saw_sfi);
}

TEST(select_le_too_small_is_6cxx)
{
    fresh();
    /* Ask for 4 bytes of an FCI that is longer. ISO says answer 6CXX with the
     * exact length, which is far more useful than truncating. */
    const uint8_t  cmd[] = { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00, 0x04 };
    uint16_t       len   = 0xFFFFu;
    const uint16_t sw    = send(cmd, sizeof(cmd), NULL, &len);
    CHECK_HEX(sw & 0xFF00u, 0x6C00);
    CHECK((sw & 0x00FFu) > 4u);
    CHECK_EQ(len, 0); /* and no data was returned */
}

TEST(read_binary_needs_a_current_ef)
{
    fresh();
    /* After a reset the MF is current and there is no EF. 6986 says exactly
     * "no current EF", telling the reader to SELECT first. */
    const uint8_t read[] = { 0x00, 0xB0, 0x00, 0x00, 0x04 };
    CHECK_HEX(send(read, sizeof(read), NULL, NULL),
              SW_COMMAND_NOT_ALLOWED_NO_EF);
}

TEST(read_and_update_binary_roundtrip)
{
    fresh();
    uint8_t  data[300];
    uint16_t len = 0u;

    /* SELECT 2F00 */
    const uint8_t sel[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0x2F, 0x00 };
    CHECK_HEX(send(sel, sizeof(sel), NULL, NULL), SW_OK);

    /* UPDATE BINARY at offset 0 with 4 bytes (Case 3). */
    const uint8_t upd[] = {
        0x00, 0xD6, 0x00, 0x00, 0x04, 0xCA, 0xFE, 0xBA, 0xBE
    };
    CHECK_HEX(send(upd, sizeof(upd), NULL, &len), SW_OK);
    CHECK_EQ(len, 0); /* UPDATE returns no data */

    /* READ BINARY (Case 2). */
    const uint8_t rd[] = { 0x00, 0xB0, 0x00, 0x00, 0x04 };
    CHECK_HEX(send(rd, sizeof(rd), data, &len), SW_OK);
    CHECK_EQ(len, 4);
    CHECK_HEX(data[0], 0xCA);
    CHECK_HEX(data[3], 0xBE);

    /* Offset form: read the two bytes at offset 2. */
    const uint8_t rd2[] = { 0x00, 0xB0, 0x00, 0x02, 0x02 };
    CHECK_HEX(send(rd2, sizeof(rd2), data, &len), SW_OK);
    CHECK_EQ(len, 2);
    CHECK_HEX(data[0], 0xBA);
}

TEST(read_binary_short_read_is_6282)
{
    fresh();
    uint8_t  data[300];
    uint16_t len = 0u;

    const uint8_t sel[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0x2F, 0x00 };
    CHECK_HEX(send(sel, sizeof(sel), NULL, NULL), SW_OK);

    /* 2F00 is 32 bytes; ask for 256 from offset 0. ISO: return what exists,
     * with 6282 "end of file reached before reading Le bytes". A warning, not
     * an error -- the data is valid and the caller should use it. */
    const uint8_t rd[] = { 0x00, 0xB0, 0x00, 0x00, 0x00 };
    CHECK_HEX(send(rd, sizeof(rd), data, &len), SW_NVM_UNCHANGED_EOF);
    CHECK_EQ(len, 32);

    /* Reading exactly the file length is a clean 9000. */
    const uint8_t exact[] = { 0x00, 0xB0, 0x00, 0x00, 0x20 };
    CHECK_HEX(send(exact, sizeof(exact), data, &len), SW_OK);
    CHECK_EQ(len, 32);
}

TEST(binary_sfi_form_selects_implicitly)
{
    fresh();
    uint8_t  data[300];
    uint16_t len = 0u;

    /* No SELECT first. P1 = 0x81 = SFI form, SFI 1 -> 2F00 under the MF. */
    const uint8_t upd[] = { 0x00, 0xD6, 0x81, 0x00, 0x03, 0x11, 0x22, 0x33 };
    CHECK_HEX(send(upd, sizeof(upd), NULL, NULL), SW_OK);

    const uint8_t rd[] = { 0x00, 0xB0, 0x81, 0x00, 0x03 };
    CHECK_HEX(send(rd, sizeof(rd), data, &len), SW_OK);
    CHECK_EQ(len, 3);
    CHECK_HEX(data[0], 0x11);
    CHECK_HEX(data[2], 0x33);

    /* An SFI that does not exist under the current DF. */
    const uint8_t bad[] = { 0x00, 0xB0, 0x85, 0x00, 0x04 };
    CHECK_HEX(send(bad, sizeof(bad), NULL, NULL), SW_FILE_NOT_FOUND);

    /* Reserved bits b7 b6 of P1 must be zero in the SFI form. */
    const uint8_t rfu[] = { 0x00, 0xB0, 0xE1, 0x00, 0x04 };
    CHECK_HEX(send(rfu, sizeof(rfu), NULL, NULL), SW_INCORRECT_P1P2);
    /* SFI 0 is not a file reference. */
    const uint8_t sfi0[] = { 0x00, 0xB0, 0x80, 0x00, 0x04 };
    CHECK_HEX(send(sfi0, sizeof(sfi0), NULL, NULL), SW_INCORRECT_P1P2);
}

TEST(binary_out_of_range_is_6b00)
{
    fresh();
    const uint8_t sel[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0x2F, 0x00 };
    CHECK_HEX(send(sel, sizeof(sel), NULL, NULL), SW_OK);

    /* Offset 100 in a 32-byte file. */
    const uint8_t rd[] = { 0x00, 0xB0, 0x00, 0x64, 0x04 };
    CHECK_HEX(send(rd, sizeof(rd), NULL, NULL), SW_WRONG_P1P2);

    /* A write that would run past the end must be refused whole. */
    const uint8_t upd[] = { 0x00, 0xD6, 0x00, 0x1E, 0x04, 1, 2, 3, 4 };
    CHECK_HEX(send(upd, sizeof(upd), NULL, NULL), SW_WRONG_P1P2);
}

TEST(binary_malformed_apdus)
{
    fresh();
    const uint8_t sel[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0x2F, 0x00 };
    CHECK_HEX(send(sel, sizeof(sel), NULL, NULL), SW_OK);

    /* READ BINARY with no Le: the card cannot know how much to send. */
    const uint8_t no_le[] = { 0x00, 0xB0, 0x00, 0x00 };
    CHECK_HEX(send(no_le, sizeof(no_le), NULL, NULL), SW_WRONG_LENGTH);
    /* READ BINARY with command data is Case 3/4 and wrong for this command. */
    const uint8_t with_data[] = { 0x00, 0xB0, 0x00, 0x00, 0x02, 0xAA, 0xBB };
    CHECK_HEX(send(with_data, sizeof(with_data), NULL, NULL),
              SW_LC_INCONSISTENT_P1P2);

    /* UPDATE BINARY with no data. */
    const uint8_t no_data[] = { 0x00, 0xD6, 0x00, 0x00 };
    CHECK_HEX(send(no_data, sizeof(no_data), NULL, NULL), SW_WRONG_LENGTH);
    /* UPDATE BINARY with Le: it returns nothing, so an Le is a caller error. */
    const uint8_t with_le[] = { 0x00, 0xD6, 0x00, 0x00, 0x01, 0xAA, 0x04 };
    CHECK_HEX(send(with_le, sizeof(with_le), NULL, NULL), SW_WRONG_LENGTH);
}

/* Data written must survive a warm reset (it is in NVM), while the SELECTION
 * must not (it is in RAM). The distinction is the whole point of the split. */
TEST(data_survives_reset_but_selection_does_not)
{
    fresh();
    const uint8_t sel[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0x2F, 0x00 };
    CHECK_HEX(send(sel, sizeof(sel), NULL, NULL), SW_OK);
    const uint8_t upd[] = { 0x00, 0xD6, 0x00, 0x00, 0x02, 0x5A, 0xA5 };
    CHECK_HEX(send(upd, sizeof(upd), NULL, NULL), SW_OK);

    scos_reset(&g_card);

    /* Selection gone: READ BINARY has no current EF. */
    const uint8_t rd[] = { 0x00, 0xB0, 0x00, 0x00, 0x02 };
    CHECK_HEX(send(rd, sizeof(rd), NULL, NULL), SW_COMMAND_NOT_ALLOWED_NO_EF);

    /* Data still there. */
    uint8_t  data[8];
    uint16_t len = 0u;
    CHECK_HEX(send(sel, sizeof(sel), NULL, NULL), SW_OK);
    CHECK_HEX(send(rd, sizeof(rd), data, &len), SW_OK);
    CHECK_EQ(len, 2);
    CHECK_HEX(data[0], 0x5A);
    CHECK_HEX(data[1], 0xA5);
}

/* Sweep every P1/P2 on both binary commands. The card must always answer, and
 * must never read or write outside a file -- verified by ASan. */
TEST(binary_never_escapes_under_a_p1p2_sweep)
{
    fresh();
    const uint8_t sel[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0x2F, 0x00 };
    CHECK_HEX(send(sel, sizeof(sel), NULL, NULL), SW_OK);

    unsigned answered = 0u;
    for (unsigned p1 = 0; p1 <= 0xFFu; p1 += 3u) {
        for (unsigned p2 = 0; p2 <= 0xFFu; p2 += 5u) {
            const uint8_t rd[] = { 0x00, 0xB0, (uint8_t)p1, (uint8_t)p2, 0x10 };
            uint16_t      sw   = send(rd, sizeof(rd), NULL, NULL);
            CHECK((sw >> 8) >= 0x60u);
            const uint8_t upd[] = { 0x00, 0xD6, (uint8_t)p1, (uint8_t)p2, 0x04,
                                    0xDE, 0xAD, 0xBE,        0xEF };
            sw                  = send(upd, sizeof(upd), NULL, NULL);
            CHECK((sw >> 8) >= 0x60u);
            answered += 2u;
        }
    }
    CHECK(answered > 4000u);

    /* The factory sizes must be intact: nothing overflowed into a descriptor. */
    fs_descriptor d;
    CHECK_EQ(fs_get(1u, &d), FS_OK);
    CHECK_EQ(d.size, 32);
    CHECK_EQ(fs_get(3u, &d), FS_OK);
    CHECK_EQ(d.size, 64);
}

int main(void)
{
    vcard_config cfg;
    vcard_config_default(&cfg);
    cfg.state_dir = NULL;
    cfg.quiet     = true;
    vcard_configure(&cfg);
    if (hal_init() != HAL_OK) {
        (void)printf("FATAL: hal_init failed\n");
        return EXIT_FAILURE;
    }

    RUN(crc16_known_answer);
    RUN(format_produces_an_empty_table);
    RUN(descriptor_roundtrip_survives_serialisation);
    RUN(corrupt_descriptor_is_detected_not_used);
    RUN(corrupt_superblock_refuses_to_mount);
    RUN(unknown_layout_version_refuses_to_mount);
    RUN(allocation_finds_a_free_extent_and_reserves_nothing);
    RUN(a_deleted_extent_is_reused_rather_than_leaked);
    RUN(exhaustion_is_reported_not_wrapped);

    RUN(factory_layout_is_as_documented);
    RUN(ef_atr_says_what_the_card_can_do);
    RUN(sfi_is_scoped_to_its_parent_df);
    RUN(selecting_a_df_clears_the_current_ef);
    RUN(selection_search_order_is_scoped);
    RUN(select_parent_and_typed_children);
    RUN(select_by_path);
    RUN(failed_path_walk_is_atomic);
    RUN(deactivated_file_is_selectable_but_not_readable);
    RUN(terminated_file_is_not_selectable);
    RUN(a_deactivated_df_blocks_the_files_inside_it);
    RUN(set_lifecycle_refuses_what_it_must);

    RUN(ef_read_write_within_bounds);
    RUN(ef_access_cannot_escape_the_file);
    RUN(files_do_not_overlap_in_flash);

    RUN(select_returns_fci_when_le_present);
    RUN(select_ef_fci_reports_size_and_sfi);
    RUN(select_le_too_small_is_6cxx);
    RUN(read_binary_needs_a_current_ef);
    RUN(read_and_update_binary_roundtrip);
    RUN(read_binary_short_read_is_6282);
    RUN(binary_sfi_form_selects_implicitly);
    RUN(binary_out_of_range_is_6b00);
    RUN(binary_malformed_apdus);
    RUN(data_survives_reset_but_selection_does_not);
    RUN(binary_never_escapes_under_a_p1p2_sweep);

    hal_shutdown();
    TEST_MAIN_END();
}
