/* SPDX-License-Identifier: MIT
 *
 * test_create.c -- CREATE FILE (E0) and DELETE FILE (E4).
 *
 * These are the first commands that consume a caller-supplied BER-TLV
 * template, so the malformed-template cases outnumber the well-formed ones on
 * purpose. They are also the first commands that MODIFY THE FILE TREE, which
 * means a bug here does not produce a wrong answer -- it produces a card whose
 * structure is quietly wrong and stays wrong across every later power-on. So
 * most tests below check the tree afterwards, not just the status word.
 */
#include "apdu/sw.h"
#include "filesystem/fs.h"
#include "filesystem/fs_store.h"
#include "hal/hal.h"
#include "hal/sim/vcard.h"
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

static uint16_t send(const uint8_t *cmd, uint16_t len,
                     uint8_t *out_data, uint16_t *out_data_len)
{
    uint8_t  rsp[SCOS_APDU_RSP_MAX];
    uint16_t rsp_len = 0u;

    CHECK_EQ(scos_process(&g_card, cmd, len, rsp, (uint16_t)sizeof(rsp),
                          &rsp_len), SCOS_OK);
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

/* --- template builders ---------------------------------------------------- */
/*
 * Hand-written hex for these templates was a mistake twice during development
 * -- once writing 0x83 as a length byte, which BER reads as "three length
 * bytes follow". Building them here means the tests exercise the parser, not
 * my arithmetic.
 */

#define FDB_EF_TRANSPARENT 0x01u
#define FDB_DF             0x38u

static uint16_t put_tlv(uint8_t *out, uint16_t n, uint8_t tag,
                        const uint8_t *v, uint8_t vlen)
{
    out[n++] = tag;
    out[n++] = vlen;
    for (uint8_t i = 0; i < vlen; i++) {
        out[n++] = v[i];
    }
    return n;
}

/* Wrap `body` in a 62 template and prepend the CREATE FILE header. */
static uint16_t make_create(uint8_t *out, const uint8_t *body, uint8_t body_len)
{
    uint16_t n = 0u;
    out[n++] = 0x00u;
    out[n++] = 0xE0u;
    out[n++] = 0x00u;
    out[n++] = 0x00u;
    out[n++] = (uint8_t)(body_len + 2u);
    out[n++] = 0x62u;
    out[n++] = body_len;
    for (uint8_t i = 0; i < body_len; i++) {
        out[n++] = body[i];
    }
    return n;
}

static uint16_t build_ef_body(uint8_t *body, uint16_t fid, uint16_t size,
                             uint8_t sfi)
{
    const uint8_t fdb[1]  = { FDB_EF_TRANSPARENT };
    const uint8_t id[2]   = { (uint8_t)(fid >> 8), (uint8_t)fid };
    const uint8_t sz[2]   = { (uint8_t)(size >> 8), (uint8_t)size };
    uint16_t      n       = 0u;
    n = put_tlv(body, n, 0x82u, fdb, 1u);
    n = put_tlv(body, n, 0x83u, id,  2u);
    n = put_tlv(body, n, 0x80u, sz,  2u);
    if (sfi != 0u) {
        const uint8_t s[1] = { (uint8_t)(sfi << 3) };
        n = put_tlv(body, n, 0x88u, s, 1u);
    }
    return n;
}

static uint16_t build_df_body(uint8_t *body, uint16_t fid)
{
    const uint8_t fdb[1] = { FDB_DF };
    const uint8_t id[2]  = { (uint8_t)(fid >> 8), (uint8_t)fid };
    uint16_t      n      = 0u;
    n = put_tlv(body, n, 0x82u, fdb, 1u);
    n = put_tlv(body, n, 0x83u, id,  2u);
    return n;
}

static uint16_t create_ef(uint16_t fid, uint16_t size, uint8_t sfi)
{
    uint8_t  body[32];
    uint8_t  apdu[64];
    const uint16_t bl = build_ef_body(body, fid, size, sfi);
    const uint16_t al = make_create(apdu, body, (uint8_t)bl);
    return send(apdu, al, NULL, NULL);
}

static uint16_t create_df(uint16_t fid)
{
    uint8_t  body[32];
    uint8_t  apdu[64];
    const uint16_t bl = build_df_body(body, fid);
    const uint16_t al = make_create(apdu, body, (uint8_t)bl);
    return send(apdu, al, NULL, NULL);
}

/*
 * Send a CREATE FILE whose data field is exactly `body`, with Lc computed.
 *
 * Hand-written Lc bytes were wrong three separate times while writing this
 * file. The tests are supposed to be attacking the FCP parser, not my
 * arithmetic, so the only length the test author controls is the one INSIDE
 * the template -- the APDU's own length is derived and cannot disagree.
 */
static uint16_t send_create_raw(const uint8_t *body, uint8_t body_len)
{
    uint8_t apdu[5u + 255u];
    apdu[0] = 0x00u;
    apdu[1] = 0xE0u;
    apdu[2] = 0x00u;
    apdu[3] = 0x00u;
    apdu[4] = body_len;
    for (uint8_t i = 0; i < body_len; i++) {
        apdu[5u + i] = body[i];
    }
    return send(apdu, (uint16_t)(5u + body_len), NULL, NULL);
}

/* Wrap `inner` in a 62 template, with the template length derived too. */
static uint16_t send_create_fcp(const uint8_t *inner, uint8_t inner_len)
{
    uint8_t body[2u + 255u];
    body[0] = 0x62u;
    body[1] = inner_len;
    for (uint8_t i = 0; i < inner_len; i++) {
        body[2u + i] = inner[i];
    }
    return send_create_raw(body, (uint8_t)(inner_len + 2u));
}

static uint16_t delete_file(uint16_t fid)
{
    const uint8_t apdu[] = { 0x00u, 0xE4u, 0x00u, 0x00u, 0x02u,
                             (uint8_t)(fid >> 8), (uint8_t)fid };
    return send(apdu, (uint16_t)sizeof(apdu), NULL, NULL);
}

static uint16_t select_fid(uint8_t p1, uint16_t fid)
{
    const uint8_t apdu[] = { 0x00u, 0xA4u, p1, 0x0Cu, 0x02u,
                             (uint8_t)(fid >> 8), (uint8_t)fid };
    return send(apdu, (uint16_t)sizeof(apdu), NULL, NULL);
}

/* ============================================================ happy path == */

TEST(create_an_ef_then_use_it)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    /* SFI 3: 1 and 2 are already used by the factory layout, and the point of
     * this test is not the collision check. */
    CHECK_HEX(create_ef(0x2801u, 40u, 3u), SW_OK);

    /* It is reachable, and it is an EF of the size we asked for. */
    CHECK_HEX(select_fid(0x02u, 0x2801u), SW_OK);

    uint8_t  data[64];
    uint16_t dlen = 0u;
    const uint8_t write[] = { 0x00u, 0xD6u, 0x00u, 0x00u, 0x04u,
                              0xDEu, 0xADu, 0xBEu, 0xEFu };
    CHECK_HEX(send(write, (uint16_t)sizeof(write), NULL, NULL), SW_OK);

    const uint8_t read[] = { 0x00u, 0xB0u, 0x00u, 0x00u, 0x04u };
    CHECK_HEX(send(read, (uint16_t)sizeof(read), data, &dlen), SW_OK);
    CHECK_EQ(dlen, 4);
    CHECK_HEX(data[0], 0xDE);
    CHECK_HEX(data[3], 0xEF);

    /* And by its short identifier, which is the part that proves tag 88 was
     * decoded rather than merely accepted. */
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    const uint8_t read_sfi[] = { 0x00u, 0xB0u, 0x83u, 0x00u, 0x04u };
    CHECK_HEX(send(read_sfi, (uint16_t)sizeof(read_sfi), data, &dlen), SW_OK);
    CHECK_HEX(data[0], 0xDE);
}

TEST(create_a_df_and_a_file_inside_it)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(create_df(0x7F20u), SW_OK);
    CHECK_HEX(select_fid(0x01u, 0x7F20u), SW_OK);

    /* SFI 1 is free INSIDE this DF even though the MF already uses it: short
     * identifiers are scoped to their DF, not to the card. */
    CHECK_HEX(create_ef(0x6F31u, 8u, 1u), SW_OK);
    CHECK_HEX(select_fid(0x02u, 0x6F31u), SW_OK);

    /* The new EF is NOT reachable from the MF by identifier. That is the
     * cross-DF isolation fs_select_by_fid documents, and creating files must
     * not open a hole in it. */
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(select_fid(0x02u, 0x6F31u), SW_FILE_NOT_FOUND);
}

TEST(create_does_not_move_the_selection)
{
    /* Deliberate divergence from ISO/IEC 7816-9, which permits selecting the
     * new file. A command that quietly moves the current EF turns the client's
     * next UPDATE BINARY into a write to a different file. */
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(select_fid(0x02u, 0x2F00u), SW_OK); /* factory EF is current */
    CHECK_HEX(create_ef(0x2802u, 16u, 4u), SW_OK);

    /* Still writing to 2F00, not to the new file. */
    const uint8_t write[] = { 0x00u, 0xD6u, 0x00u, 0x00u, 0x02u, 0xA1u, 0xA2u };
    CHECK_HEX(send(write, (uint16_t)sizeof(write), NULL, NULL), SW_OK);

    uint8_t  data[8];
    uint16_t dlen = 0u;
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(select_fid(0x02u, 0x2802u), SW_OK);
    const uint8_t read[] = { 0x00u, 0xB0u, 0x00u, 0x00u, 0x02u };
    CHECK_HEX(send(read, (uint16_t)sizeof(read), data, &dlen), SW_OK);
    CHECK_HEX(data[0], 0xFF); /* erased, i.e. the write went elsewhere */
}

TEST(a_created_file_survives_a_reset)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(create_ef(0x2803u, 24u, 0u), SW_OK);

    scos_reset(&g_card);

    /* A reset returns to the MF, so no explicit SELECT of 3F00 is needed --
     * and if it were, this test would be checking the wrong thing. */
    CHECK_HEX(select_fid(0x02u, 0x2803u), SW_OK);
}

/*
 * NOTE: there is deliberately no power-cycle test here.
 *
 * The unit-test HAL runs with state_dir == NULL, and vcard_power_on() erases
 * NVM to 0xFF in that mode -- correctly, because an in-RAM card with nowhere
 * to flush to IS a blank chip after power is removed. A "persistence" test on
 * this HAL would therefore be testing the harness, not the OS. Real
 * persistence across power cycles is covered in tests/python/test_create.py,
 * which drives a card with a state directory behind it.
 */

/* ====================================================== structural rules == */

TEST(duplicate_identifier_is_refused)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(create_ef(0x2805u, 16u, 0u), SW_OK);
    CHECK_HEX(create_ef(0x2805u, 16u, 0u), SW_FILE_ALREADY_EXISTS);
    /* Also against a file that came from the factory layout. */
    CHECK_HEX(create_ef(0x2F00u, 16u, 0u), SW_FILE_ALREADY_EXISTS);
}

TEST(duplicate_sfi_is_refused)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    /* Factory EF 2F00 already holds SFI 1 under the MF. A second file with the
     * same SFI would make READ BINARY's short form ambiguous. */
    CHECK_HEX(create_ef(0x2806u, 16u, 1u), SW_FILE_ALREADY_EXISTS);
    /* Without the SFI the same file is fine. */
    CHECK_HEX(create_ef(0x2806u, 16u, 0u), SW_OK);
}

TEST(reserved_identifiers_are_refused)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(create_ef(0x3F00u, 16u, 0u), SW_FILE_ALREADY_EXISTS);
    CHECK_HEX(create_df(0x3F00u), SW_FILE_ALREADY_EXISTS);
    /* FFFF is reserved by ISO to mean "no file". */
    CHECK_HEX(create_ef(0xFFFFu, 16u, 0u), SW_FILE_ALREADY_EXISTS);
}

TEST(the_descriptor_table_has_a_hard_limit)
{
    /* FS_MAX_FILES is 32 and the factory layout uses 5. Filling the rest must
     * produce a clean 6A84, not a wrapped index or a silent overwrite. */
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);

    unsigned created = 0u;
    for (uint16_t i = 0; i < FS_MAX_FILES + 4u; i++) {
        const uint16_t sw = create_ef((uint16_t)(0x3100u + i), 4u, 0u);
        if (sw == SW_OK) {
            created++;
            continue;
        }
        CHECK_HEX(sw, SW_NOT_ENOUGH_SPACE);
        break;
    }
    CHECK_EQ(created, FS_MAX_FILES - 5u);

    /* The card still works afterwards -- running out of slots must not be a
     * one-way trip into a broken state. */
    CHECK_HEX(select_fid(0x02u, 0x2F00u), SW_OK);
}

TEST(running_out_of_data_space_is_clean)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);

    /*
     * One maximum-size EF is only 32 KB and DFLASH is 256 KB, so a single
     * request cannot exhaust it -- an earlier version of this test assumed it
     * could and passed for the wrong reason. Allocate the largest EF ISO's
     * 15-bit offset field allows, repeatedly, until the card says no.
     */
    unsigned created = 0u;
    uint16_t sw      = SW_OK;
    for (uint16_t i = 0; i < 16u; i++) {
        sw = create_ef((uint16_t)(0x3200u + i), FS_MAX_EF_SIZE, 0u);
        if (sw != SW_OK) {
            break;
        }
        created++;
    }
    CHECK(created > 0u);
    CHECK_HEX(sw, SW_NOT_ENOUGH_SPACE);

    /* The refused request must not have consumed a descriptor slot: a card
     * that leaks a slot per failed allocation runs out of files long before it
     * runs out of bytes. */
    const uint16_t after = fs_child_count(fs_root_index());
    CHECK_HEX(create_ef(0x32F0u, FS_MAX_EF_SIZE, 0u), SW_NOT_ENOUGH_SPACE);
    CHECK_EQ(fs_child_count(fs_root_index()), after);

    /* And the card still works. */
    CHECK_HEX(select_fid(0x02u, 0x2F00u), SW_OK);
}

/* ============================================================ DELETE ===== */

TEST(delete_removes_the_file)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(create_ef(0x2808u, 16u, 0u), SW_OK);
    CHECK_HEX(select_fid(0x02u, 0x2808u), SW_OK);

    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(delete_file(0x2808u), SW_OK);
    CHECK_HEX(select_fid(0x02u, 0x2808u), SW_FILE_NOT_FOUND);
    /* And the identifier can be reused. */
    CHECK_HEX(create_ef(0x2808u, 8u, 0u), SW_OK);
}

TEST(delete_frees_the_descriptor_slot_but_not_the_data)
{
    /* KNOWN LIMITATION, asserted so it cannot regress silently: fs_store's
     * data area is a bump allocator, so a deleted EF's bytes are leaked.
     * Compaction needs atomic data movement, which needs the M4 journal. */
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);

    const uint32_t free_before = fs_store_data_free();
    CHECK_HEX(create_ef(0x2809u, 64u, 0u), SW_OK);
    const uint32_t free_after_create = fs_store_data_free();
    CHECK(free_after_create < free_before);

    CHECK_HEX(delete_file(0x2809u), SW_OK);
    CHECK_EQ(fs_store_data_free(), free_after_create); /* NOT reclaimed */

    /* The slot, however, is reusable. */
    CHECK_HEX(create_ef(0x280Au, 4u, 0u), SW_OK);
}

TEST(delete_refuses_a_non_empty_df)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    /* The factory DF 7F10 has two EFs in it. */
    CHECK_HEX(delete_file(0x7F10u), SW_CONDITIONS_NOT_SATISFIED);

    /* Empty it, and then it goes. */
    CHECK_HEX(select_fid(0x01u, 0x7F10u), SW_OK);
    CHECK_HEX(delete_file(0x6F01u), SW_OK);
    CHECK_HEX(delete_file(0x6F02u), SW_OK);
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(delete_file(0x7F10u), SW_OK);
    CHECK_HEX(select_fid(0x01u, 0x7F10u), SW_FILE_NOT_FOUND);
}

TEST(delete_refuses_the_mf)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(delete_file(0x3F00u), SW_CONDITIONS_NOT_SATISFIED);
    /* The card is still mountable, which is the thing that matters. */
    CHECK_HEX(select_fid(0x02u, 0x2F00u), SW_OK);
}

TEST(delete_only_reaches_children_of_the_current_df)
{
    fresh();
    /* 6F01 lives inside DF 7F10, not under the MF. Deleting it from the MF
     * must fail -- the same isolation rule SELECT follows. */
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(delete_file(0x6F01u), SW_FILE_NOT_FOUND);
    /* From inside its own DF it works. */
    CHECK_HEX(select_fid(0x01u, 0x7F10u), SW_OK);
    CHECK_HEX(delete_file(0x6F01u), SW_OK);
}

TEST(deleting_the_current_ef_clears_the_selection)
{
    /* Otherwise the selection points at a freed slot and the next command acts
     * on whatever gets written there. */
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(create_ef(0x280Bu, 16u, 0u), SW_OK);
    CHECK_HEX(select_fid(0x02u, 0x280Bu), SW_OK);
    CHECK_HEX(delete_file(0x280Bu), SW_OK);

    /* No current EF: 6986, not a read of a dead slot. */
    const uint8_t read[] = { 0x00u, 0xB0u, 0x00u, 0x00u, 0x04u };
    CHECK_HEX(send(read, (uint16_t)sizeof(read), NULL, NULL),
              SW_COMMAND_NOT_ALLOWED_NO_EF);
}

TEST(delete_of_a_missing_file_is_reported)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    CHECK_HEX(delete_file(0x9999u), SW_FILE_NOT_FOUND);
}

/* ====================================================== hostile templates = */

TEST(malformed_templates_are_refused)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);

    /* --- errors in the APDU framing itself: sent byte for byte ----------- */
    struct { const uint8_t *a; uint16_t n; uint16_t sw; const char *why; } raw[] = {
        /* no data field at all */
        { (const uint8_t[]){ 0x00, 0xE0, 0x00, 0x00, 0x00 }, 5,
          SW_WRONG_LENGTH, "Case 1 CREATE" },
        /* P1-P2 not 0000 -- reserved by ISO 7816-9 */
        { (const uint8_t[]){ 0x00, 0xE0, 0x01, 0x00, 0x02, 0x62, 0x00 }, 7,
          SW_INCORRECT_P1P2, "P1 set" },
        /* empty template */
        { (const uint8_t[]){ 0x00, 0xE0, 0x00, 0x00, 0x02, 0x62, 0x00 }, 7,
          SW_WRONG_DATA, "empty FCP" },
        /* the template's length byte claims more than the APDU contains */
        { (const uint8_t[]){ 0x00, 0xE0, 0x00, 0x00, 0x04, 0x62, 0x08,
                             0x82, 0x01 }, 9,
          SW_WRONG_DATA, "truncated inner object" },
        /* indefinite length, which BER allows and we refuse */
        { (const uint8_t[]){ 0x00, 0xE0, 0x00, 0x00, 0x03, 0x62, 0x80,
                             0x00 }, 8,
          SW_WRONG_DATA, "indefinite length" },
        /* Lc longer than the bytes that follow */
        { (const uint8_t[]){ 0x00, 0xE0, 0x00, 0x00, 0x20, 0x62, 0x02,
                             0x82, 0x01 }, 9,
          SW_WRONG_LENGTH, "Lc overruns the frame" },
    };
    for (size_t i = 0; i < sizeof(raw) / sizeof(raw[0]); i++) {
        const uint16_t sw = send(raw[i].a, raw[i].n, NULL, NULL);
        if (sw != raw[i].sw) {
            (void)printf("      raw case '%s': got %04X want %04X\n",
                         raw[i].why, sw, raw[i].sw);
        }
        CHECK_HEX(sw, raw[i].sw);
    }

    /* --- well-framed APDUs carrying a bad template ----------------------- */
    struct { const uint8_t *v; uint8_t n; uint16_t sw; const char *why; } inner[] = {
        /* file descriptor byte with b8 set: reserved, so malformed rather
         * than "a type we do not support" */
        { (const uint8_t[]){ 0x82, 0x01, 0x81, 0x83, 0x02, 0x28, 0x11,
                             0x80, 0x02, 0x00, 0x10 }, 11,
          SW_WRONG_DATA, "FDB b8 set" },
        /* a DF that also declares an EF structure: self-contradictory */
        { (const uint8_t[]){ 0x82, 0x01, 0x39, 0x83, 0x02, 0x7F, 0x34 }, 7,
          SW_WRONG_DATA, "DF with a structure" },
        /* no file identifier */
        { (const uint8_t[]){ 0x82, 0x01, 0x01 }, 3,
          SW_WRONG_DATA, "missing tag 83" },
        /* no file descriptor byte */
        { (const uint8_t[]){ 0x83, 0x02, 0x28, 0x11, 0x80, 0x02, 0x00, 0x10 }, 8,
          SW_WRONG_DATA, "missing tag 82" },
        /* file identifier of the wrong length */
        { (const uint8_t[]){ 0x82, 0x01, 0x01, 0x83, 0x01, 0x28 }, 6,
          SW_WRONG_DATA, "1-byte FID" },
        /* two file identifiers: which one wins? neither. */
        { (const uint8_t[]){ 0x82, 0x01, 0x01, 0x83, 0x02, 0x28, 0x12,
                             0x83, 0x02, 0x28, 0x13, 0x80, 0x02, 0x00, 0x10 }, 15,
          SW_WRONG_DATA, "duplicate tag 83" },
        /* two descriptor bytes */
        { (const uint8_t[]){ 0x82, 0x01, 0x01, 0x82, 0x01, 0x38,
                             0x83, 0x02, 0x28, 0x12 }, 10,
          SW_WRONG_DATA, "duplicate tag 82" },
        /* SFI with the reserved low bits set */
        { (const uint8_t[]){ 0x82, 0x01, 0x01, 0x83, 0x02, 0x28, 0x14,
                             0x80, 0x02, 0x00, 0x08, 0x88, 0x01, 0x09 }, 14,
          SW_WRONG_DATA, "SFI low bits set" },
        /* SFI 31: encodable in the byte, but outside ISO's 1..30 and not
         * addressable by READ BINARY's 5-bit field */
        { (const uint8_t[]){ 0x82, 0x01, 0x01, 0x83, 0x02, 0x28, 0x14,
                             0x80, 0x02, 0x00, 0x08, 0x88, 0x01, 0xF8 }, 14,
          SW_WRONG_DATA, "SFI 31" },
        /* a zero-length descriptor byte */
        { (const uint8_t[]){ 0x82, 0x00, 0x83, 0x02, 0x28, 0x14 }, 6,
          SW_WRONG_DATA, "empty tag 82" },
    };
    for (size_t i = 0; i < sizeof(inner) / sizeof(inner[0]); i++) {
        const uint16_t sw = send_create_fcp(inner[i].v, inner[i].n);
        if (sw != inner[i].sw) {
            (void)printf("      inner case '%s': got %04X want %04X\n",
                         inner[i].why, sw, inner[i].sw);
        }
        CHECK_HEX(sw, inner[i].sw);
    }

    /* Something trailing the template: framed correctly, but we would not know
     * which of the two templates to honour, so we honour neither. */
    {
        const uint8_t body[] = { 0x62, 0x07, 0x82, 0x01, 0x38, 0x83, 0x02,
                                 0x7F, 0x30,
                                 0x83, 0x02, 0x00, 0x01 };
        CHECK_HEX(send_create_raw(body, (uint8_t)sizeof(body)), SW_WRONG_DATA);
    }

    /* None of that created anything. */
    CHECK_EQ(fs_child_count(fs_root_index()), 2); /* factory: EF 2F00, DF 7F10 */
}

TEST(unknown_tags_are_refused_not_ignored)
{
    /*
     * The most important test in this file.
     *
     * Tags 86 and 8C carry security attributes. A card that ignored what it
     * did not understand would accept "create this file, PIN-protected" and
     * create an UNPROTECTED file while answering 9000 -- the client would have
     * no way to know. Refusing is the only honest option until M3 implements
     * access conditions.
     */
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);

    const uint8_t with_8c[] = { 0x82, 0x01, 0x01,
                                0x83, 0x02, 0x28, 0x15,
                                0x80, 0x02, 0x00, 0x10,
                                0x8C, 0x02, 0x01, 0xFF }; /* 8C = access cond */
    CHECK_HEX(send_create_fcp(with_8c, (uint8_t)sizeof(with_8c)),
              SW_WRONG_DATA);
    /* And nothing was created, so the client cannot end up with an
     * unprotected file it believes is protected. */
    const uint16_t sw = select_fid(0x02u, 0x2815u);
    CHECK_HEX(sw, SW_FILE_NOT_FOUND);
}

TEST(unsupported_iso_file_types_say_so)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);

    /* Linear fixed (structure 010) and internal EF (type 001) are real ISO
     * file types we do not implement. 6A81 distinguishes "not implemented"
     * from "your template is broken", which 6A80 would not. */
    const uint8_t linear[] = { 0x82, 0x01, 0x02,
                               0x83, 0x02, 0x28, 0x16,
                               0x80, 0x02, 0x00, 0x10 };
    CHECK_HEX(send_create_fcp(linear, (uint8_t)sizeof(linear)),
              SW_FUNC_NOT_SUPPORTED);

    const uint8_t internal[] = { 0x82, 0x01, 0x09,
                                 0x83, 0x02, 0x28, 0x17,
                                 0x80, 0x02, 0x00, 0x10 };
    CHECK_HEX(send_create_fcp(internal, (uint8_t)sizeof(internal)),
              SW_FUNC_NOT_SUPPORTED);
}

TEST(type_and_size_must_agree)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);

    /* An EF with no declared size. */
    const uint8_t ef_no_size[] = { 0x82, 0x01, 0x01,
                                   0x83, 0x02, 0x28, 0x18 };
    CHECK_HEX(send_create_fcp(ef_no_size, (uint8_t)sizeof(ef_no_size)),
              SW_WRONG_DATA);

    /* A DF that declares data bytes. */
    const uint8_t df_with_size[] = { 0x82, 0x01, 0x38,
                                     0x83, 0x02, 0x7F, 0x31,
                                     0x80, 0x02, 0x00, 0x10 };
    CHECK_HEX(send_create_fcp(df_with_size, (uint8_t)sizeof(df_with_size)),
              SW_WRONG_DATA);

    /* A DF with a short EF identifier. */
    const uint8_t df_with_sfi[] = { 0x82, 0x01, 0x38,
                                    0x83, 0x02, 0x7F, 0x32,
                                    0x88, 0x01, 0x08 };
    CHECK_HEX(send_create_fcp(df_with_sfi, (uint8_t)sizeof(df_with_sfi)),
              SW_WRONG_DATA);

    /* A zero-length EF. */
    CHECK_HEX(create_ef(0x2819u, 0u, 0u), SW_WRONG_DATA);
}

TEST(a_bare_fcp_without_the_62_wrapper_also_works)
{
    /* ISO/IEC 7816-9 specifies the wrapper, but real cards and real tools
     * differ. The inner content is validated identically either way, so
     * accepting both is not laxity. */
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);
    const uint8_t bare[] = { 0x82, 0x01, 0x01,
                             0x83, 0x02, 0x28, 0x1A,
                             0x80, 0x02, 0x00, 0x10 };
    CHECK_HEX(send_create_raw(bare, (uint8_t)sizeof(bare)), SW_OK);
    CHECK_HEX(select_fid(0x02u, 0x281Au), SW_OK);
}

TEST(lifecycle_can_be_requested_and_is_honoured)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);

    /* Created DEACTIVATED (04): the file exists but is not usable, which must
     * be visible as 6985 rather than 6A82. */
    const uint8_t deact[] = { 0x82, 0x01, 0x01,
                              0x83, 0x02, 0x28, 0x1B,
                              0x80, 0x02, 0x00, 0x10,
                              0x8A, 0x01, 0x04 };
    CHECK_HEX(send_create_fcp(deact, (uint8_t)sizeof(deact)), SW_OK);
    CHECK_HEX(select_fid(0x02u, 0x281Bu), SW_CONDITIONS_NOT_SATISFIED);

    /* TERMINATED (0C) is irreversible, so creating something already dead is
     * refused rather than honoured. */
    const uint8_t term[] = { 0x82, 0x01, 0x01,
                             0x83, 0x02, 0x28, 0x1C,
                             0x80, 0x02, 0x00, 0x10,
                             0x8A, 0x01, 0x0C };
    CHECK_HEX(send_create_fcp(term, (uint8_t)sizeof(term)), SW_WRONG_DATA);

    /* An undefined life cycle byte is a data error, not something to default. */
    const uint8_t bogus[] = { 0x82, 0x01, 0x01,
                              0x83, 0x02, 0x28, 0x1D,
                              0x80, 0x02, 0x00, 0x10,
                              0x8A, 0x01, 0x77 };
    CHECK_HEX(send_create_fcp(bogus, (uint8_t)sizeof(bogus)), SW_WRONG_DATA);
}

TEST(create_inside_a_deactivated_df_is_refused)
{
    fresh();
    CHECK_HEX(select_fid(0x00u, 0x3F00u), SW_OK);

    /* Make a DF, deactivate it by writing the descriptor directly -- there is
     * no ACTIVATE/DEACTIVATE FILE command yet, and inventing one here would be
     * testing something that does not exist. */
    CHECK_HEX(create_df(0x7F33u), SW_OK);
    uint16_t idx = FS_INVALID_INDEX;
    CHECK_EQ(fs_find_child(fs_root_index(), 0x7F33u, &idx), FS_OK);

    fs_descriptor d;
    CHECK_EQ(fs_get(idx, &d), FS_OK);
    d.lifecycle = FS_LC_DEACTIVATED;
    CHECK_EQ(fs_store_write_desc(idx, &d), FS_OK);

    /* Cannot even select it, so reach it through fs_create_file directly with
     * a selection that points at it -- the check must live in the filesystem
     * layer, not only in the command handler. */
    fs_selection sel = { idx, FS_INVALID_INDEX };
    fs_descriptor req;
    os_memset(&req, 0, sizeof(req));
    req.file_id   = 0x6F41u;
    req.type      = FS_TYPE_EF_TRANSPARENT;
    req.lifecycle = FS_LC_ACTIVATED;
    req.size      = 8u;
    req.sfi       = FS_NO_SFI;
    CHECK_EQ(fs_create_file(&sel, &req, NULL), FS_ERR_NOT_USABLE);
}

int main(void)
{
    RUN(create_an_ef_then_use_it);
    RUN(create_a_df_and_a_file_inside_it);
    RUN(create_does_not_move_the_selection);
    RUN(a_created_file_survives_a_reset);
    RUN(duplicate_identifier_is_refused);
    RUN(duplicate_sfi_is_refused);
    RUN(reserved_identifiers_are_refused);
    RUN(the_descriptor_table_has_a_hard_limit);
    RUN(running_out_of_data_space_is_clean);
    RUN(delete_removes_the_file);
    RUN(delete_frees_the_descriptor_slot_but_not_the_data);
    RUN(delete_refuses_a_non_empty_df);
    RUN(delete_refuses_the_mf);
    RUN(delete_only_reaches_children_of_the_current_df);
    RUN(deleting_the_current_ef_clears_the_selection);
    RUN(delete_of_a_missing_file_is_reported);
    RUN(malformed_templates_are_refused);
    RUN(unknown_tags_are_refused_not_ignored);
    RUN(unsupported_iso_file_types_say_so);
    RUN(type_and_size_must_agree);
    RUN(a_bare_fcp_without_the_62_wrapper_also_works);
    RUN(lifecycle_can_be_requested_and_is_honoured);
    RUN(create_inside_a_deactivated_df_is_refused);
    TEST_MAIN_END();
}
