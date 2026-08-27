# SPDX-License-Identifier: MIT
"""
Filesystem integration tests: a real simulator process, real NVM images.

What these cover that the C unit tests structurally cannot:
  - persistence across a genuine PROCESS restart, with the NVM written to and
    reloaded from disk. The C tests use in-RAM NVM, so they can prove data
    survives a warm reset but not a power cycle.
  - the full stack, transport included.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scos import SmartCard  # noqa: E402
from scos.card import (  # noqa: E402
    SW_FILE_NOT_FOUND,
    SW_INCORRECT_P1P2,
    SW_OK,
    hexs,
)

SW_EOF = 0x6282
SW_MEMORY_FAILURE = 0x6581
SW_WRONG_P1P2 = 0x6B00
SW_NO_CURRENT_EF = 0x6986
SW_INCOMPATIBLE_FILE = 0x6981

# The factory layout, from fs_personalise() in src/filesystem/fs.c.
MF = 0x3F00
EF_UNDER_MF = 0x2F00   # 32 bytes, SFI 1
DF_APP = 0x7F10
EF_A = 0x6F01          # 64 bytes, SFI 1
EF_B = 0x6F02          # 16 bytes, SFI 2


def sel(fid: int) -> str:
    """SELECT by identifier, P2=0C -- "no response data".

    These tests navigate; they do not inspect file control information. P2=00
    would ask for the FCI, and a Case 3 SELECT cannot return it under T=0 --
    the card answers 61XX and the reader fetches it with GET RESPONSE. That
    path is covered by test_get_response.py; asserting it here would make every
    navigation step a two-command dance for no added coverage.
    """
    return f"00A4000C02{fid:04X}"


def read(offset: int, length: int) -> str:
    return f"00B0{offset:04X}{length:02X}"


def update(offset: int, data: bytes) -> str:
    return f"00D6{offset:04X}{len(data):02X}{data.hex().upper()}"


class FsTestCase(unittest.TestCase):
    def setUp(self):
        self.card = SmartCard()
        self.addCleanup(self.card.close)

    def assertSW(self, response, expected, msg=""):
        self.assertEqual(
            response.sw,
            expected,
            f"{msg}\nexpected SW={expected:04X}, got {response.sw:04X}\n"
            f"transcript:\n{self.card.transcript}",
        )


class TestNavigation(FsTestCase):
    def test_factory_layout_is_navigable(self):
        self.assertSW(self.card.send_apdu(sel(MF)), SW_OK)
        self.assertSW(self.card.send_apdu(sel(EF_UNDER_MF)), SW_OK)
        self.assertSW(self.card.send_apdu(sel(MF)), SW_OK)
        self.assertSW(self.card.send_apdu(sel(DF_APP)), SW_OK)
        self.assertSW(self.card.send_apdu(sel(EF_A)), SW_OK)
        self.assertSW(self.card.send_apdu(sel(EF_B)), SW_OK)

    def test_scoping_prevents_cross_df_access(self):
        # From the MF, an EF inside DF 7F10 is NOT reachable by identifier.
        # There is deliberately no global search: that would let one
        # application reach another's files by FID alone.
        self.assertSW(self.card.send_apdu(sel(MF)), SW_OK)
        self.assertSW(self.card.send_apdu(sel(EF_A)), SW_FILE_NOT_FOUND)

        # Enter the DF and it becomes reachable.
        self.assertSW(self.card.send_apdu(sel(DF_APP)), SW_OK)
        self.assertSW(self.card.send_apdu(sel(EF_A)), SW_OK)

        # And the MF's own EF is now out of scope.
        self.assertSW(self.card.send_apdu(sel(EF_UNDER_MF)), SW_FILE_NOT_FOUND)

    def test_select_parent(self):
        self.assertSW(self.card.send_apdu(sel(DF_APP)), SW_OK)
        self.assertSW(self.card.send_apdu("00A4030C"), SW_OK)   # P1=03
        self.assertSW(self.card.send_apdu(sel(EF_UNDER_MF)), SW_OK)
        # The MF has no parent.
        self.assertSW(self.card.send_apdu(sel(MF)), SW_OK)
        self.assertSW(self.card.send_apdu("00A4030C"), SW_FILE_NOT_FOUND)

    def test_select_by_path_from_mf(self):
        # P1=08: 7F10 / 6F02
        self.assertSW(self.card.send_apdu("00A4080C047F106F02"), SW_OK)
        r = self.card.send_apdu(read(0, 4))
        self.assertSW(r, SW_OK)
        self.assertEqual(len(r.data), 4)

    def test_typed_child_selection(self):
        # P1=01 wants a DF, P1=02 wants an EF.
        self.assertSW(self.card.send_apdu(f"00A401 0C02{DF_APP:04X}".replace(" ", "")), SW_OK)
        # Asking for a child DF but naming an EF must fail loudly.
        self.assertSW(
            self.card.send_apdu(f"00A4010C02{EF_A:04X}"), SW_INCOMPATIBLE_FILE
        )
        self.assertSW(self.card.send_apdu(f"00A4020C02{EF_A:04X}"), SW_OK)

    def test_fci_template(self):
        # Case 4 SELECT returns file control information.
        r = self.card.send_apdu(f"00A4000002{EF_UNDER_MF:04X}20")
        self.assertSW(r, SW_OK)
        self.assertGreater(len(r.data), 0, "expected an FCI template")
        self.assertEqual(r.data[0], 0x6F, f"FCI tag, got {hexs(r.data)}")
        self.assertEqual(r.data[1], len(r.data) - 2, "template length")
        # 82 01 01 : transparent working EF
        self.assertEqual(r.data[2:5], bytes([0x82, 0x01, 0x01]))
        # 83 02 2F 00 : file identifier
        self.assertEqual(r.data[5:9], bytes([0x83, 0x02, 0x2F, 0x00]))
        # 80 02 00 20 : 32 data bytes
        self.assertIn(bytes([0x80, 0x02, 0x00, 0x20]), r.data)

    def test_le_too_small_reports_exact_length(self):
        r = self.card.send_apdu(f"00A4000002{MF:04X}04")
        self.assertEqual(r.sw1, 0x6C, f"expected 6CXX, got {r.sw:04X}")
        self.assertGreater(r.sw2, 4)
        self.assertEqual(r.data, b"")
        # Retrying with the length the card asked for must succeed.
        r2 = self.card.send_apdu(f"00A4000002{MF:04X}{r.sw2:02X}")
        self.assertSW(r2, SW_OK)
        self.assertEqual(len(r2.data), r.sw2)


class TestBinary(FsTestCase):
    def test_read_needs_a_current_ef(self):
        self.assertSW(self.card.send_apdu(sel(MF)), SW_OK)
        self.assertSW(self.card.send_apdu(read(0, 4)), SW_NO_CURRENT_EF)

    def test_update_then_read(self):
        self.assertSW(self.card.send_apdu(sel(EF_UNDER_MF)), SW_OK)
        payload = bytes.fromhex("DEADBEEF")
        self.assertSW(self.card.send_apdu(update(0, payload)), SW_OK)
        r = self.card.send_apdu(read(0, 4))
        self.assertSW(r, SW_OK)
        self.assertEqual(r.data, payload)

    def test_offsets_are_honoured(self):
        self.assertSW(self.card.send_apdu(sel(EF_A)), SW_FILE_NOT_FOUND)
        self.assertSW(self.card.send_apdu(sel(DF_APP)), SW_OK)
        self.assertSW(self.card.send_apdu(sel(EF_A)), SW_OK)
        self.assertSW(self.card.send_apdu(update(10, b"\xAA\xBB")), SW_OK)
        r = self.card.send_apdu(read(10, 2))
        self.assertEqual(r.data, b"\xAA\xBB")
        # Bytes either side untouched (still erased).
        self.assertEqual(self.card.send_apdu(read(8, 2)).data, b"\xFF\xFF")
        self.assertEqual(self.card.send_apdu(read(12, 2)).data, b"\xFF\xFF")

    def test_short_read_reports_6282(self):
        self.assertSW(self.card.send_apdu(sel(EF_UNDER_MF)), SW_OK)
        # 32-byte file, ask for 256.
        r = self.card.send_apdu("00B0000000")
        self.assertSW(r, SW_EOF)
        self.assertEqual(len(r.data), 32)
        # Exactly the file length is a clean 9000.
        r = self.card.send_apdu(read(0, 0x20))
        self.assertSW(r, SW_OK)
        self.assertEqual(len(r.data), 32)

    def test_cannot_read_or_write_past_end_of_file(self):
        self.assertSW(self.card.send_apdu(sel(EF_UNDER_MF)), SW_OK)
        self.assertSW(self.card.send_apdu(read(100, 4)), SW_WRONG_P1P2)
        # A write that would cross the end is refused ENTIRELY.
        self.assertSW(self.card.send_apdu(update(30, b"\x01\x02\x03\x04")),
                      SW_WRONG_P1P2)
        # ...and nothing was written.
        self.assertEqual(self.card.send_apdu(read(30, 2)).data, b"\xFF\xFF")
        # Exactly filling the file is legal.
        self.assertSW(self.card.send_apdu(update(0, b"\x5A" * 32)), SW_OK)

    def test_sfi_form_selects_implicitly(self):
        # P1 = 0x81: SFI form, SFI 1. No SELECT needed.
        self.assertSW(self.card.send_apdu("00D6810003112233"), SW_OK)
        r = self.card.send_apdu("00B0810003")
        self.assertSW(r, SW_OK)
        self.assertEqual(r.data, bytes.fromhex("112233"))

    def test_sfi_is_scoped_to_the_current_df(self):
        # SFI 1 under the MF is 2F00; SFI 1 inside 7F10 is 6F01. Same short
        # identifier, different files -- SFIs are per-DF, not global.
        self.assertSW(self.card.send_apdu("00D6810002AAAA"), SW_OK)
        self.assertSW(self.card.send_apdu(sel(DF_APP)), SW_OK)
        self.assertSW(self.card.send_apdu("00D6810002BBBB"), SW_OK)

        r = self.card.send_apdu("00B0810002")
        self.assertEqual(r.data, b"\xBB\xBB", "should read 6F01 inside the DF")
        self.assertSW(self.card.send_apdu(sel(MF)), SW_OK)
        r = self.card.send_apdu("00B0810002")
        self.assertEqual(r.data, b"\xAA\xAA", "should read 2F00 under the MF")

    def test_cannot_read_a_df_as_data(self):
        self.assertSW(self.card.send_apdu(sel(DF_APP)), SW_OK)
        # A DF is current but there is no current EF.
        self.assertSW(self.card.send_apdu(read(0, 4)), SW_NO_CURRENT_EF)

    def test_reserved_p1_bits_rejected(self):
        self.assertSW(self.card.send_apdu("00B0E10004"), SW_INCORRECT_P1P2)
        self.assertSW(self.card.send_apdu("00B0800004"), SW_INCORRECT_P1P2)


class TestPersistence(unittest.TestCase):
    """The tests that need a real process restart and real NVM files."""

    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="scos-state-")
        self.addCleanup(shutil.rmtree, self.state, ignore_errors=True)

    def test_data_survives_a_power_cycle(self):
        payload = bytes.fromhex("C0FFEE00")

        with SmartCard(state_dir=self.state) as card:
            self.assertEqual(card.send_apdu(sel(EF_UNDER_MF)).sw, SW_OK)
            self.assertEqual(card.send_apdu(update(0, payload)).sw, SW_OK)

        # The images must exist and be the configured sizes.
        eeprom = os.path.join(self.state, "card_eeprom.bin")
        flash = os.path.join(self.state, "card_flash.bin")
        self.assertTrue(os.path.isfile(eeprom))
        self.assertTrue(os.path.isfile(flash))
        self.assertEqual(os.path.getsize(eeprom), 16 * 1024)
        self.assertEqual(os.path.getsize(flash), 256 * 1024)

        # A brand-new process, reading the images off disk.
        with SmartCard(state_dir=self.state) as card:
            self.assertEqual(card.send_apdu(sel(EF_UNDER_MF)).sw, SW_OK)
            r = card.send_apdu(read(0, 4))
            self.assertEqual(r.sw, SW_OK)
            self.assertEqual(r.data, payload, "data did not survive power-off")

    def test_filesystem_is_formatted_once_not_every_boot(self):
        # A second boot must MOUNT the existing filesystem, not reformat it.
        # If it reformatted, the marker below would come back erased.
        with SmartCard(state_dir=self.state) as card:
            self.assertEqual(card.send_apdu(sel(EF_B)).sw, SW_FILE_NOT_FOUND)
            self.assertEqual(card.send_apdu(sel(DF_APP)).sw, SW_OK)
            self.assertEqual(card.send_apdu(sel(EF_B)).sw, SW_OK)
            self.assertEqual(card.send_apdu(update(0, b"\x42")).sw, SW_OK)

        for boot in range(3):
            with SmartCard(state_dir=self.state) as card:
                self.assertEqual(card.send_apdu(sel(DF_APP)).sw, SW_OK)
                self.assertEqual(card.send_apdu(sel(EF_B)).sw, SW_OK)
                r = card.send_apdu(read(0, 1))
                self.assertEqual(
                    r.data, b"\x42", f"reformatted on boot {boot + 1}"
                )

    def test_superblock_corruption_bricks_the_card_safely(self):
        with SmartCard(state_dir=self.state) as card:
            self.assertEqual(card.send_apdu(sel(MF)).sw, SW_OK)

        # Corrupt the superblock's data_top field without fixing its CRC --
        # exactly what a torn write or a worn cell produces.
        eeprom = os.path.join(self.state, "card_eeprom.bin")
        with open(eeprom, "r+b") as f:
            f.seek(8)
            original = f.read(1)
            f.seek(8)
            f.write(bytes([original[0] ^ 0x55]))

        # The card must come up refusing to work, and must NOT auto-format:
        # that would destroy the data most worth recovering, and would give
        # anyone able to corrupt one byte a reliable card-wipe primitive.
        with SmartCard(state_dir=self.state) as card:
            r = card.send_apdu(sel(MF))
            self.assertEqual(
                r.sw,
                SW_MEMORY_FAILURE,
                f"expected 6581, got {r.sw:04X} -- did it auto-format?",
            )

    def test_reset_clears_selection_but_not_data(self):
        with SmartCard(state_dir=self.state) as card:
            self.assertEqual(card.send_apdu(sel(EF_UNDER_MF)).sw, SW_OK)
            self.assertEqual(card.send_apdu(update(0, b"\x99")).sw, SW_OK)

            card.reset()

            # Selection gone (it lived in RAM).
            self.assertEqual(card.send_apdu(read(0, 1)).sw, SW_NO_CURRENT_EF)
            # Data intact (it lives in NVM). That split is the point.
            self.assertEqual(card.send_apdu(sel(EF_UNDER_MF)).sw, SW_OK)
            self.assertEqual(card.send_apdu(read(0, 1)).data, b"\x99")


class TestRobustness(FsTestCase):
    def test_card_survives_hostile_binary_commands(self):
        self.assertSW(self.card.send_apdu(sel(EF_UNDER_MF)), SW_OK)
        for p1 in range(0, 256, 23):
            for p2 in range(0, 256, 37):
                r = self.card.send_apdu(f"00B0{p1:02X}{p2:02X}20")
                self.assertIn(r.sw1 & 0xF0, (0x60, 0x90))
                r = self.card.send_apdu(f"00D6{p1:02X}{p2:02X}04DEADBEEF")
                self.assertIn(r.sw1 & 0xF0, (0x60, 0x90))
        # Still usable, and the file is still its documented size.
        self.assertSW(self.card.send_apdu(sel(EF_UNDER_MF)), SW_OK)
        r = self.card.send_apdu("00A400000220F00".replace("20F00", "2F0020"))
        self.assertSW(r, SW_OK)
        self.assertIn(bytes([0x80, 0x02, 0x00, 0x20]), r.data)

    def test_malformed_paths(self):
        # Odd-length path: not a whole number of 2-byte identifiers.
        self.assertSW(self.card.send_apdu("00A4080C03 7F1000".replace(" ", "")),
                      0x6A80)
        # Empty path.
        self.assertSW(self.card.send_apdu("00A40800"), 0x6A87)


if __name__ == "__main__":
    unittest.main(verbosity=2)
