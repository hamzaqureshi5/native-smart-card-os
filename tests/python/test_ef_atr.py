# SPDX-License-Identifier: MIT
"""EF.ATR (2F01), over the card interface.

The ATR is clocked out before any command and cannot change at run time, so
anything a reader must learn that is not in the ATR has to be readable
somewhere. ISO/IEC 7816-4 reserves EF.ATR at 2F01 directly under the MF for
that, holding BER-TLV data objects.

These tests read it the way a reader would -- SELECT then READ BINARY, no
inside knowledge -- and check the CLAIM, not merely that the file exists. A
wrong byte in this file does not break the card; it makes the card lie to
every reader that asks, which is worse and far harder to notice.
"""

import unittest

from scos.card import SmartCard

SW_OK = 0x9000

EF_ATR_FID = 0x2F01
CAP_EXTENDED_LENGTH = 0x40
CAP_COMMAND_CHAINING = 0x80


class EfAtrTests(unittest.TestCase):

    def read_ef_atr(self, card) -> bytes:
        r = card.send_apdu("00A4000C023F00")
        self.assertEqual(r.sw, SW_OK, f"select MF: {r}")
        r = card.send_apdu("00A4020C02" + f"{EF_ATR_FID:04X}")
        self.assertEqual(r.sw, SW_OK, f"select EF.ATR: {r}")
        # Ask for more than the file holds: the card returns what exists and
        # says 6282, which is also how a reader discovers the length.
        r = card.send_apdu("00B0000000")
        self.assertIn(r.sw, (SW_OK, 0x6282), f"read EF.ATR: {r}")
        return r.data

    def test_ef_atr_exists_and_is_readable(self):
        with SmartCard() as card:
            data = self.read_ef_atr(card)
            self.assertGreater(len(data), 0, "EF.ATR must not be empty")

    def test_it_holds_a_card_capabilities_object(self):
        with SmartCard() as card:
            data = self.read_ef_atr(card)
            self.assertEqual(data[0], 0x47, "tag 47, card capabilities")
            self.assertEqual(data[1], 0x03, "three bytes of value")
            self.assertEqual(len(data), 5,
                             "exactly the object, no trailing padding -- "
                             "trailing FF reads as a malformed object")

    def test_extended_length_is_advertised(self):
        """The bit this milestone made true. A reader that asks the card
        whether it accepts extended APDUs must be told yes."""
        with SmartCard() as card:
            data = self.read_ef_atr(card)
            self.assertTrue(data[4] & CAP_EXTENDED_LENGTH,
                            f"extended-length bit not set in {data.hex()}")

    def test_command_chaining_is_not_advertised(self):
        """And the bit that is NOT true must stay clear. The card refuses the
        CLA chaining bit with 6884, so advertising chaining would send a reader
        down a path the card rejects -- worse than advertising nothing."""
        with SmartCard() as card:
            data = self.read_ef_atr(card)
            self.assertFalse(data[4] & CAP_COMMAND_CHAINING,
                             "chaining advertised but the card answers 6884")
            # Prove the refusal, so the two statements cannot drift apart.
            r = card.send_apdu("10A4000C023F00")   # CLA 10 = chaining bit
            self.assertEqual(r.sw, 0x6884, f"expected 6884, got {r}")

    def test_unasserted_bytes_are_zero_not_guessed(self):
        """Bytes 1 and 2 are deliberately zero: their bit assignments are not
        something this project has the specification text to state, and
        under-claiming is the safe direction in the one file whose purpose is
        to tell the truth about the card."""
        with SmartCard() as card:
            data = self.read_ef_atr(card)
            self.assertEqual(data[2], 0x00)
            self.assertEqual(data[3], 0x00)

    def test_it_can_be_read_with_an_extended_apdu(self):
        """A pleasing closed loop: the file that advertises extended-length
        support is itself readable with an extended-length command."""
        with SmartCard() as card:
            self.assertEqual(card.send_apdu("00A4000C023F00").sw, SW_OK)
            self.assertEqual(
                card.send_apdu("00A4020C02" + f"{EF_ATR_FID:04X}").sw, SW_OK)
            # Case 2E, Le = 0x0000 = 65536: "everything you have".
            r = card.send_apdu("00B0000000" + "0000")
            self.assertIn(r.sw, (SW_OK, 0x6282), f"{r}")
            self.assertEqual(r.data[0], 0x47)
            self.assertEqual(len(r.data), 5)

    def test_it_is_not_writable_by_accident(self):
        """It is an ordinary EF, so UPDATE BINARY works on it -- there is no
        access control until M3. This test PINS that fact rather than pretending
        otherwise, so the day access conditions land, it fails and gets fixed.
        """
        with SmartCard() as card:
            self.assertEqual(card.send_apdu("00A4000C023F00").sw, SW_OK)
            self.assertEqual(
                card.send_apdu("00A4020C02" + f"{EF_ATR_FID:04X}").sw, SW_OK)
            r = card.send_apdu("00D6000001FF")
            self.assertEqual(
                r.sw, SW_OK,
                "EF.ATR is writable today; when M3 adds access conditions "
                "this must become a refusal and this test must change")


if __name__ == "__main__":
    unittest.main()
