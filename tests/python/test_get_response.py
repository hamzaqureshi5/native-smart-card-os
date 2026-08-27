# SPDX-License-Identifier: MIT
"""GET RESPONSE (C0) and 61XX, over the card interface.

The C suite (tests/unit/test_get_response.c) covers the sequencing rules and
the failure paths in detail. This file checks the thing a reader actually
cares about: that the two-step and the one-step produce identical bytes, on
both the native simulator and real ARM machine code.

Why this command exists is worth restating, because it looks like pointless
indirection until you know: T=0 is half-duplex and the reader must say in
advance how many bytes it will accept. A Case 3 command -- header plus data,
no Le -- therefore has no channel on which to return anything. ISO's answer is
61XX ("I have XX bytes") followed by GET RESPONSE.
"""

import unittest

from scos.card import SmartCard

SW_OK = 0x9000
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_INCORRECT_P1P2 = 0x6A86
SW_WRONG_LENGTH = 0x6700


def sw1(sw: int) -> int:
    return (sw >> 8) & 0xFF


class GetResponseTests(unittest.TestCase):

    # A Case 3 SELECT of the MF: Lc=2, data=3F00, no Le.
    CASE3_SELECT = "00A40000023F00"
    # The same thing with Le=00 (256), so the data comes back directly.
    CASE4_SELECT = "00A40000023F0000"

    def test_case3_select_announces_data_instead_of_returning_nothing(self):
        with SmartCard() as card:
            r = card.send_apdu(self.CASE3_SELECT)
            self.assertEqual(sw1(r.sw), 0x61, f"expected 61XX, got {r.sw:04X}")
            self.assertEqual(r.data, b"", "61XX carries no data of its own")
            self.assertGreater(r.sw & 0xFF, 0, "announced length must be non-zero")

    def test_the_two_step_matches_the_one_step(self):
        """The card's answer must not depend on how the reader asked."""
        with SmartCard() as card:
            direct = card.send_apdu(self.CASE4_SELECT)
            self.assertEqual(direct.sw, SW_OK)
            self.assertGreater(len(direct.data), 0)

        with SmartCard() as card:
            announced = card.send_apdu(self.CASE3_SELECT)
            self.assertEqual(sw1(announced.sw), 0x61)
            n = announced.sw & 0xFF
            fetched = card.send_apdu(f"00C00000{n:02X}")
            self.assertEqual(fetched.sw, SW_OK)
            self.assertEqual(fetched.data, direct.data)

    def test_collecting_in_chunks_reassembles_correctly(self):
        with SmartCard() as card:
            whole = card.send_apdu(self.CASE4_SELECT).data

            announced = card.send_apdu(self.CASE3_SELECT)
            total = announced.sw & 0xFF
            self.assertEqual(total, len(whole))

            first = card.send_apdu("00C0000004")
            self.assertEqual(sw1(first.sw), 0x61)
            self.assertEqual(first.sw & 0xFF, total - 4)
            self.assertEqual(len(first.data), 4)

            rest = card.send_apdu(f"00C00000{total - 4:02X}")
            self.assertEqual(rest.sw, SW_OK)
            self.assertEqual(first.data + rest.data, whole)

    def test_an_intervening_command_discards_the_data(self):
        """The rule that makes this safe rather than merely convenient.

        A card that kept pending data would let a later, unrelated command
        collect an earlier one's output -- from M3, possibly across a change of
        authentication state.
        """
        with SmartCard() as card:
            announced = card.send_apdu(self.CASE3_SELECT)
            n = announced.sw & 0xFF
            # Innocent, successful, and fatal to the pending data.
            self.assertEqual(card.send_apdu("00A4000C023F00").sw, SW_OK)
            self.assertEqual(card.send_apdu(f"00C00000{n:02X}").sw,
                             SW_CONDITIONS_NOT_SATISFIED)

    def test_a_reset_discards_the_data(self):
        with SmartCard() as card:
            announced = card.send_apdu(self.CASE3_SELECT)
            n = announced.sw & 0xFF
            card.reset()
            self.assertEqual(card.send_apdu(f"00C00000{n:02X}").sw,
                             SW_CONDITIONS_NOT_SATISFIED)

    def test_get_response_out_of_sequence_is_refused(self):
        with SmartCard() as card:
            self.assertEqual(card.send_apdu("00C000000C").sw,
                             SW_CONDITIONS_NOT_SATISFIED)

    def test_asking_for_too_much_gives_6cxx_and_does_not_consume(self):
        with SmartCard() as card:
            announced = card.send_apdu(self.CASE3_SELECT)
            n = announced.sw & 0xFF

            over = card.send_apdu("00C00000FF")
            self.assertEqual(sw1(over.sw), 0x6C)
            self.assertEqual(over.sw & 0xFF, n, "6CXX must name the real length")
            self.assertEqual(over.data, b"")

            # Still there.
            again = card.send_apdu(f"00C00000{n:02X}")
            self.assertEqual(again.sw, SW_OK)
            self.assertEqual(len(again.data), n)

    def test_malformed_get_response(self):
        with SmartCard() as card:
            for apdu, want, why in (
                ("00C001000C", SW_INCORRECT_P1P2, "P1 not zero"),
                ("00C000010C", SW_INCORRECT_P1P2, "P2 not zero"),
                ("00C0000002ABCD", SW_WRONG_LENGTH, "has a data field"),
                ("00C00000", SW_WRONG_LENGTH, "no Le"),
            ):
                card.send_apdu(self.CASE3_SELECT)   # re-arm each time
                self.assertEqual(card.send_apdu(apdu).sw, want, why)


if __name__ == "__main__":
    unittest.main()
