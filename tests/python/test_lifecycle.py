# SPDX-License-Identifier: MIT
"""ACTIVATE FILE (44) and DEACTIVATE FILE (04), over the card interface.

tests/unit/test_lifecycle.c covers the APDU contract exhaustively. What is
here is what C on this HAL cannot reach: the state surviving a real power
cycle, and the same behaviour on the ARM chip as on x86 from one test body.

The sequence that matters is deactivate-then-activate with no SELECT between.
Both commands address "the currently selected file", so three individually
defensible design choices would each break the pair and leave deactivation a
one-way door: clearing the selection after DEACTIVATE, refusing to select a
deactivated file, or refusing ACTIVATE on a file that is not usable.
"""

import os
import tempfile
import unittest

from scos.card import SmartCard

SW_OK = 0x9000
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_INCORRECT_P1P2 = 0x6A86
SW_LC_INCONSISTENT = 0x6A87

DEACTIVATE = "00040000"
ACTIVATE = "00440000"


class LifecycleTests(unittest.TestCase):

    def goto_2f00(self, card):
        self.assertEqual(card.send_apdu("00A4000C023F00").sw, SW_OK)
        self.assertEqual(card.send_apdu("00A4020C022F00").sw, SW_OK)

    def test_round_trip_with_no_reselect(self):
        with SmartCard() as card:
            self.goto_2f00(card)
            self.assertEqual(card.send_apdu("00B0000004").sw, SW_OK)

            self.assertEqual(card.send_apdu(DEACTIVATE).sw, SW_OK)
            self.assertEqual(card.send_apdu("00B0000004").sw,
                             SW_CONDITIONS_NOT_SATISFIED)

            self.assertEqual(card.send_apdu(ACTIVATE).sw, SW_OK)
            self.assertEqual(card.send_apdu("00B0000004").sw, SW_OK)

    def test_the_state_survives_a_power_cycle(self):
        """The whole reason this is a python test. Life cycle lives in NVM, so
        pulling the card out of the reader must not quietly re-enable a file an
        administrator took out of service."""
        with tempfile.TemporaryDirectory() as state:
            with SmartCard(state_dir=state) as card:
                self.goto_2f00(card)
                self.assertEqual(card.send_apdu(DEACTIVATE).sw, SW_OK)
                self.assertEqual(card.send_apdu("00B0000004").sw,
                                 SW_CONDITIONS_NOT_SATISFIED)

            # Power removed and reapplied: a different process, same chip.
            with SmartCard(state_dir=state) as card:
                self.goto_2f00(card)
                self.assertEqual(
                    card.send_apdu("00B0000004").sw,
                    SW_CONDITIONS_NOT_SATISFIED,
                    "a deactivated file came back to life after a power cycle")

                # And it can still be reactivated on the fresh session.
                self.assertEqual(card.send_apdu(ACTIVATE).sw, SW_OK)
                self.assertEqual(card.send_apdu("00B0000004").sw, SW_OK)

    def test_the_mf_cannot_be_deactivated(self):
        """The MF is the only entry point to the tree, so turning it off is
        bricking the card rather than administering it."""
        with SmartCard() as card:
            self.assertEqual(card.send_apdu("00A4000C023F00").sw, SW_OK)
            self.assertEqual(card.send_apdu(DEACTIVATE).sw,
                             SW_CONDITIONS_NOT_SATISFIED)
            # Still fully usable.
            self.assertEqual(card.send_apdu("00A4020C022F00").sw, SW_OK)
            self.assertEqual(card.send_apdu("00B0000004").sw, SW_OK)

    def test_a_data_field_is_refused_not_ignored(self):
        """With P1-P2 zero the target is the selection, so a data field is a
        file identifier the card is NOT reading. Ignoring it would let a reader
        believe it deactivated one file while the card deactivated another."""
        with SmartCard() as card:
            self.goto_2f00(card)
            self.assertEqual(card.send_apdu("0004000002" + "6F01").sw,
                             SW_LC_INCONSISTENT)
            # Nothing happened as a side effect.
            self.assertEqual(card.send_apdu("00B0000004").sw, SW_OK)

    def test_path_addressing_is_refused_precisely(self):
        """ISO/IEC 7816-9 also defines path-based addressing. Not implemented,
        and refused with 6A86 -- not 6D00, which would tell a reader the
        instruction itself is unknown and to stop using it."""
        with SmartCard() as card:
            self.goto_2f00(card)
            self.assertEqual(card.send_apdu("00040800").sw, SW_INCORRECT_P1P2)
            self.assertEqual(card.send_apdu("00440900").sw, SW_INCORRECT_P1P2)
            self.assertEqual(card.send_apdu("00B0000004").sw, SW_OK)

    def test_repeating_is_idempotent(self):
        """If the response is lost on the link, the reader's only recourse is
        to send it again."""
        with SmartCard() as card:
            self.goto_2f00(card)
            self.assertEqual(card.send_apdu(DEACTIVATE).sw, SW_OK)
            self.assertEqual(card.send_apdu(DEACTIVATE).sw, SW_OK)
            self.assertEqual(card.send_apdu(ACTIVATE).sw, SW_OK)
            self.assertEqual(card.send_apdu(ACTIVATE).sw, SW_OK)
            self.assertEqual(card.send_apdu("00B0000004").sw, SW_OK)

    def test_deactivating_a_df_blocks_its_subtree(self):
        """The property that makes DEACTIVATE on a directory mean anything.
        Without the ancestor walk in fs_ef_read, the card would report success
        and every file inside would stay readable."""
        with SmartCard() as card:
            # 7F10/6F01 is in the factory layout.
            self.assertEqual(card.send_apdu("00A4000C023F00").sw, SW_OK)
            self.assertEqual(card.send_apdu("00A4010C027F10").sw, SW_OK)
            self.assertEqual(card.send_apdu("00A4020C026F01").sw, SW_OK)
            self.assertEqual(card.send_apdu("00B0000004").sw, SW_OK)

            # Aim at the DF: selecting a child DF from the MF clears cur_ef.
            self.assertEqual(card.send_apdu("00A4000C023F00").sw, SW_OK)
            self.assertEqual(card.send_apdu("00A4010C027F10").sw, SW_OK)
            self.assertEqual(card.send_apdu(DEACTIVATE).sw, SW_OK)

            # The EF is still ACTIVATED in its own right, and unreachable.
            self.assertEqual(card.send_apdu("00A4020C026F01").sw, SW_OK)
            self.assertEqual(card.send_apdu("00B0000004").sw,
                             SW_CONDITIONS_NOT_SATISFIED)

            # Reactivating the DF restores the whole subtree.
            self.assertEqual(card.send_apdu("00A4000C023F00").sw, SW_OK)
            self.assertEqual(card.send_apdu("00A4010C027F10").sw, SW_OK)
            self.assertEqual(card.send_apdu(ACTIVATE).sw, SW_OK)
            self.assertEqual(card.send_apdu("00A4020C026F01").sw, SW_OK)
            self.assertEqual(card.send_apdu("00B0000004").sw, SW_OK)


if __name__ == "__main__":
    unittest.main()
