# SPDX-License-Identifier: MIT
"""VERIFY and the retry counter, over the card interface.

tests/unit/test_pin.c covers the command surface exhaustively. What is here is
what C on this HAL cannot reach:

  * the retry counter surviving a REAL power cycle -- the attack this whole
    design exists to stop is "get the try back by pulling the card", and the
    unit tests run in one process with an in-RAM store that is erased on
    power-on, so they cannot show it;
  * the blocked state surviving too, which is the same property one step
    further on;
  * the same behaviour on the ARM chip as on x86, from one test body.

WHAT IS STILL NOT COVERED, so this file is not read as more than it is: a power
cut in the MIDDLE of a verify, between the counter being committed and the
value being compared. That instant is what the design is built around, and
reaching it needs the fault-injection hook in hal_nvm_write() that M4 adds.
"""

import tempfile
import unittest

from scos.card import SmartCard

SW_OK = 0x9000
SW_WRONG_LENGTH = 0x6700
SW_BLOCKED = 0x6983
SW_REF_NOT_FOUND = 0x6A88
SW_SECURITY_NOT_SATISFIED = 0x6982


def tries(sw: int) -> int:
    """Attempts remaining from a 63CX, or -1 if it is not one."""
    return (sw & 0x0F) if (sw & 0xFFF0) == 0x63C0 else -1


def verify(card, value: str, ref: int = 1):
    body = value.encode("ascii")
    return card.send_apdu(
        bytes([0x00, 0x20, 0x00, ref, len(body)]) + body)


def set_pin(card, value: str, ref: int = 1):
    body = value.encode("ascii")
    return card.send_apdu(
        bytes([0x00, 0x24, 0x01, ref, len(body)]) + body)


def query(card, ref: int = 1):
    return card.send_apdu(bytes([0x00, 0x20, 0x00, ref]))


class PinTests(unittest.TestCase):

    def test_a_failed_attempt_is_not_restored_by_a_power_cycle(self):
        """THE test. If the try came back when power was removed, the retry
        counter would be infinite and a 4-digit PIN would fall in ten thousand
        attempts. It is a real attack that has been used against real
        products."""
        with tempfile.TemporaryDirectory() as state:
            with SmartCard(state_dir=state) as card:
                self.assertEqual(set_pin(card, "1234").sw, SW_OK)
                self.assertEqual(tries(verify(card, "9999").sw), 2)

            # Power removed and reapplied: a different process, same chip.
            with SmartCard(state_dir=state) as card:
                self.assertEqual(
                    tries(query(card).sw), 2,
                    "the failed attempt was restored by a power cycle")

    def test_the_counter_keeps_going_down_across_power_cycles(self):
        """One cycle proving nothing is restored is good; three proving the
        counter marches to zero regardless of how often power is cut is what
        actually closes the attack."""
        with tempfile.TemporaryDirectory() as state:
            expected = [2, 1]
            for want in expected:
                with SmartCard(state_dir=state) as card:
                    if want == 2:
                        self.assertEqual(set_pin(card, "1234").sw, SW_OK)
                    self.assertEqual(tries(verify(card, "9999").sw), want)

            # The third failure blocks, and blocking sticks.
            with SmartCard(state_dir=state) as card:
                self.assertEqual(verify(card, "9999").sw, SW_BLOCKED)
            with SmartCard(state_dir=state) as card:
                self.assertEqual(query(card).sw, SW_BLOCKED)
                # And the CORRECT PIN does not help. Blocked is a state.
                self.assertEqual(verify(card, "1234").sw, SW_BLOCKED)

    def test_a_correct_verify_survives_as_a_restored_counter(self):
        with tempfile.TemporaryDirectory() as state:
            with SmartCard(state_dir=state) as card:
                self.assertEqual(set_pin(card, "1234").sw, SW_OK)
                self.assertEqual(tries(verify(card, "9999").sw), 2)
                self.assertEqual(verify(card, "1234").sw, SW_OK)
            with SmartCard(state_dir=state) as card:
                self.assertEqual(tries(query(card).sw), 3,
                                 "a successful verify must restore the counter"
                                 " durably, not only in RAM")

    def test_authentication_does_not_survive_a_power_cycle(self):
        """The PIN state persists; the AUTHENTICATION must not. Otherwise
        pulling a card out and putting it back leaves it authenticated, and a
        stolen card needs no PIN at all."""
        with tempfile.TemporaryDirectory() as state:
            with SmartCard(state_dir=state) as card:
                self.assertEqual(set_pin(card, "1234").sw, SW_OK)
                self.assertEqual(verify(card, "1234").sw, SW_OK)
                self.assertEqual(query(card).sw, SW_OK)  # authenticated
            with SmartCard(state_dir=state) as card:
                # 63C3, not 9000: the card has forgotten, and the counter is
                # intact so nothing was spent by forgetting.
                self.assertEqual(tries(query(card).sw), 3)

    def test_a_pin_survives_and_still_works(self):
        with tempfile.TemporaryDirectory() as state:
            with SmartCard(state_dir=state) as card:
                self.assertEqual(set_pin(card, "864213").sw, SW_OK)
            with SmartCard(state_dir=state) as card:
                self.assertEqual(verify(card, "864213").sw, SW_OK)
                self.assertEqual(tries(verify(card, "864214").sw), 2)

    def test_changing_a_pin_needs_authentication_and_persists(self):
        with tempfile.TemporaryDirectory() as state:
            with SmartCard(state_dir=state) as card:
                self.assertEqual(set_pin(card, "1234").sw, SW_OK)
                # Now ACTIVE and unauthenticated in a fresh session: refused.
            with SmartCard(state_dir=state) as card:
                self.assertEqual(set_pin(card, "5678").sw,
                                 SW_SECURITY_NOT_SATISFIED)
                self.assertEqual(verify(card, "1234").sw, SW_OK)
                self.assertEqual(set_pin(card, "5678").sw, SW_OK)
            with SmartCard(state_dir=state) as card:
                self.assertEqual(verify(card, "5678").sw, SW_OK)

    def test_a_fresh_card_has_no_pin(self):
        """pin_personalise() ships no default. A fixed factory PIN in source
        would be a published credential, identical on every card built from
        this tree and preserved in the git history."""
        with SmartCard() as card:
            self.assertEqual(query(card).sw, SW_REF_NOT_FOUND)
            self.assertEqual(verify(card, "0000").sw, SW_REF_NOT_FOUND)

    def test_a_malformed_attempt_does_not_cost_a_try(self):
        """pin_verify() spends the try before it looks at the value, so a
        length check inside it would let a reader burn the cardholder's
        attempts with junk. The check lives ahead of the call."""
        with SmartCard() as card:
            self.assertEqual(set_pin(card, "1234").sw, SW_OK)
            self.assertEqual(verify(card, "1").sw, SW_WRONG_LENGTH)
            self.assertEqual(verify(card, "123").sw, SW_WRONG_LENGTH)
            self.assertEqual(tries(query(card).sw), 3)

    def test_brute_force_is_stopped(self):
        with SmartCard() as card:
            self.assertEqual(set_pin(card, "4271").sw, SW_OK)
            blocked_at = None
            for n in range(50):
                guess = f"{n:04d}"
                if guess == "4271":
                    continue
                sw = verify(card, guess).sw
                self.assertNotEqual(sw, SW_OK, f"{guess} was accepted")
                if sw == SW_BLOCKED and blocked_at is None:
                    blocked_at = n
            self.assertIsNotNone(blocked_at)
            self.assertLess(blocked_at, 5,
                            "the card allowed more attempts than its limit")


if __name__ == "__main__":
    unittest.main()
