# SPDX-License-Identifier: MIT
"""
Integration tests: a real simulator process, driven over its transport.

The C unit tests already cover the same command logic by calling scos_process()
directly. These tests exist to cover what unit tests structurally cannot: that
the binary starts, that the transport frames APDUs correctly, that stdout is a
clean response stream, and that the whole stack works end to end.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scos import SmartCard  # noqa: E402
from scos.card import (  # noqa: E402
    SW_CHAINING_UNSUPPORTED,
    SW_CHANNEL_UNSUPPORTED,
    SW_CLA_NOT_SUPPORTED,
    SW_CONDITIONS_NOT_SATISFIED,
    SW_FILE_NOT_FOUND,
    SW_FUNC_NOT_SUPPORTED,
    SW_INCORRECT_P1P2,
    SW_INS_NOT_SUPPORTED,
    SW_LC_INCONSISTENT_P1P2,
    SW_OK,
    SW_SM_UNSUPPORTED,
    SW_WRONG_LENGTH,
    hexs,
)


class CardTestCase(unittest.TestCase):
    """One freshly powered card per test, torn down afterwards."""

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


class TestSelectMasterFile(CardTestCase):
    """The milestone target."""

    def test_the_first_apdu(self):
        # The exact command from the specification, and it is a Case 3 SELECT
        # with P2=00 -- so it asks for the file's control information while
        # giving the card no Le to return it in. The correct ISO answer is
        # 61XX: "I have XX bytes, come and get them with GET RESPONSE."
        #
        # Until M2b this returned 9000 with no data, which was well-formed and
        # silently useless. Kept as an explicit assertion here because this
        # APDU is the project's canonical first command.
        response = self.card.send_apdu("00A40000023F00")
        self.assertEqual(response.sw1, 0x61, f"got {response.sw:04X}")
        self.assertEqual(response.data, b"", "61XX carries no data of its own")

        # And the selection really moved -- 61XX is a success status. A card
        # that staged the FCI without committing would answer this correctly
        # and then read the wrong file.
        fetched = self.card.send_apdu(f"00C00000{response.sw2:02X}")
        self.assertSW(fetched, SW_OK)
        self.assertEqual(fetched.data[0], 0x6F, "FCI template")

    def test_spaces_in_hex_are_accepted(self):
        # A human types it with spaces; the transport must not care. P2=0C so
        # this is about the transport, not about 61XX.
        self.assertSW(self.card.send_apdu("00 A4 00 0C 02 3F 00"), SW_OK)

    def test_select_helper(self):
        self.assertSW(self.card.select(0x3F00), SW_OK)

    def test_select_is_repeatable(self):
        for _ in range(20):
            self.assertSW(self.card.select(0x3F00), SW_OK)

    def test_select_mf_without_data_field(self):
        # ISO permits an absent data field with P1=00, meaning "select the MF".
        # Case 1 (header only) has no Le, so with P2=00 it announces 61XX;
        # Case 2 supplies Le=00 (256) and gets the template directly.
        self.assertEqual(self.card.send_apdu("00A40000").sw1, 0x61)
        self.assertSW(self.card.send_apdu("00A4000000"), SW_OK)
        # With P2=0C the card is not asked for control information at all.
        self.assertSW(self.card.send_apdu("00A4000C"), SW_OK)


class TestSelectErrors(CardTestCase):
    def test_unknown_file(self):
        self.assertSW(self.card.select(0x2F01), SW_FILE_NOT_FOUND)

    def test_select_by_df_name_not_supported(self):
        # P1=04 selects by AID. AIDs belong to the Card Manager (M7), so there
        # is nothing to search -- 6A81 "function not supported", not 6A82
        # "file not found", which would imply we looked.
        self.assertSW(
            self.card.send_apdu("00A40400023F00"), SW_FUNC_NOT_SUPPORTED
        )

    def test_undefined_selection_method(self):
        self.assertSW(self.card.send_apdu("00A47700023F00"), SW_INCORRECT_P1P2)

    def test_fmd_template_not_supported(self):
        # FCP (P2=04) is supported in M2; FMD (P2=08) is issuer data we hold
        # none of.
        self.assertSW(
            self.card.send_apdu("00A40008023F0020"), SW_FUNC_NOT_SUPPORTED
        )

    def test_wrong_lc_for_this_command(self):
        self.assertSW(
            self.card.send_apdu("00A40000033F0001"), SW_LC_INCONSISTENT_P1P2
        )

    def test_failed_select_keeps_the_previous_one(self):
        self.assertSW(self.card.select(0x3F00), SW_OK)
        self.assertSW(self.card.select(0xDEAD), SW_FILE_NOT_FOUND)
        # Still usable, still selected.
        self.assertSW(self.card.select(0x3F00), SW_OK)


class TestProtocolErrors(CardTestCase):
    def test_unknown_instruction(self):
        self.assertSW(self.card.send_apdu("00EE0000"), SW_INS_NOT_SUPPORTED)

    def test_unimplemented_instructions(self):
        # This list shrinks as milestones land, and each graduation is a
        # deliberate edit here rather than a loosened assertion:
        #   B0 / D6  -> M2a  (test_filesystem.py)
        #   E0 / E4  -> M2b  (test_create.py)
        #   C0       -> M2b  (test_get_response.py)
        # Still absent: VERIFY (M3) and GET DATA.
        for ins in ("20", "CA"):
            self.assertSW(
                self.card.send_apdu(f"00{ins}0000"),
                SW_INS_NOT_SUPPORTED,
                f"INS {ins}",
            )

    def test_implemented_instructions_are_not_reported_as_unknown(self):
        """The other half of the test above.

        A dispatcher that answered 6D00 for a command it does in fact have
        would be a registration bug, and the list above cannot detect it --
        it only checks what is absent. These get a real error for the empty
        APDU (6700 or 6986), never 6D00.
        """
        for ins in ("A4", "B0", "D6", "E0", "E4", "C0"):
            sw = self.card.send_apdu(f"00{ins}0000").sw
            self.assertNotEqual(sw, SW_INS_NOT_SUPPORTED, f"INS {ins}")

    def test_class_diagnostics(self):
        cases = {
            "0CA40000": SW_SM_UNSUPPORTED,
            "01A40000": SW_CHANNEL_UNSUPPORTED,
            "10A40000": SW_CHAINING_UNSUPPORTED,
            "80A40000": SW_CLA_NOT_SUPPORTED,
            "FFA40000": SW_CLA_NOT_SUPPORTED,
        }
        for apdu, expected in cases.items():
            self.assertSW(self.card.send_apdu(apdu), expected, apdu)

    def test_truncated_apdu(self):
        self.assertSW(self.card.send_apdu("00A400"), SW_WRONG_LENGTH)

    def test_lc_longer_than_data(self):
        self.assertSW(self.card.send_apdu("00A40000FF3F00"), SW_WRONG_LENGTH)

    def test_extended_apdu_selects_the_mf(self):
        # 00 A4 00 00 | 00 00 02 | 3F 00 -- a Case 3E SELECT of the MF.
        # The same command the card is most often asked, in the extended
        # encoding. Answers 610C: selection succeeded and 12 bytes of FCI are
        # waiting, exactly as the short form does.
        r = self.card.send_apdu("00A40000000002" + "3F00")
        self.assertEqual(r.sw1, 0x61, f"expected 61XX, got {r.sw:04X}")
        # And the FCI is collectable, which proves the extended frame did not
        # merely parse but dispatched into a real handler.
        fci = self.card.send_apdu(f"00C00000{r.sw2:02X}")
        self.assertSW(fci, SW_OK)
        self.assertEqual(len(fci.data), r.sw2)

    def test_extended_five_byte_boundary_is_short_le(self):
        # 00 A4 00 00 00 is FIVE bytes with a zero fifth byte. It is a short
        # Case 2 with Le=256, NOT the start of an extended APDU -- the
        # extended form needs three bytes of length field and there is one.
        # Misreading it would break the project's canonical first APDU.
        #
        # The discriminating outcome is 9000 WITH data: Le is present, so the
        # card returns the FCI in this same exchange and never needs a 61XX.
        # Had the frame been taken for the start of an extended APDU it would
        # have been 6700, and had the fifth byte been read as Lc it would have
        # been 6700 as well -- so success with a non-empty body is the only
        # answer consistent with a correct parse.
        r = self.card.send_apdu("00A4000000")
        self.assertSW(r, SW_OK)
        self.assertGreater(len(r.data), 0, "Le was present; FCI expected")

    def test_extended_six_bytes_is_wrong_length(self):
        # A zero introducer with only two bytes after it. No legal APDU has
        # this shape: 6700, and specifically not 6A81, because extended length
        # IS supported -- telling a reader otherwise would make it abandon the
        # encoding instead of fixing the frame.
        self.assertSW(self.card.send_apdu("00A400000001"), SW_WRONG_LENGTH)

    def test_extended_lc_above_ceiling_is_wrong_length(self):
        # A well-formed extended header announcing 4096 data bytes, which is
        # above the card's documented ceiling. The card must answer rather
        # than hang or drop the frame.
        apdu = "00D60000" + "00" + "1000" + ("AA" * 16)
        self.assertSW(self.card.send_apdu(apdu), SW_WRONG_LENGTH)

    def test_maximum_length_apdu(self):
        # Lc=255 plus Le: 261 bytes, the largest short APDU. Must be handled,
        # not truncated -- this is the buffer-boundary case. UPDATE BINARY
        # returns no data, so an Le present makes it 6700.
        apdu = "00D60000FF" + ("AA" * 255) + "00"
        self.assertEqual(len(bytes.fromhex(apdu)), 261)
        self.assertSW(self.card.send_apdu(apdu), SW_WRONG_LENGTH)

    def test_maximum_length_case3_apdu(self):
        # 260 bytes: Lc=255 with no Le. Reaches UPDATE BINARY, which refuses it
        # on range (the target file is far smaller) -- the point is that the
        # 260-byte APDU parsed and dispatched rather than being truncated.
        apdu = "00D60000FF" + ("AA" * 255)
        self.assertEqual(len(bytes.fromhex(apdu)), 260)
        r = self.card.send_apdu(apdu)
        self.assertIn(r.sw1 & 0xF0, (0x60, 0x90))


class TestCardAlwaysAnswers(CardTestCase):
    """The card must never go silent, whatever it is sent."""

    def test_hostile_inputs_all_get_a_status_word(self):
        hostile = [
            "00",  # 1 byte
            "0000",  # 2
            "000000",  # 3
            "00000000",  # bare header, unknown INS
            "FFFFFFFF",
            "FFFFFFFFFF",
            "00A400000000000000",
            "00A4000001",  # Lc=1, no data
            "00A400007F" + "00" * 10,  # Lc=127, 10 bytes
            "FFFFFFFFFF" + "FF" * 256,
            "00" * 261,
            "A5" * 261,
        ]
        for apdu in hostile:
            with self.subTest(apdu=apdu[:32]):
                r = self.card.send_apdu(apdu)
                # A status word, in a valid ISO class.
                self.assertIn(
                    r.sw1 & 0xF0,
                    (0x60, 0x90),
                    f"SW1={r.sw1:02X} is not a valid ISO status class",
                )

    def test_card_survives_a_flood(self):
        # Interleave good and hostile commands; the card must stay usable.
        for i in range(100):
            self.card.send_apdu(f"00{i % 256:02X}0000")
            self.assertSW(self.card.select(0x3F00), SW_OK, f"after {i} junk")


class TestTransport(CardTestCase):
    """Transport-layer behaviour, which unit tests cannot reach."""

    def test_atr(self):
        atr = self.card.atr()
        # Documented in docs/simulator.md; asserted here so a change to the
        # ATR cannot happen silently.
        self.assertEqual(
            atr, bytes.fromhex("3B94110053434F53"), f"ATR was {hexs(atr)}"
        )
        self.assertEqual(atr[0], 0x3B, "TS must indicate direct convention")
        k = atr[1] & 0x0F
        self.assertEqual(len(atr), 2 + 2 + k, "T0 historical-byte count")
        self.assertEqual(atr[4:], b"SCOS", "historical bytes")

    def test_malformed_hex_is_a_transport_error_not_a_card_response(self):
        # Garbage on the wire must NOT reach the OS and must NOT produce a
        # status word: on real hardware the link layer would reject it.
        # So the card stays silent, and the next real APDU still works.
        self.card._write("not-hex-at-all")
        self.card._write("00A4000C023F00")   # P2=0C: plain 9000, no 61XX
        self.assertEqual(self.card._read(), "9000")

    def test_odd_number_of_hex_digits_rejected(self):
        self.card._write("00A4000")
        self.card._write("00A4000C023F00")
        self.assertEqual(self.card._read(), "9000")

    def test_comments_and_blank_lines_ignored(self):
        self.card._write("# a comment")
        self.card._write("")
        self.card._write("   ")
        self.assertSW(self.card.select(0x3F00), SW_OK)

    def test_warm_reset_returns_atr_and_card_still_works(self):
        self.assertSW(self.card.select(0x3F00), SW_OK)
        atr = self.card.reset()
        self.assertEqual(atr, bytes.fromhex("3B94110053434F53"))
        self.assertSW(self.card.select(0x3F00), SW_OK)

    def test_responses_only_on_stdout(self):
        # Every line the client reads must be pure hex. If the banner or a
        # diagnostic leaked onto stdout, this fails.
        for _ in range(5):
            line = self.card.send_raw("00A4000C023F00")
            int(line, 16)  # raises if not hex
            self.assertEqual(line, "9000")

    def test_unknown_control_line_does_not_answer(self):
        self.card._write(".nonsense")
        self.assertSW(self.card.select(0x3F00), SW_OK)


class TestLifecycle(unittest.TestCase):
    def test_two_cards_are_independent(self):
        with SmartCard() as a, SmartCard() as b:
            self.assertEqual(a.select(0x3F00).sw, SW_OK)
            self.assertEqual(b.select(0x3F00).sw, SW_OK)

    def test_quit_shuts_down_cleanly(self):
        card = SmartCard()
        self.assertEqual(card.select(0x3F00).sw, SW_OK)
        card.close()
        self.assertEqual(
            card.proc.returncode, 0, "simulator must exit 0 on .quit"
        )

    @unittest.skipIf(
        os.environ.get("SCOS_TARGET") == "qemu",
        "EOF is not a hardware concept: a UART has no end-of-stream, so the "
        "ARM target waits for the next byte forever -- which is what a real "
        "card does until power is removed. Native-only by nature, not a gap.",
    )
    def test_link_down_when_stdin_closes(self):
        # Pulling the card out of the reader. The process must exit cleanly,
        # not hang and not crash.
        card = SmartCard()
        card.proc.stdin.close()
        card.proc.wait(timeout=10)
        self.assertEqual(card.proc.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
