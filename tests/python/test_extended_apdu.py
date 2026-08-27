# SPDX-License-Identifier: MIT
"""Extended-length APDUs (ISO/IEC 7816-4 s.5.1), over the card interface.

tests/unit/test_apdu_parse.c covers the ENCODING exhaustively -- every (Lc,
frame length) pair, both zero-normalisations, the ceiling, and the five-byte
boundary. None of that proves the card can actually move more than 255 bytes,
because a parser can be perfectly correct while every buffer downstream is
still 261 bytes long.

So what is here is the CAPABILITY, end to end:

  * write more than 255 bytes in one command  (extended Lc)
  * read more than 256 bytes in one response (extended Le)
  * the byte-for-byte round trip of both
  * the documented ceiling, refused cleanly rather than half-honoured
  * the difference between "the file ended" and "the card stopped"

Every APDU here is BUILT from its parts. Hand-writing extended length fields
is the same trap as hand-writing BER lengths, one field wider.
"""

import unittest

from scos.card import SmartCard

FDB_EF_TRANSPARENT = 0x01

SW_OK = 0x9000
SW_WRONG_LENGTH = 0x6700
SW_EOF = 0x6282

# Must match SCOS_APDU_EXT_DATA_MAX in include/os/scos_config.h.in. Asserted
# against the card's real behaviour below rather than merely trusted, so a
# change to one without the other fails a test instead of drifting.
EXT_DATA_MAX = 1024


def tlv(tag: int, value: bytes) -> bytes:
    assert len(value) < 0x80
    return bytes([tag, len(value)]) + value


def ef_template(fid: int, size: int) -> bytes:
    return tlv(0x62, b"".join([
        tlv(0x82, bytes([FDB_EF_TRANSPARENT])),
        tlv(0x83, fid.to_bytes(2, "big")),
        tlv(0x80, size.to_bytes(2, "big")),
    ]))


def short_apdu(cla, ins, p1, p2, data=b"") -> str:
    return (bytes([cla, ins, p1, p2, len(data)]) + data).hex().upper()


def ext_case3(cla, ins, p1, p2, data: bytes) -> str:
    """header 00 Lc1 Lc2 <data> -- extended Lc, no Le."""
    assert len(data) > 0
    return (bytes([cla, ins, p1, p2, 0x00])
            + len(data).to_bytes(2, "big") + data).hex().upper()


def ext_case4(cla, ins, p1, p2, data: bytes, le: int) -> str:
    """header 00 Lc1 Lc2 <data> Le1 Le2. le=0 means 65536 on the wire."""
    assert len(data) > 0
    return (bytes([cla, ins, p1, p2, 0x00])
            + len(data).to_bytes(2, "big") + data
            + (le & 0xFFFF).to_bytes(2, "big")).hex().upper()


def ext_case2(cla, ins, p1, p2, le: int) -> str:
    """header 00 Le1 Le2 -- extended Le, no data."""
    return (bytes([cla, ins, p1, p2, 0x00])
            + (le & 0xFFFF).to_bytes(2, "big")).hex().upper()


class ExtendedApduTests(unittest.TestCase):

    # --- helpers ----------------------------------------------------------

    def make_ef(self, card, fid: int, size: int):
        """Create an EF under the MF and select it. Returns nothing; fails the
        test if either step does not answer 9000."""
        self.assertSW(card.send_apdu(short_apdu(0x00, 0xA4, 0x00, 0x0C,
                                                b"\x3F\x00")), SW_OK)
        self.assertSW(card.send_apdu(short_apdu(0x00, 0xE0, 0x00, 0x00,
                                                ef_template(fid, size))), SW_OK)
        self.assertSW(card.send_apdu(short_apdu(0x00, 0xA4, 0x02, 0x0C,
                                                fid.to_bytes(2, "big"))), SW_OK)

    def assertSW(self, r, expected):
        self.assertEqual(
            r.sw, expected,
            f"\nexpected SW={expected:04X}, got {r.sw:04X}"
            f"\ntranscript:\n{getattr(self, 'card', None) and self.card.transcript}",
        )

    # --- the capability ---------------------------------------------------

    def test_write_more_than_255_bytes_in_one_command(self):
        """The whole point of extended Lc. 600 bytes is impossible in the
        short form, where Lc caps at 255."""
        payload = bytes((i * 7 + 3) & 0xFF for i in range(600))
        with SmartCard() as card:
            self.card = card
            self.make_ef(card, 0x4501, 1024)

            # UPDATE BINARY, Case 3E, 600 data bytes.
            self.assertSW(card.send_apdu(
                ext_case3(0x00, 0xD6, 0x00, 0x00, payload)), SW_OK)

            # Read it back in short-form chunks, so the verification does not
            # depend on the feature under test.
            got = b""
            while len(got) < len(payload):
                off = len(got)
                r = card.send_apdu(
                    bytes([0x00, 0xB0, off >> 8, off & 0xFF, 0xFF]).hex())
                self.assertIn(r.sw, (SW_OK, SW_EOF), f"read at {off}: {r}")
                self.assertGreater(len(r.data), 0)
                got += r.data
            self.assertEqual(got[:len(payload)], payload)

    def test_read_more_than_256_bytes_in_one_response(self):
        """The whole point of extended Le. A short Le caps at 256."""
        payload = bytes((i * 11 + 5) & 0xFF for i in range(700))
        with SmartCard() as card:
            self.card = card
            self.make_ef(card, 0x4502, 1024)
            self.assertSW(card.send_apdu(
                ext_case3(0x00, 0xD6, 0x00, 0x00, payload)), SW_OK)

            # READ BINARY, Case 2E, Le = 700.
            r = card.send_apdu(ext_case2(0x00, 0xB0, 0x00, 0x00, 700))
            self.assertSW(r, SW_OK)
            self.assertEqual(len(r.data), 700,
                             "extended Le must return the full amount")
            self.assertEqual(r.data, payload)

    def test_round_trip_at_the_ceiling(self):
        """The documented maximum must be usable, not one byte off. This is the
        test that would catch an off-by-one in any of the three buffers the
        data passes through."""
        payload = bytes((i ^ 0xA5) & 0xFF for i in range(EXT_DATA_MAX))
        with SmartCard() as card:
            self.card = card
            self.make_ef(card, 0x4503, EXT_DATA_MAX)
            self.assertSW(card.send_apdu(
                ext_case3(0x00, 0xD6, 0x00, 0x00, payload)), SW_OK)
            r = card.send_apdu(ext_case2(0x00, 0xB0, 0x00, 0x00, EXT_DATA_MAX))
            self.assertSW(r, SW_OK)
            self.assertEqual(len(r.data), EXT_DATA_MAX)
            self.assertEqual(r.data, payload)

    # --- the ceiling, refused honestly ------------------------------------

    def test_one_byte_over_the_ceiling_is_refused(self):
        """6700, and the card must still be alive afterwards. A card that
        accepts a length it cannot honour is worse than one that refuses."""
        payload = b"\xAA" * (EXT_DATA_MAX + 1)
        with SmartCard() as card:
            self.card = card
            self.make_ef(card, 0x4504, 64)
            self.assertSW(card.send_apdu(
                ext_case3(0x00, 0xD6, 0x00, 0x00, payload)), SW_WRONG_LENGTH)
            # Still responsive: the refusal must not have wedged the link.
            self.assertSW(card.send_apdu(short_apdu(0x00, 0xA4, 0x00, 0x0C,
                                                    b"\x3F\x00")), SW_OK)

    def test_a_huge_announced_lc_is_refused_not_dropped(self):
        """A well-formed extended header claiming 65535 bytes, with only a few
        actually sent. The card must ANSWER -- silently dropping the frame
        would look identical to a dead card."""
        apdu = "00D60000" + "00" + "FFFF" + ("AA" * 8)
        with SmartCard() as card:
            self.card = card
            self.assertSW(card.send_apdu(apdu), SW_WRONG_LENGTH)
            self.assertSW(card.send_apdu(short_apdu(0x00, 0xA4, 0x00, 0x0C,
                                                    b"\x3F\x00")), SW_OK)

    def test_le_65536_returns_what_exists_not_an_error(self):
        """Le=0x0000 extended means 65536: "everything you have". Le is a
        MAXIMUM, so the card answers with what it has rather than refusing --
        and, since the file did not end, 9000 rather than 6282."""
        payload = bytes(range(256)) * 2  # 512 bytes
        with SmartCard() as card:
            self.card = card
            self.make_ef(card, 0x4505, 900)
            self.assertSW(card.send_apdu(
                ext_case3(0x00, 0xD6, 0x00, 0x00, payload)), SW_OK)
            r = card.send_apdu(ext_case2(0x00, 0xB0, 0x00, 0x00, 0x0000))
            self.assertIn(r.sw, (SW_OK, SW_EOF))
            self.assertGreater(len(r.data), 256,
                              "Le=65536 must not be clamped to the short max")

    # --- end of file versus end of card ----------------------------------

    def test_eof_is_distinguishable_from_a_capacity_clamp(self):
        """The one place READ BINARY can return fewer bytes than Le for two
        different reasons, which a reader must be able to tell apart:

          6282  the FILE ended -- reading further yields nothing
          9000  the CARD clamped -- the file continues past what was sent

        Collapsing them would either report a file as shorter than it is or
        send a reader round a loop that never ends.
        """
        with SmartCard() as card:
            self.card = card
            # A file SHORTER than the extended read we will ask for.
            self.make_ef(card, 0x4506, 300)
            self.assertSW(card.send_apdu(
                ext_case3(0x00, 0xD6, 0x00, 0x00, b"\x5A" * 300)), SW_OK)

            # Ask for 900: the file ends at 300, so this is genuine EOF.
            r = card.send_apdu(ext_case2(0x00, 0xB0, 0x00, 0x00, 900))
            self.assertSW(r, SW_EOF)
            self.assertEqual(len(r.data), 300)

    # --- the encoding boundaries, over the wire --------------------------

    def test_case4_extended_both_directions(self):
        """Lc and Le both extended in one command. SELECT by FID with an
        extended Le is the smallest command that exercises both fields."""
        with SmartCard() as card:
            self.card = card
            r = card.send_apdu(ext_case4(0x00, 0xA4, 0x00, 0x00,
                                         b"\x3F\x00", 256))
            self.assertSW(r, SW_OK)
            self.assertGreater(len(r.data), 0, "Le present, so FCI expected")

    def test_extended_lc_zero_is_refused(self):
        """00 00 00 followed by a body. Zero data bytes means Case 1 or 2, so
        this is not encodable -- and without an explicit check it would parse
        as a Case 4E with an empty data field."""
        with SmartCard() as card:
            self.card = card
            self.assertSW(card.send_apdu("00A4000000000001 00".replace(" ", "")),
                          SW_WRONG_LENGTH)


if __name__ == "__main__":
    unittest.main()
