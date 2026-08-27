# SPDX-License-Identifier: MIT
"""Per-file access conditions (FCP tag 86), over the card interface.

This is the milestone item that closes the holes the source has been
documenting in as many words: until now any reader that could reach the card
could read, write, delete and deactivate any file.

The format in tag 86 is OURS. ISO/IEC 7816-4 defines 86 as "proprietary", so a
card-specific format is exactly what that tag is for -- and it is used in
preference to 8C, the ISO compact format, because 8C's access-mode byte assigns
bits to operations and this project does not have the specification text to
state those positions. A card that misread which bit protected which operation
would create files whose protection is not the protection requested. 8C is
refused with 6A81.

  86 03 <read> <update> <admin>

    0x00   ALWAYS
    0x1N   PIN reference N must be verified in this session
    0xFF   NEVER
"""

import unittest

from scos.card import SmartCard

FDB_EF = 0x01
FDB_DF = 0x38

SW_OK = 0x9000
SW_SECURITY_NOT_SATISFIED = 0x6982
SW_FILE_NOT_FOUND = 0x6A82
SW_WRONG_DATA = 0x6A80
SW_EOF = 0x6282

AC_ALWAYS = 0x00
AC_NEVER = 0xFF
AC_PIN1 = 0x11


def tlv(tag, value: bytes) -> bytes:
    assert len(value) < 0x80
    return bytes([tag, len(value)]) + value


def fcp(*objs: bytes) -> bytes:
    return tlv(0x62, b"".join(objs))


def ef(fid: int, size: int, read=AC_ALWAYS, update=AC_ALWAYS,
       admin=AC_ALWAYS) -> bytes:
    return fcp(
        tlv(0x82, bytes([FDB_EF])),
        tlv(0x83, fid.to_bytes(2, "big")),
        tlv(0x80, size.to_bytes(2, "big")),
        tlv(0x86, bytes([read, update, admin])),
    )


def apdu(cla, ins, p1, p2, data=b"") -> bytes:
    return bytes([cla, ins, p1, p2, len(data)]) + data


class AccessConditionTests(unittest.TestCase):

    # --- helpers ---------------------------------------------------------

    def mf(self, card):
        self.assertEqual(card.send_apdu("00A4000C023F00").sw, SW_OK)

    def create(self, card, template):
        return card.send_apdu(apdu(0x00, 0xE0, 0x00, 0x00, template))

    def select_ef(self, card, fid):
        return card.send_apdu(apdu(0x00, 0xA4, 0x02, 0x0C,
                                   fid.to_bytes(2, "big")))

    def read(self, card, n=4):
        return card.send_apdu(bytes([0x00, 0xB0, 0x00, 0x00, n]))

    def write(self, card, data=b"\xAA\xBB"):
        return card.send_apdu(apdu(0x00, 0xD6, 0x00, 0x00, data))

    def set_pin(self, card, value="1234", ref=1):
        body = value.encode("ascii")
        return card.send_apdu(bytes([0x00, 0x24, 0x01, ref, len(body)]) + body)

    def verify(self, card, value="1234", ref=1):
        body = value.encode("ascii")
        return card.send_apdu(bytes([0x00, 0x20, 0x00, ref, len(body)]) + body)

    # --- the point of the whole feature ----------------------------------

    def test_a_pin_protected_file_is_unreadable_until_verified(self):
        with SmartCard() as card:
            self.mf(card)
            self.assertEqual(self.set_pin(card).sw, SW_OK)
            self.assertEqual(self.create(card, ef(0x2A01, 16, read=AC_PIN1)).sw,
                             SW_OK)
            self.assertEqual(self.select_ef(card, 0x2A01).sw, SW_OK)

            # Selected but not authenticated: 6982.
            self.assertEqual(self.read(card).sw, SW_SECURITY_NOT_SATISFIED)

            self.assertEqual(self.verify(card).sw, SW_OK)
            # Now readable. 6282 is fine: the file is longer than the read.
            self.assertIn(self.read(card).sw, (SW_OK, SW_EOF))

    def test_read_and_update_are_independent(self):
        """A file readable by anyone and writable only with the PIN is the
        common real configuration, so the two conditions must not be one."""
        with SmartCard() as card:
            self.mf(card)
            self.assertEqual(self.set_pin(card).sw, SW_OK)
            self.assertEqual(
                self.create(card, ef(0x2A02, 16, read=AC_ALWAYS,
                                     update=AC_PIN1)).sw, SW_OK)
            self.assertEqual(self.select_ef(card, 0x2A02).sw, SW_OK)

            self.assertIn(self.read(card).sw, (SW_OK, SW_EOF))
            self.assertEqual(self.write(card).sw, SW_SECURITY_NOT_SATISFIED)

            self.assertEqual(self.verify(card).sw, SW_OK)
            self.assertEqual(self.write(card).sw, SW_OK)

    def test_never_means_never(self):
        """0xFF has no path through the command interface at all -- not even
        with the PIN. This is what an issuer uses for a file the card writes
        and nobody reads."""
        with SmartCard() as card:
            self.mf(card)
            self.assertEqual(self.set_pin(card).sw, SW_OK)
            self.assertEqual(self.verify(card).sw, SW_OK)
            self.assertEqual(self.create(card, ef(0x2A03, 16,
                                                  read=AC_NEVER)).sw, SW_OK)
            self.assertEqual(self.select_ef(card, 0x2A03).sw, SW_OK)
            # Authenticated, and still refused.
            self.assertEqual(self.read(card).sw, SW_SECURITY_NOT_SATISFIED)

    def test_the_condition_does_not_survive_a_power_cycle_as_authentication(self):
        """The CONDITION is in NVM; the AUTHENTICATION is not. A new session
        must be refused again."""
        import tempfile
        with tempfile.TemporaryDirectory() as state:
            with SmartCard(state_dir=state) as card:
                self.mf(card)
                self.assertEqual(self.set_pin(card).sw, SW_OK)
                self.assertEqual(
                    self.create(card, ef(0x2A04, 16, read=AC_PIN1)).sw, SW_OK)
                self.assertEqual(self.verify(card).sw, SW_OK)
                self.assertEqual(self.select_ef(card, 0x2A04).sw, SW_OK)
                self.assertIn(self.read(card).sw, (SW_OK, SW_EOF))

            with SmartCard(state_dir=state) as card:
                self.mf(card)
                self.assertEqual(self.select_ef(card, 0x2A04).sw, SW_OK)
                self.assertEqual(self.read(card).sw,
                                 SW_SECURITY_NOT_SATISFIED,
                                 "authentication survived a power cycle")
                self.assertEqual(self.verify(card).sw, SW_OK)
                self.assertIn(self.read(card).sw, (SW_OK, SW_EOF))

    def test_a_failed_pin_revokes_access_already_granted(self):
        with SmartCard() as card:
            self.mf(card)
            self.assertEqual(self.set_pin(card).sw, SW_OK)
            self.assertEqual(self.create(card, ef(0x2A05, 16,
                                                  read=AC_PIN1)).sw, SW_OK)
            self.assertEqual(self.verify(card).sw, SW_OK)
            self.assertEqual(self.select_ef(card, 0x2A05).sw, SW_OK)
            self.assertIn(self.read(card).sw, (SW_OK, SW_EOF))

            # One wrong attempt, and the door closes again.
            self.assertEqual(self.verify(card, "9999").sw & 0xFFF0, 0x63C0)
            self.assertEqual(self.read(card).sw, SW_SECURITY_NOT_SATISFIED)

    # --- administrative operations ---------------------------------------

    def test_delete_is_gated_on_the_files_own_admin_condition(self):
        """And not on its parent's: otherwise one condition on a DF would
        govern the destruction of everything inside it, so a file could be
        protected against reading and unprotected against deletion."""
        with SmartCard() as card:
            self.mf(card)
            self.assertEqual(self.set_pin(card).sw, SW_OK)
            self.assertEqual(self.create(card, ef(0x2A06, 16,
                                                  admin=AC_PIN1)).sw, SW_OK)

            delete = apdu(0x00, 0xE4, 0x00, 0x00, (0x2A06).to_bytes(2, "big"))
            self.assertEqual(card.send_apdu(delete).sw,
                             SW_SECURITY_NOT_SATISFIED)
            # Still there.
            self.assertEqual(self.select_ef(card, 0x2A06).sw, SW_OK)

            self.mf(card)
            self.assertEqual(self.verify(card).sw, SW_OK)
            self.assertEqual(card.send_apdu(delete).sw, SW_OK)
            self.assertEqual(self.select_ef(card, 0x2A06).sw, SW_FILE_NOT_FOUND)

    def test_deactivate_is_gated_on_admin(self):
        with SmartCard() as card:
            self.mf(card)
            self.assertEqual(self.set_pin(card).sw, SW_OK)
            self.assertEqual(self.create(card, ef(0x2A07, 16,
                                                  admin=AC_PIN1)).sw, SW_OK)
            self.assertEqual(self.select_ef(card, 0x2A07).sw, SW_OK)

            self.assertEqual(card.send_apdu("00040000").sw,
                             SW_SECURITY_NOT_SATISFIED)
            self.assertEqual(self.verify(card).sw, SW_OK)
            self.assertEqual(card.send_apdu("00040000").sw, SW_OK)
            self.assertEqual(card.send_apdu("00440000").sw, SW_OK)

    def test_a_nonexistent_file_says_not_found_not_unauthorised(self):
        """6A82, not 6982. Refusing on authorisation grounds would confirm the
        file exists, which is exactly what an attacker enumerating identifiers
        wants to learn."""
        with SmartCard() as card:
            self.mf(card)
            delete = apdu(0x00, 0xE4, 0x00, 0x00, (0x2FFE).to_bytes(2, "big"))
            self.assertEqual(card.send_apdu(delete).sw, SW_FILE_NOT_FOUND)

    # --- the template itself ---------------------------------------------

    def test_an_uninterpretable_condition_is_refused_at_create(self):
        """A stored condition the card could not evaluate would have to be
        treated as NEVER -- the only safe reading -- leaving the file
        permanently unreachable for a reason nothing could explain. Refusing
        up front turns that into a 6A80 with the template in hand."""
        with SmartCard() as card:
            self.mf(card)
            bad = fcp(
                tlv(0x82, bytes([FDB_EF])),
                tlv(0x83, (0x2A08).to_bytes(2, "big")),
                tlv(0x80, (16).to_bytes(2, "big")),
                tlv(0x86, bytes([0x00, 0x00, 0x77])),  # 0x77 means nothing
            )
            self.assertEqual(self.create(card, bad).sw, SW_WRONG_DATA)
            self.assertEqual(self.select_ef(card, 0x2A08).sw, SW_FILE_NOT_FOUND)

    def test_the_security_attribute_must_be_exactly_three_bytes(self):
        """Two bytes would leave ac_admin at its permissive default while
        looking configured -- the near-miss that produces an unprotected file
        and a satisfied caller."""
        with SmartCard() as card:
            self.mf(card)
            short = fcp(
                tlv(0x82, bytes([FDB_EF])),
                tlv(0x83, (0x2A09).to_bytes(2, "big")),
                tlv(0x80, (16).to_bytes(2, "big")),
                tlv(0x86, bytes([AC_PIN1, AC_PIN1])),
            )
            self.assertEqual(self.create(card, short).sw, SW_WRONG_DATA)

    def test_conditions_survive_a_power_cycle(self):
        import tempfile
        with tempfile.TemporaryDirectory() as state:
            with SmartCard(state_dir=state) as card:
                self.mf(card)
                self.assertEqual(self.set_pin(card).sw, SW_OK)
                self.assertEqual(
                    self.create(card, ef(0x2A0A, 16, read=AC_NEVER)).sw, SW_OK)
            with SmartCard(state_dir=state) as card:
                self.mf(card)
                self.assertEqual(self.select_ef(card, 0x2A0A).sw, SW_OK)
                self.assertEqual(self.read(card).sw,
                                 SW_SECURITY_NOT_SATISFIED,
                                 "the access condition was lost in NVM")


if __name__ == "__main__":
    unittest.main()
