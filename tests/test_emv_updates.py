# -*- coding: utf-8 -*-
import unittest

from emv import extract_arqc_from_rapdu, parse_dol
from mutations import parse_cdol1, parse_cvm_list
from tlv import build_tlv


class EmvUpdatesTests(unittest.TestCase):
    def test_extract_arqc_from_template_80_with_0x81_length(self):
        payload = bytes.fromhex("4012341122334455667788A1B2C3D4")
        rapdu = b"\x80\x81\x0F" + payload + b"\x90\x00"
        cache = extract_arqc_from_rapdu(rapdu, gpo_template=0x80)
        self.assertEqual(cache.template, 0x80)
        self.assertEqual(cache.cid, 0x40)
        self.assertEqual(cache.atc, bytes.fromhex("1234"))
        self.assertEqual(cache.ac, bytes.fromhex("1122334455667788"))
        self.assertEqual(cache.iad, bytes.fromhex("A1B2C3D4"))

    def test_parse_cvm_list_skips_amount_x_y_header(self):
        cvm_raw = bytes.fromhex("00000001000000021E035E03")
        self.assertEqual(parse_cvm_list(cvm_raw), [(0x1E, 0x03), (0x5E, 0x03)])

    def test_parse_dol_handles_multi_byte_continuation_tags(self):
        dol_raw = bytes.fromhex("DF8117019F0206")
        self.assertEqual(parse_dol(dol_raw), [(0xDF8117, 0x01), (0x9F02, 0x06)])

    def test_parse_cdol1_handles_multi_byte_continuation_tags(self):
        cdol_raw = bytes.fromhex("DF8117019F0206")
        self.assertEqual(parse_cdol1(cdol_raw), [(0xDF8117, 0x01), (0x9F02, 0x06)])

    def test_build_tlv_supports_three_byte_tag(self):
        self.assertEqual(build_tlv(0xDF8117, b"\xAA"), bytes.fromhex("DF811701AA"))


if __name__ == "__main__":
    unittest.main()
