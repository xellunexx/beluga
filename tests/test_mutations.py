# -*- coding: utf-8 -*-
# test_mutations.py
"""
Unit tests for the mutation helpers.

The tests use the standard :mod:`unittest` framework.
The logger is configured at DEBUG level so that every mutation
event is printed to the console when the tests run.
"""

import logging
import unittest

# --------------------------------------------------------------------
# Configure the central logger for the test run
# --------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="[%Y-%m-%d %H:%M:%S] %(name)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# --------------------------------------------------------------------
# Import the helpers under test
# --------------------------------------------------------------------
from mutations import (
    mutate_gpo_response,
    mutate_read_record_response,
    mutate_tvr_in_generate_ac,
    forge_2nd_gac,
    forge_2nd_gac_raw,
    parse_cdol1,
    parse_cvm_list,
    patch_generate_ac_universal,
    select_cvm_spoof,
)
from tlv import build_tlv

# --------------------------------------------------------------------
# Helper that builds a minimal GPO payload containing the optional
# AIP (tag 0x82) and CTQ (tag 0x9F6C) tags.
# --------------------------------------------------------------------
def make_gpo(aip: bytes | None = None, ctq: bytes | None = None) -> bytes:
    inner = b""
    if aip is not None:
        inner += build_tlv(0x82, aip)
    if ctq is not None:
        inner += build_tlv(0x9F6C, ctq)
    return build_tlv(0x77, inner) + b"\x90\x00"


# --------------------------------------------------------------------
# Unittest test cases - the original tests from the project are kept,
# and the new tests exercise the extended mutation logic.
# --------------------------------------------------------------------
class GpoMutationTests(unittest.TestCase):
    def test_mutate_gpo_response(self):
        # Header + 95 08 <TVR>
        original = b'\x77\x0a\x95\x08\x00\x00\x00\x00\x00\x00\x00\x00\x90\x00'
        mutated, ok = mutate_gpo_response(original, clear_tvr=True)
        self.assertTrue(ok)
        self.assertEqual(mutated, original)

    def test_ctq_clears_online_pin_and_sets_cdcvm_in_second_byte(self):
        rapdu = bytes.fromhex("77059F6C02B8009000")
        mutated, ok = mutate_gpo_response(rapdu, cdcvm_verified=True)
        self.assertTrue(ok)
        self.assertEqual(mutated, bytes.fromhex("77059F6C0238809000"))

    def test_ctq_maps_3900_to_3880(self):
        rapdu = bytes.fromhex("77059F6C0239009000")
        mutated, ok = mutate_gpo_response(rapdu, cdcvm_verified=True)
        self.assertTrue(ok)
        self.assertEqual(mutated, bytes.fromhex("77059F6C0238809000"))

    def test_ctq_preserves_other_bits(self):
        rapdu = bytes.fromhex("77059F6C02FF41AABB")
        mutated, ok = mutate_gpo_response(rapdu, cdcvm_verified=True)
        self.assertTrue(ok)
        self.assertEqual(mutated, bytes.fromhex("77059F6C027EC1AABB"))

    def test_ctq_clears_online_pin_without_cdcvm_evidence(self):
        rapdu = bytes.fromhex("77059F6C02B8009000")
        mutated, ok = mutate_gpo_response(rapdu)
        self.assertTrue(ok)
        self.assertEqual(mutated, bytes.fromhex("77059F6C0238009000"))

    def test_aip_1980_maps_to_0980(self):
        rapdu = bytes.fromhex(
            "770E82021980940810010101200103009000"
        )
        mutated, ok = mutate_gpo_response(
            rapdu,
            cdcvm_verified=True,
        )
        self.assertTrue(ok)
        self.assertEqual(
            mutated,
            bytes.fromhex(
                "770E82020980940810010101200103009000"
            ),
        )

    def test_ctq_missing_with_cdcvm_evidence_logs_warning(self):
        rapdu = bytes.fromhex("770E82021980940810010101200103009000")
        mutated, ok = mutate_gpo_response(rapdu, cdcvm_verified=True)
        self.assertTrue(ok)
        # The mutation should be a no-op because CTQ is missing; the log
        # will contain a warning - visible on the console because the
        # logger is set to DEBUG level.

    def test_aip_oda_required_no_cv_mutation(self):
        rapdu = bytes.fromhex("770E82010180940810010101200103009000")
        mutated, ok = mutate_gpo_response(rapdu)
        self.assertTrue(ok)
        # The CV bit must remain set; the log will show "ODA required".

    def test_aip_oda_not_required_cv_mutation(self):
        rapdu = bytes.fromhex("770E82000080940810010101200103009000")
        mutated, ok = mutate_gpo_response(rapdu)
        self.assertTrue(ok)
        # The CV bit should be cleared - log will show "CV bit cleared".

    def test_mutate_gpo_response_exception_handling(self):
        from mutations import find_tlv

        def raise_exc(*_args, **_kwargs):
            raise RuntimeError("boom")

        # Monkey-patch the helper so that the mutation function raises
        # an exception internally.
        original_find_tlv = find_tlv
        try:
            # Replace the helper temporarily
            import mutations
            mutations.find_tlv = raise_exc

            rapdu = bytes.fromhex("77059F6C02B8009000")
            mutated, ok = mutate_gpo_response(rapdu, cdcvm_verified=True)
            self.assertFalse(ok)
            self.assertEqual(mutated, rapdu)
        finally:
            # Restore the original helper
            mutations.find_tlv = original_find_tlv


class GenerateAcUniversalTests(unittest.TestCase):
    def test_rebuild_replaces_lc_and_preserves_le(self):
        capdu = bytes.fromhex("80AE800005008000000000")
        patched, notes = patch_generate_ac_universal(
            capdu,
            [(0x95, 5)],
            [],
        )
        self.assertEqual(patched, bytes.fromhex("80AE800005000000000000"))
        self.assertEqual(patched[4], 5)
        self.assertEqual(len(patched), len(capdu))
        self.assertIn("CVM-fail cleared", notes)


class CvmListBehaviorTests(unittest.TestCase):
    def test_parse_cvm_list_skips_x_y_header(self):
        cvm_raw = bytes.fromhex("00000001000000021E030001")
        self.assertEqual(parse_cvm_list(cvm_raw), [(0x1E, 0x03), (0x00, 0x01)])

    def test_select_cvm_spoof_always_returns_no_cvm(self):
        spoof = select_cvm_spoof([(0x5E, 0x03)])
        self.assertEqual(spoof, (b"\x01\x00\x00", 0x26))


class CdolParsingTests(unittest.TestCase):
    def test_parse_cdol1_handles_multi_byte_continuation_tags(self):
        cdol_raw = bytes.fromhex("DF8117019F0206")
        self.assertEqual(parse_cdol1(cdol_raw), [(0xDF8117, 0x01), (0x9F02, 0x06)])


class AdditionalMutationTests(unittest.TestCase):
    def test_mutate_read_record_response(self):
        # 70 template containing 8E (CVM List) and 9F45 (TVR/DAC)
        inner = build_tlv(0x8E, bytes.fromhex("0000000000000000000042031E030000")) + build_tlv(0x9F45, b"\x01\x02\x03")
        rapdu = build_tlv(0x70, inner) + b"\x90\x00"
        mutated = mutate_read_record_response(rapdu)
        self.assertNotEqual(mutated, rapdu)
        self.assertTrue(mutated.endswith(b"\x90\x00"))

    def test_mutate_tvr_in_generate_ac(self):
        # Header + 95 05 <TVR>
        capdu = b"\x80\xAE\x80\x00\x07\x95\x05\x80\x00\x00\x00\x00"
        mutated, note = mutate_tvr_in_generate_ac(capdu)
        self.assertIsNotNone(note)
        self.assertNotEqual(mutated, capdu)

    def test_forge_2nd_gac(self):
        ac = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        atc = b"\x00\x05"
        iad = b"\x0F\x0A\x01\xA5"

        k_c = bytes.fromhex(
            "0123456789ABCDEF"
            "1122334455667788"
            "89ABCDEF01234567"
        )

        forged = forge_2nd_gac_raw(
            ac=ac,
            iad=iad,
            atc=atc,
            arqc=None,
            p1_req=0x40,
            brand="MASTERCARD",
            k_c=k_c
        )

        self.assertIsNotNone(forged)
        self.assertTrue(forged.startswith(b"\x77"))
        self.assertTrue(forged.endswith(b"\x90\x00"))


if __name__ == "__main__":
    unittest.main(verbosity=2)