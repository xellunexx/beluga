# -*- coding: utf-8 -*-
import unittest

from constants import CID_ARQC
from guard import (
    Guard, Phase, SessionState, SW_9000,
    INS_GENERATE_AC, INS_SELECT,
)


class GuardAdvanceTests(unittest.TestCase):
    def test_repeated_read_record_phase_is_sticky(self):
        guard = Guard()
        guard.record_sw(SW_9000)

        for phase in (
            Phase.PPSE_SELECTED,
            Phase.AID_SELECTED,
            Phase.GPO_RESPONDED,
            Phase.READ_RECORD_DONE,
        ):
            allowed, _ = guard.advance(phase)
            self.assertTrue(allowed)

        allowed, reason = guard.advance(Phase.READ_RECORD_DONE)

        self.assertTrue(allowed)
        self.assertEqual(guard.phase, Phase.READ_RECORD_DONE)
        self.assertEqual(reason, "Phase READ_RECORD_DONE already active (sticky)")

    def test_sticky_read_record_allows_re_advance_regardless_of_sw(self):
        guard = Guard()
        guard.phase = Phase.READ_RECORD_DONE
        guard.record_sw(b"\x6a\x83")

        allowed, reason = guard.advance(Phase.READ_RECORD_DONE)

        self.assertTrue(allowed)
        self.assertEqual(reason, "Phase READ_RECORD_DONE already active (sticky)")

    def test_other_phases_are_not_implicitly_sticky(self):
        guard = Guard()
        guard.phase = Phase.ARQC_RECEIVED
        guard.record_sw(SW_9000)

        allowed, _ = guard.advance(Phase.ARQC_RECEIVED)

        self.assertFalse(allowed)

    def test_forge_is_valid_after_external_authentication(self):
        guard = Guard()
        guard.phase = Phase.EXTERNAL_AUTH_DONE
        session = SessionState(arpc_forge_enabled=True, second_ae_pending=True)
        session.arqc_cache.cid = CID_ARQC
        session.arqc_cache.atc = b"\x00\x01"
        session.arqc_cache.ac = b"12345678"
        session.arqc_cache.iad = b"iad"

        allowed, _ = guard.check_forge(session)

        self.assertTrue(allowed)

    def test_undefined_mutation_and_intercept_fail_closed(self):
        guard = Guard()
        session = SessionState(arpc_rewrite_enabled=True)

        self.assertFalse(guard.check_mutation(INS_SELECT, session)[0])
        self.assertFalse(guard.check_intercept(0xCA, session)[0])

    def test_generate_ac_rewrite_requires_online_phase(self):
        guard = Guard()
        session = SessionState(arpc_rewrite_enabled=True)

        self.assertFalse(guard.check_intercept(INS_GENERATE_AC, session)[0])
        guard.phase = Phase.ARQC_RECEIVED
        self.assertTrue(guard.check_intercept(INS_GENERATE_AC, session)[0])

    def test_first_gac_passthrough_is_runtime_guarded(self):
        guard = Guard()
        guard.phase = Phase.READ_RECORD_DONE
        guard.record_sw(SW_9000)

        pass_through = guard.should_pass_through_first_gac()
        allowed, reason = guard.check_mutation(INS_GENERATE_AC, SessionState())

        self.assertTrue(pass_through)
        self.assertTrue(allowed)
        self.assertIn("First GAC mutation allowed", reason)

    def test_valid_arqc_phase_advances_to_arqc_received(self):
        guard = Guard()
        guard.phase = Phase.FIRST_GAC_SENT
        guard.record_sw(SW_9000)

        allowed, reason = guard.advance(Phase.ARQC_RECEIVED)

        self.assertTrue(allowed)
        self.assertEqual(guard.phase, Phase.ARQC_RECEIVED)
        self.assertIn("Phase advanced to ARQC_RECEIVED", reason)

    def test_partial_arqc_does_not_arm_second_gac_forge(self):
        guard = Guard()
        guard.phase = Phase.ARQC_RECEIVED
        session = SessionState(arpc_forge_enabled=True, second_ae_pending=True)
        session.arqc_cache.atc = b"\x00\x01"
        session.arqc_cache.ac = None
        session.arqc_cache.iad = None

        allowed, reason = guard.check_forge(session)

        self.assertFalse(allowed)
        self.assertIn("ARQC cache incomplete", reason)

    def test_guard_with_mock_session_and_config(self):
        config = {
            "aids": {
                "A0000000041010": {"brand": "MASTERCARD", "mutate_gpo": True}
            }
        }
        guard = Guard(config=config)
        self.assertEqual(guard.config["aids"]["A0000000041010"]["brand"], "MASTERCARD")

        class MockSessionState:
            def __init__(self):
                self.phase = Phase.IDLE
                self.cached_arqc = b"\x11\x22\x33\x44\x55\x66\x77\x88"
                self.cached_atc = b"\x00\x01"
                self.cached_iad = b"\x01\x02"
                self.brand = "MASTERCARD"
                self.arpc_forge_enabled = True
                self.second_ae_pending = True
                self.arqc_cache = type("MockCache", (), {
                    "is_complete": lambda s: True,
                    "atc": b"\x00\x01",
                    "ac": b"\x11\x22\x33\x44\x55\x66\x77\x88",
                    "iad": b"\x01\x02"
                })()

        mock_session = MockSessionState()
        guard.phase = Phase.ARQC_RECEIVED
        allowed, reason = guard.check_forge(mock_session)
        self.assertTrue(allowed)


if __name__ == "__main__":
    unittest.main()
