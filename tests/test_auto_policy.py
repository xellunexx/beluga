# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rel8hf import ProductionCardRouter, RelayServer


class ProductionCardRouterAutoPolicyTests(unittest.TestCase):
    def setUp(self):
        self.router = ProductionCardRouter()

    def test_unknown_bin_defaults_to_online(self):
        decision = self.router.decide(
            pan_bin="999999",
            amount_cents=500,
            floor_limit_cents=1000,
            ctq=b"\x00\x00",
        )
        self.assertEqual(decision["mode"], "ONLINE")
        self.assertEqual(decision["reason"], "bin_not_whitelisted")

    def test_whitelisted_bin_below_floor_is_offline_nocvm(self):
        decision = self.router.decide(
            pan_bin="400000",
            amount_cents=500,
            floor_limit_cents=1000,
            ctq=b"\x00\x00",
        )
        self.assertEqual(decision["mode"], "OFFLINE_NOCVM")
        self.assertEqual(decision["reason"], "offline_nocvm_ok")

    def test_ctq_forces_online_pin_for_whitelisted_bin(self):
        decision = self.router.decide(
            pan_bin="400000",
            amount_cents=500,
            floor_limit_cents=1000,
            ctq=b"\x80\x00",
        )
        self.assertEqual(decision["mode"], "ONLINE")
        self.assertEqual(decision["reason"], "ctq_forces_online_pin")

    def test_amount_over_limit_forces_online(self):
        decision = self.router.decide(
            pan_bin="400000",
            amount_cents=6000,
            floor_limit_cents=2000,
            ctq=b"\x00\x00",
        )
        self.assertEqual(decision["mode"], "ONLINE")
        self.assertEqual(decision["reason"], "amount_over_limit")

    def test_no_offline_support_routes_online(self):
        decision = self.router.decide(
            pan_bin="340000",
            amount_cents=500,
            floor_limit_cents=10000,
            ctq=b"\x00\x00",
        )
        self.assertEqual(decision["mode"], "ONLINE")
        self.assertEqual(decision["reason"], "no_offline_support")

    def test_cdcvm_verified_skips_ctq_online_pin(self):
        decision = self.router.decide(
            pan_bin="400000",
            amount_cents=500,
            floor_limit_cents=1000,
            ctq=b"\x80\x00",
            cdcvm_verified=True,
        )
        self.assertEqual(decision["mode"], "OFFLINE_NOCVM")
        self.assertEqual(decision["reason"], "offline_nocvm_ok")

    def test_ctq_cdcvm_required_with_cdcvm_card_skips_online_pin(self):
        decision = self.router.decide(
            pan_bin="400000",
            amount_cents=500,
            floor_limit_cents=1000,
            ctq=b"\x20\x00",
        )
        self.assertEqual(decision["mode"], "OFFLINE_NOCVM")
        self.assertEqual(decision["reason"], "offline_nocvm_ok")

    def test_auc_forced_pin_routes_online(self):
        decision = self.router.decide(
            pan_bin="400000",
            amount_cents=500,
            floor_limit_cents=1000,
            ctq=b"\x00\x00",
            auc=b"\x00\x40",
        )
        self.assertEqual(decision["mode"], "ONLINE")
        self.assertEqual(decision["reason"], "auc_forced_pin")

    def test_debit_card_no_offline_support(self):
        decision = self.router.decide(
            pan_bin="457100",
            amount_cents=3000,
            floor_limit_cents=10000,
            ctq=b"\x00\x00",
        )
        self.assertEqual(decision["mode"], "ONLINE")
        self.assertEqual(decision["reason"], "no_offline_support")
        self.assertEqual(decision["brand"], "VISA")
        self.assertEqual(decision["card_type"], "Visa Debit")

    def test_debit_card_still_online_even_with_cdcvm(self):
        decision = self.router.decide(
            pan_bin="457100",
            amount_cents=3000,
            floor_limit_cents=10000,
            ctq=b"\x00\x00",
            cdcvm_verified=True,
        )
        self.assertEqual(decision["mode"], "ONLINE")
        self.assertEqual(decision["reason"], "no_offline_support")

    def test_brand_returned_in_decision(self):
        decision = self.router.decide(
            pan_bin="400000",
            amount_cents=500,
            floor_limit_cents=1000,
            ctq=b"\x00\x00",
        )
        self.assertEqual(decision["brand"], "VISA")
        self.assertEqual(decision["card_type"], "Visa Credit")
        self.assertTrue(decision["offline_capable"])
        self.assertTrue(decision["cdcvm_capable"])


class RelayServerAutoPolicyTests(unittest.TestCase):
    def setUp(self):
        self.server = RelayServer()
        self.server._card_bin = "400000"
        self.server._ctq_value = b"\x00\x00"
        self.server._floor_limit_cents = 2000
        self.server.policy_amount_cents = 1500

    def test_auto_policy_uses_router_when_env_is_unset(self):
        os.environ.pop("RELAY_POLICY_MODE", None)
        policy = self.server._mutation_policy()
        self.assertEqual(policy["mode"], "OFFLINE_NOCVM")
        self.assertEqual(policy["reason"], "offline_nocvm_ok")

    def test_explicit_policy_override_beats_router(self):
        os.environ["RELAY_POLICY_MODE"] = "ONLINE"
        policy = self.server._mutation_policy()
        self.assertEqual(policy["mode"], "ONLINE")
        self.assertEqual(policy["reason"], "forced_policy_mode")
        os.environ.pop("RELAY_POLICY_MODE", None)

    def test_auto_policy_switches_to_online_for_ctq_pin_required(self):
        self.server._ctq_value = b"\x80\x00"
        os.environ.pop("RELAY_POLICY_MODE", None)
        policy = self.server._mutation_policy()
        self.assertEqual(policy["mode"], "ONLINE")
        self.assertEqual(policy["reason"], "ctq_forces_online_pin")


if __name__ == "__main__":
    print("=== AUTO policy validation ===", flush=True)
    print("Checking BIN / CTQ / floor-limit / amount routing for the AUTO policy path.\n", flush=True)
    unittest.main(verbosity=2)
