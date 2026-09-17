# -*- coding: utf-8 -*-
"""Structured card-type knowledge base for ProductionCardRouter.

Pure-Python, no JSON, no DB, no external deps. Each entry maps a 4-digit
BIN prefix to brand, category, AID, supported features, verification
methods, and per-type transaction limits (in cents).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple, Any

# ======================================================================
# Card type registry
#
# Each entry: {
#   "brand":        str   — brand name (matches constants.BRAND_*)
#   "category":     str   — "credit" | "debit" | "prepaid"
#   "aid":          str   — canonical AID hex
#   "bin_prefixes": list  — 4-digit string prefixes
#   "offline":      bool  — card supports offline cryptograms
#   "cdcvm":        bool  — card supports CDCVM
#   "contactless":  bool  — card supports contactless
#   "offline_limit_cents":   int — max amount for offline (0 = no offline)
#   "contactless_limit_cents": int — max contactless amount
#   "floor_limit_cents":     int — card floor limit
#   "pin_required_above_cents": int — debit: PIN required above this (0 = never)
# }
# ======================================================================

CARD_TYPES: Dict[str, Dict[str, Any]] = {
    "Visa Credit": {
        "brand": "VISA",
        "category": "credit",
        "aid": "A0000000031010",
        "bin_prefixes": ["4000", "4111", "4444", "4567", "4712", "4999",
                         "4001", "4003", "4005", "4007", "4009", "4011"],
        "offline": True,
        "cdcvm": True,
        "contactless": True,
        "offline_limit_cents": 5000,
        "contactless_limit_cents": 10000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
    "Mastercard Credit": {
        "brand": "MASTERCARD",
        "category": "credit",
        "aid": "A0000000041010",
        "bin_prefixes": ["5100", "5200", "5300", "5400", "5500", "2720",
                         "5101", "5102", "5103", "5104", "5105", "2721"],
        "offline": True,
        "cdcvm": True,
        "contactless": True,
        "offline_limit_cents": 5000,
        "contactless_limit_cents": 10000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
    "American Express": {
        "brand": "AMEX",
        "category": "credit",
        "aid": "A000000025010801",
        "bin_prefixes": ["3400", "3700", "3780", "3701", "3702", "3703"],
        "offline": False,
        "cdcvm": False,
        "contactless": True,
        "offline_limit_cents": 0,
        "contactless_limit_cents": 20000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
    "Discover": {
        "brand": "DISCOVER",
        "category": "credit",
        "aid": "A0000001523010",
        "bin_prefixes": ["6011", "6500", "6550", "6012", "6013", "6501"],
        "offline": True,
        "cdcvm": False,
        "contactless": True,
        "offline_limit_cents": 5000,
        "contactless_limit_cents": 10000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
    "JCB": {
        "brand": "JCB",
        "category": "credit",
        "aid": "A0000000651010",
        "bin_prefixes": ["3528", "3589", "3529", "3530", "3531", "3532"],
        "offline": False,
        "cdcvm": False,
        "contactless": True,
        "offline_limit_cents": 0,
        "contactless_limit_cents": 10000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
    "UnionPay": {
        "brand": "UNIONPAY",
        "category": "credit",
        "aid": "A000000333010101",
        "bin_prefixes": ["6200", "6220", "6240", "6201", "6202", "6221"],
        "offline": False,
        "cdcvm": False,
        "contactless": True,
        "offline_limit_cents": 0,
        "contactless_limit_cents": 30000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
    "Diners Club": {
        "brand": "DISCOVER",
        "category": "credit",
        "aid": "A0000001523010",
        "bin_prefixes": ["3000", "3010", "3020", "3001", "3002", "3011"],
        "offline": False,
        "cdcvm": False,
        "contactless": False,
        "offline_limit_cents": 0,
        "contactless_limit_cents": 0,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
    "Maestro": {
        "brand": "MASTERCARD",
        "category": "debit",
        "aid": "A0000000043060",
        "bin_prefixes": ["5018", "5020", "5038", "5893", "6304", "6759"],
        "offline": False,
        "cdcvm": False,
        "contactless": True,
        "offline_limit_cents": 0,
        "contactless_limit_cents": 5000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
    "Visa Debit": {
        "brand": "VISA",
        "category": "debit",
        "aid": "A0000000032010",
        "bin_prefixes": ["4571", "4631", "4988"],
        "offline": False,
        "cdcvm": False,
        "contactless": True,
        "offline_limit_cents": 0,
        "contactless_limit_cents": 5000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 2500,
    },
    "Mastercard Debit": {
        "brand": "MASTERCARD",
        "category": "debit",
        "aid": "A0000000043060",
        "bin_prefixes": ["5555", "5434", "2223"],
        "offline": False,
        "cdcvm": False,
        "contactless": True,
        "offline_limit_cents": 0,
        "contactless_limit_cents": 5000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 2500,
    },
    "Visa Prepaid": {
        "brand": "VISA",
        "category": "prepaid",
        "aid": "A0000000031010",
        "bin_prefixes": ["4744", "4847", "4917", "4929"],
        "offline": False,
        "cdcvm": False,
        "contactless": True,
        "offline_limit_cents": 0,
        "contactless_limit_cents": 10000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
    "Mastercard Prepaid": {
        "brand": "MASTERCARD",
        "category": "prepaid",
        "aid": "A0000000041010",
        "bin_prefixes": ["5301", "5431", "2221"],
        "offline": False,
        "cdcvm": False,
        "contactless": True,
        "offline_limit_cents": 0,
        "contactless_limit_cents": 10000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
    "Amex Prepaid": {
        "brand": "AMEX",
        "category": "prepaid",
        "aid": "A000000025010801",
        "bin_prefixes": ["3782", "3787", "3797", "3716", "3714", "3717"],
        "offline": False,
        "cdcvm": False,
        "contactless": True,
        "offline_limit_cents": 0,
        "contactless_limit_cents": 15000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
    "Gift Card": {
        "brand": "DISCOVER",
        "category": "prepaid",
        "aid": "A0000001523010",
        "bin_prefixes": ["6040", "6042", "6043", "6044", "6045", "6046"],
        "offline": False,
        "cdcvm": False,
        "contactless": True,
        "offline_limit_cents": 0,
        "contactless_limit_cents": 50000,
        "floor_limit_cents": 0,
        "pin_required_above_cents": 0,
    },
}

# ======================================================================
# Reverse lookup: 4-digit prefix -> card type name
# ======================================================================

_PREFIX_INDEX: Dict[str, str] = {}
for _name, _cfg in CARD_TYPES.items():
    for _pfx in _cfg["bin_prefixes"]:
        _PREFIX_INDEX[_pfx] = _name
del _name, _cfg, _pfx


def lookup_bin(pan_bin: str) -> Optional[Dict[str, Any]]:
    """Look up card type from a BIN string (6-8 digits).
    Tries 4-digit prefix match against the registry.
    Returns the card type config dict or None."""
    if not pan_bin or not pan_bin.isdigit():
        return None
    prefix = pan_bin[:4]
    name = _PREFIX_INDEX.get(prefix)
    if name is None:
        return None
    entry = CARD_TYPES[name].copy()
    entry["name"] = name
    return entry


def all_offline_capable_prefixes() -> List[str]:
    """Return all 4-digit prefixes for card types that support offline."""
    result = []
    for cfg in CARD_TYPES.values():
        if cfg["offline"]:
            result.extend(cfg["bin_prefixes"])
    return result
