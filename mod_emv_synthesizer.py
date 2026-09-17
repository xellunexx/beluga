# -*- coding: utf-8 -*-
"""
Automated Dynamic PDOL/CDOL Field Synthesizer Plugin (mod_emv_synthesizer.py)
----------------------------------------------------------------------------
Inspects unknown/dynamic terminal tags in EMV flows (GPO / GENERATE AC)
and automatically synthesizes valid terminal data (TTQ, Terminal Capabilities,
Amount, Country/Currency, UN, TVR, CVM Results) matching card profiles.
"""

from __future__ import annotations

import datetime
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple


def _parse_tlv(buf: bytes) -> List[Tuple[int, bytes]]:
    """Parse flat TLV stream into (tag, val) pairs."""
    res: List[Tuple[int, bytes]] = []
    i = 0
    n = len(buf)
    while i < n:
        b = buf[i]
        i += 1
        if b in (0x00, 0xFF):
            continue
        tag = b
        if (b & 0x1F) == 0x1F:
            tag = 0
            while i < n:
                nb = buf[i]
                i += 1
                tag = (tag << 8) | nb
                if not (nb & 0x80):
                    break
        if i >= n:
            break
        length = buf[i]
        i += 1
        if length & 0x80:
            nb = length & 0x7F
            if i + nb > n:
                break
            length = int.from_bytes(buf[i:i + nb], "big")
            i += nb
        if i + length > n:
            val = buf[i:]
            res.append((tag, val))
            break
        val = buf[i:i + length]
        res.append((tag, val))
        i += length
    return res


def _find_tlv(buf: bytes, target_tag: int) -> Optional[bytes]:
    for tag, val in _parse_tlv(buf):
        if tag == target_tag:
            return val
    return None


def _parse_dol(dol: bytes) -> List[Tuple[int, int]]:
    """Parse Data Object List into list of (tag, length)."""
    out: List[Tuple[int, int]] = []
    i = 0
    n = len(dol)
    while i < n:
        b = dol[i]
        i += 1
        if b in (0x00, 0xFF):
            continue
        tag = b
        if (b & 0x1F) == 0x1F:
            tag = 0
            while i < n:
                nb = dol[i]
                i += 1
                tag = (tag << 8) | nb
                if not (nb & 0x80):
                    break
        if i >= n:
            break
        length = dol[i]
        i += 1
        out.append((tag, length))
    return out


class EmvSynthesizer:
    """Dynamic EMV Field Synthesizer for PDOL / CDOL1 / CDOL2."""

    def __init__(
        self,
        amount: int = 0,
        currency_code: int = 978,  # EUR
        country_code: int = 250,   # France
        terminal_type: int = 0x22,    # Attended online/offline capable
        contactless: bool = True,
    ) -> None:
        self.amount = amount
        self.currency_code = currency_code
        self.country_code = country_code
        self.terminal_type = terminal_type
        self.contactless = contactless

    def synthesize_tag(self, tag: int, length: int) -> bytes:
        """Synthesize a single EMV terminal tag with the exact requested length."""
        now = datetime.datetime.now(datetime.timezone.utc)

        # 9F66: Terminal Transaction Qualifiers (TTQ)
        if tag == 0x9F66:
            # Byte 1: Contactless EMV, qVSDC, DDA/fDDA, Offline data auth supported
            # Byte 2: CVM required / No CVM
            # Byte 3: Reader offline / online PIN support
            # Byte 4: Contactless/Contact switch
            val = bytearray([0x36, 0x00, 0x40, 0x00]) if self.contactless else bytearray([0x20, 0x00, 0x00, 0x00])
            return bytes(val[:length]).ljust(length, b"\x00")

        # 9F02: Amount, Authorized (Numeric BCD, 6 bytes)
        elif tag == 0x9F02:
            amount = max(0, int(self.amount)) % 1_000_000_000_000
            amt_str = f"{amount:012d}"
            return bytes.fromhex(amt_str)[-length:].rjust(length, b"\x00")

        # 9F03: Amount, Other (Numeric BCD, 6 bytes)
        elif tag == 0x9F03:
            return b"\x00" * length

        # 9F1A: Terminal Country Code (2 bytes BCD)
        elif tag == 0x9F1A:
            country = max(0, int(self.country_code)) % 10_000
            return bytes.fromhex(f"{country:04d}")[-length:].rjust(length, b"\x00")

        # 5F2A: Transaction Currency Code (2 bytes BCD)
        elif tag == 0x5F2A:
            currency = max(0, int(self.currency_code)) % 10_000
            return bytes.fromhex(f"{currency:04d}")[-length:].rjust(length, b"\x00")

        # 9A: Transaction Date (YYMMDD BCD, 3 bytes)
        elif tag == 0x9A:
            date_str = now.strftime("%y%m%d")
            return bytes.fromhex(date_str)[:length].rjust(length, b"\x00")

        # 9F21: Transaction Time (HHMMSS BCD, 3 bytes)
        elif tag == 0x9F21:
            time_str = now.strftime("%H%M%S")
            return bytes.fromhex(time_str)[:length].rjust(length, b"\x00")

        # 9C: Transaction Type (1 byte: 0x00 = Goods/Services)
        elif tag == 0x9C:
            return b"\x00" * length

        # 9F37: Unpredictable Number (UN, 4 bytes random)
        elif tag == 0x9F37:
            return secrets.token_bytes(length)

        # 9F35: Terminal Type (1 byte)
        elif tag == 0x9F35:
            return bytes([self.terminal_type])[:length]

        # 9F33: Terminal Capabilities (3 bytes)
        elif tag == 0x9F33:
            # SDA, DDA, CDA, EMV / Magstripe, Plaintext / Enciphered PIN, Signature, No CVM
            return (b"\xE0\xF8\xC8")[:length].ljust(length, b"\x00")

        # 9F40: Additional Terminal Capabilities (5 bytes)
        elif tag == 0x9F40:
            return (b"\xF0\x00\xF0\xA0\x01")[:length].ljust(length, b"\x00")

        # 9F34: CVM Results (3 bytes)
        elif tag == 0x9F34:
            # 0x1F = No CVM, 0x03 = Successful, 0x00 = No details
            return (b"\x1F\x03\x00")[:length].ljust(length, b"\x00")

        # 95: Terminal Verification Results (TVR, 5 bytes)
        elif tag == 0x95:
            return b"\x00" * length

        # 9F1E: IFD Serial Number (8 bytes ASCII)
        elif tag == 0x9F1E:
            return b"RELAY001"[:length].ljust(length, b" ")

        # 9F53: Transaction Category Code (1 byte)
        elif tag == 0x9F53:
            return b"R"[:length].ljust(length, b"\x00")

        # Fallback for any unknown tag: zero-fill
        return b"\x00" * length

    def synthesize_dol(self, dol: bytes) -> bytes:
        """Synthesize full byte buffer for the provided DOL schema."""
        entries = _parse_dol(dol)
        chunks: List[bytes] = []
        for tag, length in entries:
            chunks.append(self.synthesize_tag(tag, length))
        return b"".join(chunks)

    def build_gpo_apdu(self, pdol: Optional[bytes] = None) -> bytes:
        """Build GPO CAPDU (80A80000 Lc 83 Lg [synthesized data] 00)."""
        if not pdol:
            data = b"\x83\x00"
        else:
            synth = self.synthesize_dol(pdol)
            data = b"\x83" + bytes([len(synth)]) + synth
        lc = len(data)
        return bytes([0x80, 0xA8, 0x00, 0x00, lc]) + data + b"\x00"

    def process_apdu(self, data: bytes, is_card_to_reader: bool = False) -> Tuple[bytes, bool]:
        """Process an APDU and synthesize missing terminal objects if appropriate."""
        if not data or len(data) < 4:
            return data, False
        cla, ins = data[0], data[1]
        # Intercept GPO
        if cla == 0x80 and ins == 0xA8:
            synth_gpo = self.build_gpo_apdu()
            return synth_gpo, True
        return data, False


# Backward-compatible alias
ModEmvSynthesizer = EmvSynthesizer


class Plugin:
    """Server2 Plugin interface for dynamic PDOL / CDOL synthesis."""

    def __init__(self, args: Any = None) -> None:
        amt = getattr(args, "amount", 0) if args else 0
        curr = getattr(args, "currency_code", 978) if args else 978
        country = getattr(args, "country_code", 250) if args else 250
        self.synth = EmvSynthesizer(amount=amt, currency_code=curr, country_code=country)

    def process(self, logger: Any, data: bytes, client: Any, server: Any, session: Any) -> bytes:
        """Middleware hook: inspects and synthesizes GPO and GAC APDUs dynamically."""
        if not data or len(data) < 4:
            return data

        cla, ins = data[0], data[1]

        # Intercept GPO with dynamic PDOL synthesis
        if cla == 0x80 and ins == 0xA8:
            stored_pdol = getattr(server, "shared_state", {}).get(session, {}).get("pdol")
            if stored_pdol:
                logger.info(f"[SYNTHESIZER] Dynamic PDOL synthesis applied ({len(stored_pdol)} bytes schema)")
                return self.synth.build_gpo_apdu(stored_pdol)

        return data


def handle_data_ex(logger: Any, data: bytes, client: Any, server: Any, session: Any) -> bytes:
    """Functional plugin interface."""
    p = Plugin()
    return p.process(logger, data, client, server, session)
