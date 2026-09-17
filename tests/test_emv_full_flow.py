#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REL8HF FULL EMV FLOW / DEFINITION EXERCISER

Offline, deterministic laboratory test that calls the real project code and
prints actual outputs. It does not open sockets, use a reader, or touch live
payment infrastructure.

Run:
    python test_emv_full_flow.py
    python test_emv_full_flow.py --no-scenarios
    pytest -q test_emv_full_flow.py

Coverage:
    protocol.py   APDU + TLV parse/build/identify helpers
    tlv.py        active bridge + fallback helpers
    emv.py        DOL/CDOL/CVM/cache/ARQC/identification/rebuild helpers
    mutations.py  mutation/CVM/TVR/ARPC/forge/rebuild paths
    mutation_scenarios.py registry + every registered executor

Every call prints:
    definition
    actual output
    PASS/FAIL/ERROR
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import random
import re
import sys
import traceback
from pathlib import Path
from typing import Any, Callable

import pytest

import constants
import emv
import mutations
import mutation_scenarios
import protocol
import tlv


SW9000 = b"\x90\x00"
CID_ARQC = getattr(constants, "CID_ARQC", 0x80)
CID_TC = getattr(constants, "CID_TC", 0x40)
CID_AAC = getattr(constants, "CID_AAC", 0x00)
TEMPLATE_77 = getattr(constants, "TEMPLATE_77", 0x77)
TEMPLATE_80 = getattr(constants, "TEMPLATE_80", 0x80)
BRAND = getattr(constants, "BRAND_UNKNOWN", "UNKNOWN")

# ---------------------------------------------------------------------------
# Canonical synthetic fixtures
# ---------------------------------------------------------------------------

GPO_INNER = b"".join([
    protocol.build_tlv(0x82, bytes.fromhex("3800")),
    protocol.build_tlv(0x94, bytes.fromhex("0801010010010200")),
    protocol.build_tlv(0x9F6C, bytes.fromhex("0000")),
    protocol.build_tlv(0x5F28, bytes.fromhex("0840")),
    protocol.build_tlv(0x9F36, bytes.fromhex("001A")),
    protocol.build_tlv(0x57, bytes.fromhex("4111111111111111D261220100000000000F")),
    protocol.build_tlv(0x5A, bytes.fromhex("4111111111111111")),
])
GPO_RAPDU = protocol.build_tlv(0x77, GPO_INNER) + SW9000

CVM_LIST = bytes.fromhex("000000000000000042031F031E030000")
READ_RECORD_INNER = b"".join([
    protocol.build_tlv(0x8E, CVM_LIST),
    protocol.build_tlv(0x9F0D, bytes.fromhex("0010000000")),
    protocol.build_tlv(0x9F0E, bytes.fromhex("0010000000")),
    protocol.build_tlv(0x9F0F, bytes.fromhex("0010000000")),
    protocol.build_tlv(0x5A, bytes.fromhex("4111111111111111")),
    protocol.build_tlv(0x5F24, bytes.fromhex("261231")),
    protocol.build_tlv(0x5F34, b"\x01"),
])
READ_RECORD_RAPDU = protocol.build_tlv(0x70, READ_RECORD_INNER) + SW9000

GAC_DATA = bytes.fromhex(
    "9F0206000000002500"
    "9F0306000000000000"
    "9F1A020840"
    "95058000800000"
    "5F2A020840"
    "9A03260825"
    "9C0100"
    "9F370411223344"
    "9F350122"
    "9F34031E0300"
)
GAC_CAPDU = bytes.fromhex("80AE8000") + bytes([len(GAC_DATA)]) + GAC_DATA + b"\x00"

GAC_DATA_11 = bytes.fromhex(
    "9F0206000000001000"
    "9F0306000000000000"
    "9F1A020840"
    "95058000800000"
    "5F2A020840"
    "9A03260825"
    "9C0100"
    "9F370411223344"
    "9F350122"
    "9F34031E0300"
)
GAC_CAPDU_11 = bytes.fromhex("80AE8000") + bytes([len(GAC_DATA_11)]) + GAC_DATA_11 + b"\x00"

SECOND_GAC_RAPDU = (
    protocol.build_tlv(
        0x77,
        protocol.build_tlv(0x95, bytes.fromhex("8000800000"))
        + protocol.build_tlv(0x9F27, b"\x80")
        + protocol.build_tlv(0x9F36, bytes.fromhex("0012"))
        + protocol.build_tlv(0x9F26, bytes.fromhex("1122334455667788"))
    )
    + SW9000
)

EXT_AUTH_CAPDU = bytes.fromhex("008200000A11223344556677883035")
TAG91 = protocol.build_tlv(0x91, bytes.fromhex("1122334455667788") + b"05")
TAG91_GAC_CAPDU = bytes.fromhex("80AE4000") + bytes([len(TAG91)]) + TAG91 + b"\x00"

CDOL1_RAW = bytes.fromhex(
    "9F0206 9F0306 9F1A02 9505 5F2A02 9A03 9C01"
    "9F3704 9F3501 9F3403 9F4C08 9F4501".replace(" ", "")
)
CDOL1_ENTRIES = [
    (0x9F02, 6), (0x9F03, 6), (0x9F1A, 2), (0x95, 5),
    (0x5F2A, 2), (0x9A, 3), (0x9C, 1), (0x9F37, 4),
    (0x9F35, 1), (0x9F34, 3), (0x9F4C, 8), (0x9F45, 1),
]

UNIVERSAL_PAYLOAD = (
    bytes.fromhex("000000000000") + bytes.fromhex("000000000000")
    + bytes.fromhex("0840") + bytes.fromhex("0080800000")
    + bytes.fromhex("0840") + bytes.fromhex("260825") + b"\x00"
    + bytes.fromhex("11223344") + b"\x21" + bytes.fromhex("020300")
    + bytes(8) + b"\x00"
)
assert len(UNIVERSAL_PAYLOAD) == sum(n for _, n in CDOL1_ENTRIES)
UNIVERSAL_CAPDU = bytes.fromhex("80AE8000") + bytes([len(UNIVERSAL_PAYLOAD)]) + UNIVERSAL_PAYLOAD + b"\x00"

ARQC_77 = (
    protocol.build_tlv(
        0x77,
        protocol.build_tlv(0x9F27, bytes([CID_ARQC]))
        + protocol.build_tlv(0x9F36, bytes.fromhex("0012"))
        + protocol.build_tlv(0x9F26, bytes.fromhex("1122334455667788"))
        + protocol.build_tlv(0x9F10, bytes.fromhex("06010A030000")),
    ) + SW9000
)
ARQC_80 = (
    protocol.build_tlv(
        0x80,
        bytes([CID_ARQC]) + bytes.fromhex("0012")
        + bytes.fromhex("1122334455667788")
        + bytes.fromhex("06010A030000"),
    ) + SW9000
)

# Deterministic 24-byte 3DES test key (48 hex characters).
TEST_KEY = bytes.fromhex(
    "0123456789ABCDEFFEDCBA9876543210"
    "0011223344556677"
)
assert len(TEST_KEY) == 24


NESTED = (
    protocol.build_tlv(
        0x77,
        protocol.build_tlv(0x9F6C, b"\x00\x00")
        + protocol.build_tlv(0x82, b"\x38\x00"),
    )
    + protocol.build_tlv(0x5F28, b"\x08\x40")
)


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

RESULTS: list[dict[str, Any]] = []


def show(value: Any) -> str:
    if isinstance(value, bytes):
        return f"bytes[{len(value)}] {value.hex().upper()}"
    if isinstance(value, bytearray):
        b = bytes(value)
        return f"bytearray[{len(b)}] {b.hex().upper()}"
    return repr(value)


def call(
    name: str,
    fn: Callable[..., Any],
    *args: Any,
    expected: Callable[[Any], bool] | None = None,
    **kwargs: Any,
) -> Any:
    idx = len(RESULTS) + 1
    print(f"\n[{idx:03d}] {name}")
    print(f"      CALL: {getattr(fn, '__qualname__', repr(fn))}")
    try:
        result = fn(*args, **kwargs)
        actual = show(result)
        print(f"      OUTPUT: {actual}")
        ok = True if expected is None else bool(expected(result))
        print(f"      RESULT: {'PASS' if ok else 'FAIL'}")
        RESULTS.append({
            "id": idx, "name": name,
            "callable": getattr(fn, "__qualname__", repr(fn)),
            "status": "PASS" if ok else "FAIL",
            "output": actual,
        })
        return result
    except Exception as exc:
        print(f"      ERROR: {type(exc).__name__}: {exc}")
        RESULTS.append({
            "id": idx, "name": name,
            "callable": getattr(fn, "__qualname__", repr(fn)),
            "status": "ERROR",
            "exception": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        })
        return None


def section(title: str) -> None:
    print("\n" + "=" * 84)
    print(title)
    print("=" * 84)


# ---------------------------------------------------------------------------
# protocol.py
# ---------------------------------------------------------------------------

def flow_protocol() -> None:
    section("A. protocol.py — APDU PARSING / IDENTIFICATION / TLV BUILD & REBUILD")

    select_raw = bytes.fromhex("00A404000E325041592E5359532E444446303100")
    cmd = call(
        "CommandAPDU.from_bytes(SELECT)",
        protocol.CommandAPDU.from_bytes, select_raw,
        expected=lambda x: x is not None,
    )
    if cmd:
        call("CommandAPDU.to_bytes", cmd.to_bytes, expected=lambda x: x == select_raw)
        call("CommandAPDU.ins_name", lambda: cmd.ins_name)
        call("CommandAPDU.is_select", lambda: cmd.is_select, expected=lambda x: x is True)
        call("CommandAPDU.is_gpo", lambda: cmd.is_gpo, expected=lambda x: x is False)
        call("CommandAPDU.is_read_record", lambda: cmd.is_read_record, expected=lambda x: x is False)
        call("CommandAPDU.is_generate_ac", lambda: cmd.is_generate_ac, expected=lambda x: x is False)
        call("CommandAPDU.is_verify", lambda: cmd.is_verify, expected=lambda x: x is False)
        call("CommandAPDU.select_aid", lambda: cmd.select_aid)

    verify = protocol.CommandAPDU.from_bytes(bytes.fromhex("0020008000"))
    if verify:
        call("CommandAPDU VERIFY ins_name", lambda: verify.ins_name)
        call("CommandAPDU VERIFY is_verify", lambda: verify.is_verify, expected=lambda x: x is True)

    response = call("ResponseAPDU.from_bytes(GPO)", protocol.ResponseAPDU.from_bytes, GPO_RAPDU)
    if response:
        call("ResponseAPDU.to_bytes", response.to_bytes, expected=lambda x: x == GPO_RAPDU)
        call("ResponseAPDU.sw", lambda: response.sw, expected=lambda x: x == SW9000)
        call("ResponseAPDU.is_ok", lambda: response.is_ok, expected=lambda x: x is True)
        call("ResponseAPDU.parse_tlv_list", response.parse_tlv_list)

    call("craft_verify_success", protocol.craft_verify_success)
    call("sw(9000)", protocol.sw, SW9000)

    built = call("protocol.build_tlv(9F6C)", protocol.build_tlv, 0x9F6C, b"\x80\x00",
                 expected=lambda x: x == bytes.fromhex("9F6C028000"))
    call("protocol.parse_tlv(9F6C)", protocol.parse_tlv, built)
    call("protocol.parse_tlv_list(NESTED)", protocol.parse_tlv_list, NESTED)
    tree = call("protocol.parse_ber_tlv(NESTED)", protocol.parse_ber_tlv, NESTED)
    if tree is not None:
        rebuilt = call("protocol.build_ber_tlv(TlvTree)", protocol.build_ber_tlv, tree)
        if rebuilt is not None:
            call("BER round-trip equality", lambda: rebuilt == NESTED, expected=lambda x: x is True)

    call("protocol.find_tlv(9F6C)", protocol.find_tlv, NESTED, 0x9F6C,
         expected=lambda x: x == b"\x00\x00")
    replaced = call("protocol.replace_tlv(9F6C)", protocol.replace_tlv, NESTED, 0x9F6C, b"\x80\x00")
    if replaced is not None:
        call("replacement value", protocol.find_tlv, replaced, 0x9F6C,
             expected=lambda x: x == b"\x80\x00")
        call("replacement preserves 5F28", protocol.find_tlv, replaced, 0x5F28,
             expected=lambda x: x == b"\x08\x40")

    call("protocol.is_constructed_tag(77)", protocol.is_constructed_tag, 0x77,
         expected=lambda x: x is True)
    call("protocol.is_constructed_tag(9F6C)", protocol.is_constructed_tag, 0x9F6C,
         expected=lambda x: x is False)

    tv = protocol.TlvValue(b"ABC")
    call("TlvValue.length", lambda: tv.length, expected=lambda x: x == 3)
    tt = protocol.TlvTree()
    tt[0x9F6C] = b"\x00\x00"
    call("TlvTree.__contains__", lambda: 0x9F6C in tt, expected=lambda x: x is True)
    call("TlvTree.__getitem__", lambda: tt[0x9F6C])
    call("TlvTree.get", tt.get, 0x9F6C)


# ---------------------------------------------------------------------------
# tlv.py
# ---------------------------------------------------------------------------

def flow_tlv() -> None:
    section("B. tlv.py — ACTIVE BRIDGE + FALLBACK DEFINITIONS")

    call("tlv._parse_tag(9F6C)", tlv._parse_tag, bytes.fromhex("9F6C028000"), 0)
    call("tlv._parse_length(short)", tlv._parse_length, bytes.fromhex("0200"), 0)
    call("tlv._is_constructed(77)", tlv._is_constructed, 0x77)
    call("tlv._is_constructed(9F6C)", tlv._is_constructed, 0x9F6C)

    # When protocol.py is importable, tlv.py intentionally exposes the
    # protocol implementations. Call those active definitions as well.
    call("tlv.build_tlv(9F6C)", tlv.build_tlv, 0x9F6C, b"\x00\x00")
    call("tlv.find_tlv(9F6C)", tlv.find_tlv, NESTED, 0x9F6C)
    call("tlv.parse_tlv_list", tlv.parse_tlv_list, NESTED)
    call("tlv.parse_tlv", tlv.parse_tlv, bytes.fromhex("9F6C020000"))
    call("tlv.parse_ber_tlv", tlv.parse_ber_tlv, NESTED)
    tree = tlv.parse_ber_tlv(NESTED)
    call("tlv.build_ber_tlv", tlv.build_ber_tlv, tree)
    call("tlv.replace_tlv", tlv.replace_tlv, NESTED, 0x9F6C, b"\x80\x00")


# ---------------------------------------------------------------------------
# emv.py
# ---------------------------------------------------------------------------

def flow_emv() -> None:
    section("C. emv.py — PARSING / IDENTIFICATION / CACHE / REBUILD")

    call("emv.parse_tlv", emv.parse_tlv, bytes.fromhex("9F6C028000"))

    cache = emv.ArqcCache()
    call("ArqcCache.is_complete(empty)", cache.is_complete, expected=lambda x: x is False)
    cache.cid = CID_ARQC
    cache.atc = b"\x00\x12"
    cache.ac = bytes.fromhex("1122334455667788")
    cache.iad = bytes.fromhex("06010A030000")
    cache.template = TEMPLATE_77
    call("ArqcCache.is_complete(filled)", cache.is_complete, expected=lambda x: x is True)
    call("ArqcCache.clear", cache.clear)
    call("ArqcCache.is_complete(after clear)", cache.is_complete, expected=lambda x: x is False)

    state = emv.SessionState()
    call("SessionState.cached_arqc getter", lambda: state.cached_arqc)
    call("SessionState.cached_arqc setter", lambda: setattr(state, "cached_arqc", b"\xAA" * 8))
    call("SessionState.cached_arqc getter", lambda: state.cached_arqc)
    call("SessionState.cached_iad setter", lambda: setattr(state, "cached_iad", b"\x01\x02"))
    call("SessionState.cached_iad getter", lambda: state.cached_iad)
    call("SessionState.cached_atc setter", lambda: setattr(state, "cached_atc", b"\x00\x01"))
    call("SessionState.cached_atc getter", lambda: state.cached_atc)
    call("SessionState.reset", state.reset)

    parsed_dol = call("emv.parse_dol", emv.parse_dol, CDOL1_RAW)
    call("emv.parse_cdol1", emv.parse_cdol1, CDOL1_RAW)
    call("emv.build_offset_map", emv.build_offset_map, CDOL1_ENTRIES)

    cvm_entries = call("emv.parse_cvm_list", emv.parse_cvm_list, CVM_LIST)
    if cvm_entries is not None:
        call("emv.select_cvm_spoof(normal)", emv.select_cvm_spoof, cvm_entries, b"\x08\x00")
        call("emv.select_cvm_spoof(forced PIN)", emv.select_cvm_spoof, cvm_entries, b"\x08\x40")

    rr_context = (
        protocol.build_tlv(
            0x70,
            protocol.build_tlv(0x8C, CDOL1_RAW)
            + protocol.build_tlv(0x8E, CVM_LIST)
            + protocol.build_tlv(0x9F07, b"\x08\x40"),
        )
        + SW9000
    )
    call("emv.parse_read_record_cdol", emv.parse_read_record_cdol, rr_context)
    call("emv.extract_card_cvm_data", emv.extract_card_cvm_data, rr_context)

    c77 = call("emv.extract_arqc_from_rapdu(77)", emv.extract_arqc_from_rapdu, ARQC_77, TEMPLATE_77)
    if c77:
        call("emv.cid_indicates_arqc(77)", emv.cid_indicates_arqc, c77, ARQC_77)
    c80 = call("emv.extract_arqc_from_rapdu(80)", emv.extract_arqc_from_rapdu, ARQC_80, TEMPLATE_80)
    if c80:
        call("emv.cid_indicates_arqc(80)", emv.cid_indicates_arqc, c80, ARQC_80)

    for cid, name in ((CID_ARQC, "ARQC"), (CID_TC, "TC"), (CID_AAC, "AAC")):
        call(f"emv.cid_indicates_arqc({name})", emv.cid_indicates_arqc, emv.ArqcCache(cid=cid), b"")

    call(
        "emv.cid_indicates_arqc(byte-scan fallback)",
        emv.cid_indicates_arqc,
        emv.ArqcCache(),
        bytes.fromhex("9F270180"),
    )
    call("emv.craft_verify_success_bytes", emv.craft_verify_success_bytes,
         expected=lambda x: x == SW9000)

    correct77 = protocol.build_tlv(
        0x77,
        protocol.build_tlv(0x9F27, b"\x40") + protocol.build_tlv(0x9F36, b"\x00\x01"),
    ) + SW9000
    malformed77 = b"\x77\x01" + correct77[2:-2] + SW9000
    call("emv.fix_gac_response_length", emv.fix_gac_response_length, malformed77)


# ---------------------------------------------------------------------------
# mutations.py — every relevant definition
# ---------------------------------------------------------------------------

def flow_mutations() -> None:
    section("D. mutations.py — ALL MUTATION / CVM / FORGE / REBUILD DEFINITIONS")

    protected = protocol.build_tlv(0x5A, bytes.fromhex("4111111111111111"))
    call("mutations._safe_replace_tlv(non-protected)", mutations._safe_replace_tlv,
         NESTED, 0x9F6C, b"\x80\x00")
    call("mutations._safe_replace_tlv(protected 5A)", mutations._safe_replace_tlv,
         protected, 0x5A, b"\x00" * 8, expected=lambda x: x == protected)

    gpo = call("mutations.mutate_gpo_response", mutations.mutate_gpo_response,
               GPO_RAPDU, cdcvm_verified=True,
               expected=lambda x: isinstance(x, tuple) and isinstance(x[0], bytes))
    if gpo:
        call("GPO output bytes", lambda: gpo[0])
        call("GPO status", lambda: gpo[0][-2:], expected=lambda x: x == SW9000)
        call("GPO AIP", protocol.find_tlv, gpo[0], 0x82)
        call("GPO CTQ", protocol.find_tlv, gpo[0], 0x9F6C)

    rr = call("mutations.mutate_read_record_response", mutations.mutate_read_record_response,
              READ_RECORD_RAPDU, expected=lambda x: isinstance(x, bytes))
    if rr:
        call("READ RECORD CVM", protocol.find_tlv, rr, 0x8E)
        call("READ RECORD IAC-Default", protocol.find_tlv, rr, 0x9F0D)
        call("READ RECORD IAC-Denial", protocol.find_tlv, rr, 0x9F0E)
        call("READ RECORD IAC-Online", protocol.find_tlv, rr, 0x9F0F)
        call("READ RECORD no-op after normalization", mutations.mutate_read_record_response, rr,
             expected=lambda x: x == rr)

    tv = call("mutations.mutate_tvr_in_generate_ac_capdu", mutations.mutate_tvr_in_generate_ac_capdu,
              GAC_CAPDU, expected=lambda x: isinstance(x, tuple) and isinstance(x[0], bytes))
    call("mutations.mutate_tvr_in_generate_ac_capdu Scenario 11",
         mutations.mutate_tvr_in_generate_ac_capdu, GAC_CAPDU_11)

    call("mutations.rewrite_arpc_in_capdu(EXTERNAL AUTH)", mutations.rewrite_arpc_in_capdu,
         EXT_AUTH_CAPDU)
    call("mutations.rewrite_arpc_in_capdu(Tag 91)", mutations.rewrite_arpc_in_capdu,
         TAG91_GAC_CAPDU)

    f77 = call("mutations.forge_2nd_gac_template_77",
               mutations.forge_2nd_gac_template_77,
               emv.ArqcCache(cid=CID_ARQC, atc=b"\x00\x12",
                             ac=bytes.fromhex("1122334455667788"),
                             iad=bytes.fromhex("06010A030000"), template=TEMPLATE_77),
               CID_TC, BRAND, expected=lambda x: isinstance(x, bytes) and x.endswith(SW9000))
    if f77:
        call("forge77 CID", protocol.find_tlv, f77, 0x9F27)
        call("forge77 ATC", protocol.find_tlv, f77, 0x9F36)
        call("forge77 AC", protocol.find_tlv, f77, 0x9F26)
        call("forge77 IAD", protocol.find_tlv, f77, 0x9F10)

    call("mutations.forge_2nd_gac_template_80",
         mutations.forge_2nd_gac_template_80,
         emv.ArqcCache(cid=CID_ARQC, atc=b"\x00\x25",
                       ac=bytes.fromhex("AABBCCDDEEFF0011"),
                       iad=bytes.fromhex("060112030000"), template=TEMPLATE_80),
         CID_TC, BRAND, expected=lambda x: isinstance(x, bytes) and x.endswith(SW9000))

    call("mutations.FORGE_DISPATCH[77]",
         lambda: mutations.FORGE_DISPATCH[TEMPLATE_77].__name__)
    call("mutations.FORGE_DISPATCH[80]",
         lambda: mutations.FORGE_DISPATCH[TEMPLATE_80].__name__)

    call("mutations._compute_arpc", mutations._compute_arpc,
         bytes.fromhex("1122334455667788"),
         bytes.fromhex("06010A030000"),
         b"\x00\x12",
         TEST_KEY,
         expected=lambda x: isinstance(x, bytes) and len(x) == 8)

    raw = call("mutations.forge_2nd_gac_raw", mutations.forge_2nd_gac_raw,
               bytes.fromhex("1122334455667788"),
               bytes.fromhex("06010A030000"),
               b"\x00\x12",
               bytes.fromhex("0102030405060708"),
               0x80, BRAND, TEST_KEY,
               expected=lambda x: isinstance(x, bytes) and x.endswith(SW9000))
    old = call("mutations.forge_2nd_gac_old", mutations.forge_2nd_gac_old,
               bytes.fromhex("1122334455667788"),
               bytes.fromhex("06010A030000"),
               b"\x00\x12",
               bytes.fromhex("0102030405060708"),
               0x80, BRAND, TEST_KEY)
    if raw is not None and old is not None:
        call("legacy forge == raw forge", lambda: old == raw, expected=lambda x: x is True)

    call("mutations.forge_2nd_gac(dispatch 77)", mutations.forge_2nd_gac,
         emv.ArqcCache(cid=CID_ARQC, atc=b"\x00\x12",
                       ac=bytes.fromhex("1122334455667788"),
                       iad=bytes.fromhex("06010A030000"), template=TEMPLATE_77),
         CID_TC, BRAND)

    call("mutations.forge_2nd_gac(dispatch 80)", mutations.forge_2nd_gac,
         emv.ArqcCache(cid=CID_ARQC, atc=b"\x00\x25",
                       ac=bytes.fromhex("AABBCCDDEEFF0011"),
                       iad=bytes.fromhex("060112030000"), template=TEMPLATE_80),
         CID_TC, BRAND)

    call("mutations.mutate_tvr_in_generate_ac", mutations.mutate_tvr_in_generate_ac,
         SECOND_GAC_RAPDU, clear_tvr=True)

    call("mutations.parse_cdol1", mutations.parse_cdol1, CDOL1_RAW)
    call("mutations.build_offset_map", mutations.build_offset_map, CDOL1_ENTRIES)
    m_cvm = call("mutations.parse_cvm_list", mutations.parse_cvm_list, CVM_LIST)
    if m_cvm is not None:
        call("mutations.select_cvm_spoof(normal)", mutations.select_cvm_spoof, m_cvm, b"\x08\x00")
        call("mutations.select_cvm_spoof(forced PIN)", mutations.select_cvm_spoof, m_cvm, b"\x08\x40")

    univ = call("mutations.patch_generate_ac_universal",
                mutations.patch_generate_ac_universal,
                UNIVERSAL_CAPDU, CDOL1_ENTRIES, m_cvm, b"\x08\x00")
    if univ:
        call("universal patched CAPDU length", lambda: len(univ[0]))
        call("universal notes", lambda: univ[1])

    call("mutations.clear_tvr_if_allowed(clear)",
         mutations.clear_tvr_if_allowed, bytes.fromhex("8000800000"), [], set(),
         expected=lambda x: x == b"\x00" * 5)
    call("mutations.clear_tvr_if_allowed(unchanged)",
         mutations.clear_tvr_if_allowed, bytes.fromhex("8000800000"), [0x1F], set(),
         expected=lambda x: x == bytes.fromhex("8000800000"))


# ---------------------------------------------------------------------------
# mutation_scenarios.py — call every registered executor
# ---------------------------------------------------------------------------

def clean_html(s: str) -> str:
    return re.sub(r"<[^>]+>", "", s)


def scenario_context(scen: Any) -> mutation_scenarios.ScenarioRunContext:
    raw_hex = scen.preset_apdu or "80A8000002830000"
    return mutation_scenarios.ScenarioRunContext(
        raw_hex=raw_hex,
        raw_bytes=bytes.fromhex(raw_hex),
        cdcvm=True,
        brand=BRAND,
        cdol1_hex=getattr(scen, "preset_cdol1", "") or CDOL1_RAW.hex().upper(),
        cvm_hex=getattr(scen, "preset_cvm", "") or CVM_LIST.hex().upper(),
        synth_amount=1234,
        synth_currency=978,
        synth_country=250,
    )


def flow_scenarios() -> None:
    section("E. mutation_scenarios.py — REGISTRY + EVERY CURRENT EXECUTOR")

    scenarios = call("mutation_scenarios.get_scenarios", mutation_scenarios.get_scenarios,
                     expected=lambda x: isinstance(x, list) and bool(x))
    if not scenarios:
        return

    for i, scen in enumerate(scenarios, start=1):
        print(f"\n--- SCENARIO {i}: {scen.key} ---")
        print(f"TITLE: {scen.title}")
        print(f"EXECUTOR: {scen.executor.__name__}")
        print(f"PRESET: {scen.preset_apdu}")

        call(f"get_scenario({scen.key})", mutation_scenarios.get_scenario, scen.key,
             expected=lambda x, s=scen: x is s)

        ctx = scenario_context(scen)
        outcome = call(
            f"run_scenario({scen.key})",
            mutation_scenarios.run_scenario,
            scen.key,
            ctx,
            expected=lambda x: isinstance(x, mutation_scenarios.ScenarioOutcome),
        )
        if outcome is not None:
            print("     STEPS:")
            for step in outcome.steps:
                print(f"       {clean_html(step)}")
            print(f"     MUTATED FLAG: {outcome.mutated_flag}")
            if outcome.mutated_bytes:
                print(
                    f"     FINAL OUTPUT: {len(outcome.mutated_bytes)} B "
                    f"{outcome.mutated_bytes.hex().upper()}"
                )


# ---------------------------------------------------------------------------
# Inventory and final report
# ---------------------------------------------------------------------------

def inventory() -> None:
    section("F. DEFINITION INVENTORY — WHAT THE TEST KNOWS ABOUT")

    for name, mod in (
        ("protocol", protocol),
        ("tlv", tlv),
        ("emv", emv),
        ("mutations", mutations),
        ("mutation_scenarios", mutation_scenarios),
    ):
        funcs = []
        classes = []
        for n, obj in inspect.getmembers(mod):
            if inspect.isfunction(obj) and getattr(obj, "__module__", None) == mod.__name__:
                funcs.append(n)
            elif inspect.isclass(obj) and getattr(obj, "__module__", None) == mod.__name__:
                classes.append(n)
        print(f"\n{name}.py")
        print("  functions:", ", ".join(funcs))
        print("  classes:  ", ", ".join(classes))


def report() -> int:
    path = Path("test_emv_full_flow_report.json")
    payload = {
        "status": "PASS" if not any(x["status"] in {"FAIL", "ERROR"} for x in RESULTS) else "FAIL",
        "python": sys.version,
        "modules": {
            n: getattr(m, "__file__", None)
            for n, m in {
                "constants": constants,
                "protocol": protocol,
                "tlv": tlv,
                "emv": emv,
                "mutations": mutations,
                "mutation_scenarios": mutation_scenarios,
            }.items()
        },
        "calls": RESULTS,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    failed = sum(x["status"] == "FAIL" for x in RESULTS)
    errors = sum(x["status"] == "ERROR" for x in RESULTS)

    print("\n" + "=" * 84)
    print("FINAL RESULT")
    print("=" * 84)
    print(f"Definitions/calls recorded: {len(RESULTS)}")
    print(f"FAIL: {failed}")
    print(f"ERROR: {errors}")
    print(f"JSON report: {path.resolve()}")

    if failed or errors:
        print("\nFAILED/ERROR CALLS:")
        for x in RESULTS:
            if x["status"] in {"FAIL", "ERROR"}:
                print(f" - {x['name']}: {x.get('exception', x.get('output', ''))}")
        return 1

    print("\nALL EXERCISED EMV DOMAIN CALLS PASSED.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-scenarios", action="store_true")
    args = parser.parse_args()

    random.seed(1337)
    inventory()
    flow_protocol()
    flow_tlv()
    flow_emv()
    flow_mutations()
    if not args.no_scenarios:
        flow_scenarios()
    return report()


def test_full_emv_domain_flow() -> None:
    """Pytest entry point for the direct-core phases."""
    RESULTS.clear()
    FAILURES_BEFORE = len(RESULTS)
    random.seed(1337)
    flow_protocol()
    flow_tlv()
    flow_emv()
    flow_mutations()
    bad = [x for x in RESULTS if x["status"] in {"FAIL", "ERROR"}]
    assert not bad, json.dumps(bad, indent=2)


if __name__ == "__main__":
    raise SystemExit(main())
