#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_mutation_matrix.py
=======================

Deterministic, offline regression matrix for the REL8HF mutation layer.

This is the runnable version of the original mutation-matrix scaffold.  It
keeps the useful ideas from that file (matrix, audit evidence, replay support)
but removes the inert execute_python() wrapper, fake network/tool calls, stale
CAPDU labels, and ambiguous mutation routing.

Default mode is pytest and NEVER starts the relay or sends network traffic:

    pytest -q test_mutation_matrix.py

or simply:

    python test_mutation_matrix.py

Offline replay audit mode:

    python test_mutation_matrix.py --replay-dir testlogs

The replay audit feeds recorded RAPDUs directly through deterministic mutation
functions.  Malformed historical fixtures are classified as SAFE_REJECTED or
SAFE_UNCHANGED; they are never rewritten to make a test green.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest

try:
    import constants
    import emv
    import mutations
    import tlv
except Exception as exc:  # pragma: no cover
    IMPORT_ERROR = (type(exc).__name__, str(exc))
    constants = emv = mutations = tlv = None  # type: ignore[assignment]
else:
    IMPORT_ERROR = None


def _require_core_imports() -> None:
    if IMPORT_ERROR is not None:
        exc_type, message = IMPORT_ERROR
        pytest.fail(
            "REL8HF core import failed: "
            f"{exc_type}: {message}. "
            "Run this from the project root with the project venv active."
        )


# ============================================================================
# Deterministic fixtures
# ============================================================================

SW_9000 = b"\x90\x00"

GPO_RAPDU = bytes.fromhex(
    "770E82021880940810010101200103009000"
)

READ_RECORD_RAPDU = bytes.fromhex(
    "703E"
    "8E10"
    "000000000000000042031F031E030000"
    "9F0D050010000000"
    "9F0E050010000000"
    "9F0F050010000000"
    "5A084111111111111111"
    "5F2403261231"
    "5F340101"
    "9000"
)

READ_RECORD_CANONICAL_RAPDU = bytes.fromhex(
    "703E"
    "8E10"
    "0000000000000000000001031E030000"
    "9F0D050000000000"
    "9F0E050000000000"
    "9F0F050000000000"
    "5A084111111111111111"
    "5F2403261231"
    "5F340101"
    "9000"
)

GAC_TVR_CAPDU = bytes.fromhex(
    "80AE80003C"
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
    "00"
)

GAC_TVR_CAPDU_2 = bytes.fromhex(
    "80AE80003C"
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
    "00"
)

EXT_AUTH_CAPDU = bytes.fromhex(
    "008200000A"
    "1122334455667788"
    "3035"
)

TAG91_GAC_CAPDU = bytes.fromhex(
    "80AE40000C"
    "910A"
    "1122334455667788"
    "3035"
)

CVM_LIST = bytes.fromhex(
    "0000000000000000"
    "1F03"
    "1E03"
    "0000"
)

CDOL1 = bytes.fromhex(
    "9F0206"
    "9F0306"
    "9F1A02"
    "9505"
    "5F2A02"
    "9A03"
    "9C01"
    "9F3704"
    "9F3501"
    "9F3403"
)

UNIVERSAL_PATCH_ENTRIES = [
    (0x9F02, 6),
    (0x9F03, 6),
    (0x9F1A, 2),
    (0x95, 5),
    (0x5F2A, 2),
    (0x9A, 3),
    (0x9C, 1),
    (0x9F37, 4),
    (0x9F35, 1),
    (0x9F34, 3),
    (0x9F4C, 8),
    (0x9F45, 1),
]

UNIVERSAL_PATCH_PAYLOAD = (
    bytes.fromhex("000000000000")
    + bytes.fromhex("000000000000")
    + bytes.fromhex("0840")
    + bytes.fromhex("0080808000")
    + bytes.fromhex("0840")
    + bytes.fromhex("260825")
    + bytes.fromhex("00")
    + bytes.fromhex("11223344")
    + bytes.fromhex("22")
    + bytes.fromhex("1F0300")
    + bytes.fromhex("0000000000000000")
    + bytes.fromhex("00")
)

UNIVERSAL_PATCH_CAPDU = (
    bytes.fromhex("80AE4000")
    + bytes([len(UNIVERSAL_PATCH_PAYLOAD)])
    + UNIVERSAL_PATCH_PAYLOAD
)

TEST_KC = bytes.fromhex(
    "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF"
)

KNOWN_FUNCTIONS = (
    "_safe_replace_tlv",
    "mutate_gpo_response",
    "mutate_read_record_response",
    "mutate_tvr_in_generate_ac_capdu",
    "rewrite_arpc_in_capdu",
    "forge_2nd_gac_template_77",
    "forge_2nd_gac_template_80",
    "_compute_arpc",
    "forge_2nd_gac",
    "forge_2nd_gac_raw",
    "forge_2nd_gac_old",
    "mutate_tvr_in_generate_ac",
    "parse_cdol1",
    "build_offset_map",
    "parse_cvm_list",
    "select_cvm_spoof",
    "patch_generate_ac_universal",
    "clear_tvr_if_allowed",
)


# ============================================================================
# Evidence helpers
# ============================================================================

AUDIT_EVENTS: List[Dict[str, Any]] = []


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record(
    name: str,
    status: str,
    *,
    function: Optional[str] = None,
    input_bytes: Optional[bytes] = None,
    output_bytes: Optional[bytes] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    AUDIT_EVENTS.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test": name,
            "function": function,
            "status": status,
            "input_length": len(input_bytes) if input_bytes is not None else None,
            "output_length": len(output_bytes) if output_bytes is not None else None,
            "input_sha256": sha256_bytes(input_bytes) if input_bytes is not None else None,
            "output_sha256": sha256_bytes(output_bytes) if output_bytes is not None else None,
            "details": details or {},
        }
    )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write JSONL evidence without affecting the test outcome."""
    path = Path(
        os.environ.get(
            "MUTATION_MATRIX_AUDIT",
            "mutation_matrix_audit.jsonl",
        )
    )
    try:
        with path.open("w", encoding="utf-8") as fh:
            for event in AUDIT_EVENTS:
                fh.write(json.dumps(event, sort_keys=True) + "\n")
    except OSError:
        pass


# ============================================================================
# Generic assertions
# ============================================================================


def response_body(data: bytes) -> bytes:
    assert len(data) >= 2
    return data[:-2]


def status_word(data: bytes) -> bytes:
    assert len(data) >= 2
    return data[-2:]


def same_tags(before: bytes, after: bytes, tags: Iterable[int]) -> None:
    for tag in tags:
        assert tlv.find_tlv(before, tag) == tlv.find_tlv(after, tag), (
            f"Tag 0x{tag:X} changed unexpectedly"
        )


# ============================================================================
# Import/API coherence
# ============================================================================


def test_module_paths_are_canonical() -> None:
    _require_core_imports()
    paths = {
        "mutations": getattr(mutations, "__file__", ""),
        "tlv": getattr(tlv, "__file__", ""),
        "emv": getattr(emv, "__file__", ""),
        "constants": getattr(constants, "__file__", ""),
    }
    for name, path in paths.items():
        assert path, f"Cannot determine imported path for {name}"
        assert Path(path).name.lower() == f"{name}.py", (
            f"Unexpected imported {name}: {path}"
        )
    record("module path coherence", "PASS", details=paths)


def test_mutation_api_inventory() -> None:
    _require_core_imports()
    missing = [
        name
        for name in KNOWN_FUNCTIONS
        if not callable(getattr(mutations, name, None))
    ]
    assert not missing, f"Missing mutation functions: {missing}"

    signatures = {
        name: str(inspect.signature(getattr(mutations, name)))
        for name in KNOWN_FUNCTIONS
    }
    record(
        "mutation API inventory",
        "PASS",
        details={"count": len(KNOWN_FUNCTIONS), "signatures": signatures},
    )


# ============================================================================
# GPO
# ============================================================================


def test_gpo_mutation_smoke() -> None:
    _require_core_imports()
    out, ok = mutations.mutate_gpo_response(
        GPO_RAPDU,
        cdcvm_verified=True,
    )
    assert isinstance(out, bytes)
    assert isinstance(ok, bool)
    assert out[-2:] == SW_9000
    assert tlv.find_tlv(out[:-2], 0x82) is not None

    record(
        "GPO mutation smoke",
        "PASS",
        function="mutate_gpo_response",
        input_bytes=GPO_RAPDU,
        output_bytes=out,
        details={"ok_flag": ok},
    )


# ============================================================================
# READ RECORD
# ============================================================================


def test_read_record_valid_mutation_and_preservation() -> None:
    _require_core_imports()
    out = mutations.mutate_read_record_response(READ_RECORD_RAPDU)
    assert isinstance(out, bytes)
    assert len(out) == len(READ_RECORD_RAPDU)
    assert status_word(out) == SW_9000

    before = response_body(READ_RECORD_RAPDU)
    after = response_body(out)
    expected_cvm = bytes.fromhex(
        "0000000000000000000001031E030000"
    )

    assert tlv.find_tlv(after, 0x8E) == expected_cvm
    for tag in (0x9F0D, 0x9F0E, 0x9F0F):
        value = tlv.find_tlv(after, tag)
        assert value is not None
        assert value == b"\x00" * len(value)

    same_tags(before, after, (0x5A, 0x5F24, 0x5F34))

    record(
        "READ RECORD valid mutation",
        "PASS",
        function="mutate_read_record_response",
        input_bytes=READ_RECORD_RAPDU,
        output_bytes=out,
        details={"preserved": ["5A", "5F24", "5F34"]},
    )


def test_read_record_already_mutated_is_noop() -> None:
    _require_core_imports()
    out = mutations.mutate_read_record_response(
        READ_RECORD_CANONICAL_RAPDU
    )
    assert isinstance(out, bytes)
    assert out == READ_RECORD_CANONICAL_RAPDU

    record(
        "READ RECORD already-mutated no-op",
        "PASS",
        function="mutate_read_record_response",
        input_bytes=READ_RECORD_CANONICAL_RAPDU,
        output_bytes=out,
    )


def test_read_record_malformed_is_safe() -> None:
    _require_core_imports()

    # Derive the malformed fixture from the known-valid deterministic fixture.
    # This intentionally changes ONLY the 8E length declaration from 0x10 to
    # 0x1B while leaving every subsequent byte untouched. The result is
    # structurally malformed because the declared CVM value overlaps siblings.
    malformed_body = (
        READ_RECORD_RAPDU[:-2]
        .replace(
            bytes.fromhex("8E10"),
            bytes.fromhex("8E1B"),
            1,
        )
    )
    malformed = malformed_body + SW_9000

    assert malformed != READ_RECORD_RAPDU
    assert bytes.fromhex("8E1B") in malformed_body

    try:
        out = mutations.mutate_read_record_response(malformed)
    except (ValueError, RuntimeError) as exc:
        record(
            "READ RECORD malformed safe rejection",
            "PASS",
            function="mutate_read_record_response",
            input_bytes=malformed,
            details={"exception": f"{type(exc).__name__}: {exc}"},
        )
        return

    assert isinstance(out, bytes)
    assert out == malformed
    assert len(out) == len(malformed)

    record(
        "READ RECORD malformed safe unchanged",
        "PASS",
        function="mutate_read_record_response",
        input_bytes=malformed,
        output_bytes=out,
    )


# ============================================================================
# GENERATE AC TVR
# ============================================================================


def test_generate_ac_tvr_fixture_matches_current_scenario_input() -> None:
    _require_core_imports()

    expected_hex = (
        "80AE80003C"
        "9F0206000000002500"
        "9F0306000000000000"
        "9F1A020840"
        "95058000800000"
        "5F2A020840"
        "9A03260825"
        "9C0100"
        "9F370411223344"
        "9F350122"
        "9F34031E030000"
    )

    assert GAC_TVR_CAPDU.hex().upper() == expected_hex
    assert len(GAC_TVR_CAPDU) == 66
    assert GAC_TVR_CAPDU[4] == 0x3C
    assert 5 + GAC_TVR_CAPDU[4] == 65
    assert len(GAC_TVR_CAPDU) - (5 + GAC_TVR_CAPDU[4]) == 1
    assert GAC_TVR_CAPDU[-1] == 0x00


def test_generate_ac_tvr_capdu_contract() -> None:
    _require_core_imports()

    # Contract preflight: this fixture is intentionally a GENERATE AC CAPDU
    # and must agree with the production APDU constants. These assertions do
    # not alter the test; they make a constants/index mismatch diagnosable.
    assert hasattr(constants, "APDU_INS"), "constants.APDU_INS is missing"
    assert hasattr(constants, "INS_GENERATE_AC"), "constants.INS_GENERATE_AC is missing"

    ins_offset = constants.APDU_INS
    assert isinstance(ins_offset, int)
    assert 0 <= ins_offset < 5
    assert GAC_TVR_CAPDU[ins_offset] == constants.INS_GENERATE_AC, (
        "Fixture/function contract mismatch: "
        f"fixture byte at APDU_INS={ins_offset} is "
        f"0x{GAC_TVR_CAPDU[ins_offset]:02X}, "
        f"but INS_GENERATE_AC is 0x{constants.INS_GENERATE_AC:02X}"
    )

    lc = GAC_TVR_CAPDU[4]
    assert lc > 0
    assert 5 + lc <= len(GAC_TVR_CAPDU), (
        f"Malformed CAPDU fixture: Lc={lc}, total={len(GAC_TVR_CAPDU)}"
    )

    payload = GAC_TVR_CAPDU[5:5 + lc]
    marker = bytes.fromhex("9505")
    before_at = payload.find(marker)

    assert before_at >= 0, "Fixture does not contain Tag 95 length 05"
    before_tvr = payload[before_at + 2:before_at + 7]
    assert len(before_tvr) == 5

    # The fixture must actually require the mutation we are testing.
    assert (before_tvr[0] & 0x80) != 0, (
        f"TVR byte 1 does not contain the ODA-failure bit: "
        f"{before_tvr.hex().upper()}"
    )
    assert (before_tvr[2] & 0xC0) != 0, (
        f"TVR byte 3 does not contain the expected CVM/PIN bits: "
        f"{before_tvr.hex().upper()}"
    )

    out, note = mutations.mutate_tvr_in_generate_ac_capdu(
        GAC_TVR_CAPDU
    )

    assert isinstance(out, bytes)
    assert isinstance(note, (str, type(None)))
    assert len(out) == len(GAC_TVR_CAPDU)
    assert out[:5] == GAC_TVR_CAPDU[:5]
    assert out[4] == GAC_TVR_CAPDU[4]

    after_payload = out[5:5 + out[4]]
    after_at = after_payload.find(marker)

    assert after_at == before_at, (
        "Tag 95 moved within the declared CAPDU payload"
    )

    after_tvr = after_payload[after_at + 2:after_at + 7]
    assert len(after_tvr) == 5

    # Exact mutation contract.
    expected = bytearray(before_tvr)
    expected[0] &= ~0x80
    expected[2] &= ~0xC0
    expected = bytes(expected)

    assert after_tvr == expected, (
        f"TVR mutation mismatch: "
        f"{before_tvr.hex().upper()} -> {after_tvr.hex().upper()}, "
        f"expected {expected.hex().upper()}"
    )

    # Everything else in the CAPDU payload must remain byte-for-byte equal.
    before_payload_after_header = (
        payload[:before_at] + payload[before_at + 7:]
    )
    after_payload_after_header = (
        after_payload[:after_at] + after_payload[after_at + 7:]
    )
    assert (
        before_payload_after_header
        == after_payload_after_header
    ), "Bytes outside Tag 95 were modified."

    record(
        "GENERATE AC TVR CAPDU mutation",
        "PASS",
        function="mutate_tvr_in_generate_ac_capdu",
        input_bytes=GAC_TVR_CAPDU,
        output_bytes=out,
        details={
            "note": note,
            "tvr_before": before_tvr.hex().upper(),
            "tvr_after": after_tvr.hex().upper(),
        },
    )


@pytest.mark.parametrize(
    "fixture",
    [GAC_TVR_CAPDU, GAC_TVR_CAPDU_2],
    ids=["scenario3-shape", "scenario11-shape"],
)
def test_generate_ac_tvr_both_current_scenario_inputs(
    fixture: bytes,
) -> None:
    _require_core_imports()

    assert fixture[1] == constants.INS_GENERATE_AC
    out, note = mutations.mutate_tvr_in_generate_ac_capdu(fixture)

    assert isinstance(out, bytes)
    assert len(out) == len(fixture)
    assert out[:5] == fixture[:5]

    lc = fixture[4]
    assert 5 + lc <= len(fixture)
    assert fixture[5 + lc:] == b"\x00"
    before = fixture[5:5 + lc]
    after = out[5:5 + out[4]]

    marker = bytes.fromhex("9505")
    before_at = before.find(marker)
    after_at = after.find(marker)

    assert before_at >= 0
    assert after_at == before_at

    before_tvr = before[before_at + 2:before_at + 7]
    after_tvr = after[after_at + 2:after_at + 7]

    expected = bytearray(before_tvr)
    expected[0] &= ~0x80
    expected[2] &= ~0xC0

    assert after_tvr == bytes(expected), (
        f"{before_tvr.hex().upper()} -> "
        f"{after_tvr.hex().upper()} != "
        f"{bytes(expected).hex().upper()}"
    )

    assert (
        before[:before_at] + before[before_at + 7:]
        == after[:after_at] + after[after_at + 7:]
    )


def test_legacy_generate_ac_response_path_is_byte_safe() -> None:
    _require_core_imports()
    rapdu = bytes.fromhex("770E950580008000009000")
    out, ok = mutations.mutate_tvr_in_generate_ac(
        rapdu,
        clear_tvr=True,
    )
    assert isinstance(out, bytes)
    assert isinstance(ok, bool)
    record(
        "legacy GENERATE AC response path",
        "PASS",
        function="mutate_tvr_in_generate_ac",
        input_bytes=rapdu,
        output_bytes=out,
        details={"ok_flag": ok},
    )


# ============================================================================
# ARPC / ARC
# ============================================================================


def test_external_authenticate_arc_rewrite() -> None:
    _require_core_imports()
    out, note = mutations.rewrite_arpc_in_capdu(EXT_AUTH_CAPDU)
    assert isinstance(out, bytes)
    assert len(out) == len(EXT_AUTH_CAPDU)
    assert out[:5] == EXT_AUTH_CAPDU[:5]

    if note is not None:
        assert len(out[5 + 8:5 + 10]) == 2

    record(
        "EXTERNAL AUTHENTICATE ARC rewrite",
        "PASS",
        function="rewrite_arpc_in_capdu",
        input_bytes=EXT_AUTH_CAPDU,
        output_bytes=out,
        details={"note": note},
    )


def test_generate_ac_tag91_arc_rewrite() -> None:
    _require_core_imports()
    out, note = mutations.rewrite_arpc_in_capdu(TAG91_GAC_CAPDU)
    assert isinstance(out, bytes)
    assert len(out) == len(TAG91_GAC_CAPDU)
    assert out[:5] == TAG91_GAC_CAPDU[:5]

    data = out[5:5 + out[4]]
    value = tlv.find_tlv(data, 0x91)
    assert value is not None
    assert len(value) == 10

    record(
        "GENERATE AC Tag 91 ARC rewrite",
        "PASS",
        function="rewrite_arpc_in_capdu",
        input_bytes=TAG91_GAC_CAPDU,
        output_bytes=out,
        details={"note": note},
    )


# ============================================================================
# Second-GAC forge subsystem
# ============================================================================


def make_cache(template: int) -> Any:
    return emv.ArqcCache(
        cid=getattr(constants, "CID_ARQC", 0x80),
        atc=bytes.fromhex("0012"),
        ac=bytes.fromhex("1122334455667788"),
        iad=bytes.fromhex("06010A030000"),
        template=template,
    )


def test_forge_template_77() -> None:
    _require_core_imports()
    template = getattr(constants, "TEMPLATE_77", 0x77)
    tc = getattr(constants, "CID_TC", 0x40)
    cache = make_cache(template)
    out = mutations.forge_2nd_gac_template_77(cache, forced_cid=tc)

    assert isinstance(out, bytes)
    assert out.endswith(SW_9000)
    body = out[:-2]
    assert body[0] == template
    assert tlv.find_tlv(body, 0x9F27) == bytes([tc])
    assert tlv.find_tlv(body, 0x9F36) == bytes.fromhex("0012")
    assert tlv.find_tlv(body, 0x9F26) == bytes.fromhex("1122334455667788")
    assert tlv.find_tlv(body, 0x9F10) == bytes.fromhex("06010A030000")

    record(
        "Template 77 forge",
        "PASS",
        function="forge_2nd_gac_template_77",
        output_bytes=out,
    )


def test_forge_template_80() -> None:
    _require_core_imports()
    template = getattr(constants, "TEMPLATE_80", 0x80)
    tc = getattr(constants, "CID_TC", 0x40)
    cache = make_cache(template)
    out = mutations.forge_2nd_gac_template_80(cache, forced_cid=tc)

    assert isinstance(out, bytes)
    assert out.endswith(SW_9000)
    assert out[0] == template

    body = out[:-2]
    if body[1] == 0x81:
        payload_len = body[2]
        payload = body[3:]
    elif body[1] == 0x82:
        payload_len = int.from_bytes(body[2:4], "big")
        payload = body[4:]
    else:
        payload_len = body[1]
        payload = body[2:]

    expected = (
        bytes([tc])
        + bytes.fromhex("0012")
        + bytes.fromhex("1122334455667788")
        + bytes.fromhex("06010A030000")
    )
    assert payload_len == len(payload) == len(expected)
    assert payload == expected

    record(
        "Template 80 forge",
        "PASS",
        function="forge_2nd_gac_template_80",
        output_bytes=out,
        details={"payload_length": payload_len},
    )


def test_forge_dispatcher_routes_both_templates() -> None:
    _require_core_imports()
    tc = getattr(constants, "CID_TC", 0x40)
    for template in (
        getattr(constants, "TEMPLATE_77", 0x77),
        getattr(constants, "TEMPLATE_80", 0x80),
    ):
        cache = make_cache(template)
        out = mutations.forge_2nd_gac(cache, forced_cid=tc)
        assert isinstance(out, bytes)
        assert out.endswith(SW_9000)
        assert out[0] == template

        record(
            f"forge dispatcher template {template:02X}",
            "PASS",
            function="forge_2nd_gac",
            output_bytes=out,
            details={"template": f"{template:02X}"},
        )


def test_raw_and_legacy_forge_are_coherent() -> None:
    _require_core_imports()
    ac = bytes.fromhex("1122334455667788")
    iad = bytes.fromhex("06010A030000")
    atc = bytes.fromhex("0012")
    arqc = bytes.fromhex("0102030405060708")
    brand = getattr(constants, "BRAND_UNKNOWN", "UNKNOWN")

    arpc = mutations._compute_arpc(ac, iad, atc, TEST_KC)
    assert isinstance(arpc, bytes)
    assert len(arpc) == 8

    raw = mutations.forge_2nd_gac_raw(
        ac, iad, atc, arqc, 0x80, brand, TEST_KC
    )
    old = mutations.forge_2nd_gac_old(
        ac, iad, atc, arqc, 0x80, brand, TEST_KC
    )
    assert isinstance(raw, bytes)
    assert isinstance(old, bytes)
    assert raw == old
    assert raw.endswith(SW_9000)

    record(
        "raw/legacy forge coherence",
        "PASS",
        function="forge_2nd_gac_raw",
        output_bytes=raw,
        details={"arpc_length": len(arpc)},
    )


# ============================================================================
# Parsing / mapping helpers
# ============================================================================


def test_parse_cdol1_and_offset_map() -> None:
    _require_core_imports()
    entries = mutations.parse_cdol1(CDOL1)
    assert entries
    assert entries[0] == (0x9F02, 6)
    assert entries[1] == (0x9F03, 6)
    assert (0x95, 5) in entries
    assert (0x9F34, 3) in entries

    offsets = mutations.build_offset_map(entries)
    assert offsets[0x9F02] == (0, 6)
    assert offsets[0x9F03] == (6, 6)
    assert offsets[0x9F1A] == (12, 2)
    assert offsets[0x95] == (14, 5)

    record(
        "CDOL1/offset-map coherence",
        "PASS",
        function="parse_cdol1",
        input_bytes=CDOL1,
        details={"entry_count": len(entries)},
    )


def test_parse_cvm_list_and_select_spoof() -> None:
    _require_core_imports()
    entries = mutations.parse_cvm_list(CVM_LIST)
    assert (0x1F, 0x03) in entries
    assert (0x1E, 0x03) in entries

    spoof = mutations.select_cvm_spoof(entries, auc=b"\x00\x00")
    assert spoof is not None
    spoof_9f34, spoof_9f35 = spoof
    assert isinstance(spoof_9f34, bytes)
    assert len(spoof_9f34) == 3
    assert isinstance(spoof_9f35, int)

    forced = mutations.select_cvm_spoof(
        [(0x1E, 0x03)],
        auc=b"\x00\x40",
    )
    assert forced == (bytes.fromhex("010000"), 0x26)

    record(
        "CVM parsing/spoof selection",
        "PASS",
        function="select_cvm_spoof",
        input_bytes=CVM_LIST,
        details={"entries": entries},
    )


# ============================================================================
# Universal patcher
# ============================================================================


def test_universal_generate_ac_patcher() -> None:
    _require_core_imports()
    import random

    state = random.getstate()
    random.seed(1337)
    try:
        out, notes = mutations.patch_generate_ac_universal(
            UNIVERSAL_PATCH_CAPDU,
            UNIVERSAL_PATCH_ENTRIES,
            cvm_entries=[(0x1F, 0x03), (0x1E, 0x03)],
            auc=b"\x00\x00",
        )
    finally:
        random.setstate(state)

    assert isinstance(out, bytes)
    assert isinstance(notes, str)
    assert len(out) == len(UNIVERSAL_PATCH_CAPDU)
    assert out[:4] == UNIVERSAL_PATCH_CAPDU[:4]
    assert out[4] == UNIVERSAL_PATCH_CAPDU[4]

    payload = out[5:5 + out[4]]
    offsets = mutations.build_offset_map(UNIVERSAL_PATCH_ENTRIES)

    tvr_off, tvr_len = offsets[0x95]
    assert tvr_len == 5
    assert payload[tvr_off + 1] & 0x80 == 0

    term_off, _ = offsets[0x9F35]
    cvm_off, cvm_len = offsets[0x9F34]
    assert payload[term_off] == 0x26
    assert cvm_len == 3
    assert payload[cvm_off:cvm_off + 3] == bytes.fromhex("010000")

    icc_off, icc_len = offsets[0x9F4C]
    dac_off, dac_len = offsets[0x9F45]
    assert any(payload[icc_off:icc_off + icc_len])
    assert any(payload[dac_off:dac_off + dac_len])

    record(
        "universal GENERATE AC patcher",
        "PASS",
        function="patch_generate_ac_universal",
        input_bytes=UNIVERSAL_PATCH_CAPDU,
        output_bytes=out,
        details={"notes": notes},
    )


# ============================================================================
# CVM-aware TVR helper
# ============================================================================


def test_clear_tvr_if_allowed() -> None:
    _require_core_imports()
    original = bytes.fromhex("8000800000")

    cleared = mutations.clear_tvr_if_allowed(
        original,
        cvm_list=[],
        terminal_cvm=set(),
    )
    assert cleared == b"\x00" * len(original)

    unchanged = mutations.clear_tvr_if_allowed(
        original,
        cvm_list=[0x1F],
        terminal_cvm=set(),
    )
    assert unchanged == original

    record(
        "CVM-aware TVR clearing",
        "PASS",
        function="clear_tvr_if_allowed",
    )


# ============================================================================
# Protected-tag helper
# ============================================================================


def test_safe_replace_protected_tag_is_noop() -> None:
    _require_core_imports()
    data = bytes.fromhex(
        "5A084111111111111111"
        "8E100000000000000000001F031E030000"
    )
    out = mutations._safe_replace_tlv(
        data,
        0x5A,
        bytes.fromhex("0000000000000000"),
    )
    assert out == data
    record(
        "protected-tag replacement guard",
        "PASS",
        function="_safe_replace_tlv",
        input_bytes=data,
        output_bytes=out,
    )


# ============================================================================
# Direct TLV regression
# ============================================================================


def test_tlv_replace_preserves_suffix() -> None:
    _require_core_imports()
    old_value = bytes(range(27))
    new_value = bytes.fromhex("000000000000000000001F031E030000")
    original = (
        tlv.build_tlv(0x5A, bytes.fromhex("12345678"))
        + tlv.build_tlv(0x8E, old_value)
        + tlv.build_tlv(0x9F51, bytes.fromhex("010203"))
    )

    out = tlv.replace_tlv(original, 0x8E, new_value)
    assert len(out) - len(original) == len(new_value) - len(old_value)
    assert tlv.find_tlv(out, 0x8E) == new_value
    assert tlv.find_tlv(out, 0x5A) == bytes.fromhex("12345678")
    assert tlv.find_tlv(out, 0x9F51) == bytes.fromhex("010203")

    malformed = b"\x8E\x05\x01\x02"
    with pytest.raises(ValueError):
        tlv.replace_tlv(malformed, 0x8E, b"X")

    record(
        "TLV exact replacement/suffix preservation",
        "PASS",
        function="replace_tlv",
        input_bytes=original,
        output_bytes=out,
        details={"expected_delta": len(new_value) - len(old_value)},
    )


# ============================================================================
# Offline replay audit
# ============================================================================


def replay_directory(replay_dir: Path) -> List[Dict[str, Any]]:
    """Run deterministic response mutations over JSON replay files."""
    results: List[Dict[str, Any]] = []

    for path in sorted(replay_dir.glob("*.json")):
        try:
            sequence = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            results.append({
                "file": path.name,
                "status": "ERROR",
                "error": f"JSON: {type(exc).__name__}: {exc}",
            })
            continue

        for index, exchange in enumerate(sequence, start=1):
            capdu_hex = str(exchange.get("capdu", ""))
            rapdu_hex = str(exchange.get("rapdu", ""))
            try:
                rapdu = bytes.fromhex(rapdu_hex)
            except ValueError as exc:
                results.append({
                    "file": path.name,
                    "exchange": index,
                    "status": "ERROR",
                    "error": f"RAPDU hex: {exc}",
                })
                continue

            ins = capdu_hex[2:4].upper() if len(capdu_hex) >= 4 else ""
            if ins not in {"A8", "B2"}:
                continue

            item: Dict[str, Any] = {
                "file": path.name,
                "exchange": index,
                "ins": ins,
                "input_length": len(rapdu),
                "input_sha256": sha256_bytes(rapdu),
            }

            try:
                if ins == "A8":
                    out, ok = mutations.mutate_gpo_response(
                        rapdu,
                        cdcvm_verified=True,
                    )
                    if not isinstance(out, bytes):
                        raise TypeError("GPO mutation did not return bytes")
                    item.update({
                        "path": "GPO",
                        "status": "PASS",
                        "ok_flag": bool(ok),
                        "output_length": len(out),
                        "output_sha256": sha256_bytes(out),
                    })

                else:
                    try:
                        out = mutations.mutate_read_record_response(rapdu)
                    except (ValueError, RuntimeError) as exc:
                        item.update({
                            "path": "READ_RECORD",
                            "status": "SAFE_REJECTED",
                            "error": f"{type(exc).__name__}: {exc}",
                        })
                    else:
                        if not isinstance(out, bytes):
                            raise TypeError(
                                "READ RECORD mutation did not return bytes"
                            )
                        if out != rapdu and len(out) != len(rapdu):
                            raise AssertionError(
                                "mutation changed READ RECORD length"
                            )
                        item.update({
                            "path": "READ_RECORD",
                            "status": "PASS",
                            "output_length": len(out),
                            "output_sha256": sha256_bytes(out),
                            "unchanged": out == rapdu,
                        })

            except Exception as exc:
                item.update({
                    "status": "ERROR",
                    "error": f"{type(exc).__name__}: {exc}",
                })

            results.append(item)

    return results


def print_replay_results(results: List[Dict[str, Any]]) -> int:
    counts: Dict[str, int] = {}
    for item in results:
        status = str(item.get("status"))
        counts[status] = counts.get(status, 0) + 1
        print(json.dumps(item, sort_keys=True))

    print("Summary:", json.dumps(counts, sort_keys=True))
    return 1 if any(
        item.get("status") in {"ERROR", "FAIL"}
        for item in results
    ) else 0


# ============================================================================
# Standalone entry point
# ============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(
        description="REL8HF deterministic mutation matrix"
    )
    parser.add_argument(
        "--replay-dir",
        type=Path,
        help="Run offline mutation replay audit against JSON files.",
    )
    args, extra = parser.parse_known_args()

    if args.replay_dir is not None:
        if not args.replay_dir.exists():
            print(f"Replay directory not found: {args.replay_dir}")
            return 2
        return print_replay_results(
            replay_directory(args.replay_dir)
        )

    pytest_args = [str(Path(__file__).resolve()), "-q", *extra]
    return int(pytest.main(pytest_args))


if __name__ == "__main__":
    raise SystemExit(main())
