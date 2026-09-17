# -*- coding: utf-8 -*-
"""mutation_scenarios.py — Canonical data-driven laboratory scenario registry.

This module is intentionally Qt-free. It is the shared scenario/evidence layer
used by the Qt mutation playground, headless runners, regression matrices, and
contract-harness tooling.

Design goals
------------
* One scenario definition is shared by GUI and headless callers.
* Executors perform deterministic/synthetic laboratory operations only.
* Outcomes carry machine-readable evidence in addition to presentation text.
* Validators state what was actually asserted; no hard-coded "100% verified"
  claims are emitted unless an executable assertion passed.
* Randomized fixtures can be reproduced with an explicit seed.
* Multi-stage experiments record stage provenance instead of pretending that
  independent fixtures form one continuous runtime transaction.

This file is a test harness component, not a production payment component.
Synthetic fixtures are explicitly labeled as synthetic evidence.
"""

from __future__ import annotations

import contextlib
import hashlib
import html
import random
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import constants
import emv
import mod_emv_synthesizer
import mutations
import protocol
import tlv


# ============================================================================
# Evidence model
# ============================================================================

VALID_STATUSES = {"PASS", "FAIL", "PARTIAL", "UNVERIFIED", "SKIPPED"}
VALID_PROVENANCE = {"synthetic", "runtime", "static", "derived"}


@dataclass
class ScenarioAssertion:
    """One executable assertion and the evidence supporting its result."""

    name: str
    status: str
    expected: Any = None
    observed: Any = None
    evidence: str = ""
    provenance: str = "synthetic"
    # Runtime provenance of the CREATION SITE (who called add_assertion).
    # Captured at runtime — never guessed via AST.
    creation_file: str = ""
    creation_line: int = 0
    creation_qualname: str = ""

    def __post_init__(self) -> None:
        self.status = str(self.status).upper()
        self.provenance = str(self.provenance).lower()
        if self.status not in VALID_STATUSES:
            raise ValueError(f"Invalid assertion status: {self.status!r}")
        if self.provenance not in VALID_PROVENANCE:
            raise ValueError(f"Invalid assertion provenance: {self.provenance!r}")
        if not self.creation_file:
            self._capture_creation_site()

    def _capture_creation_site(self) -> None:
        """Record the frame that created this assertion, skipping internal plumbing."""
        import inspect
        frame = inspect.currentframe()  # this helper
        try:
            f = frame.f_back  # __post_init__
            while f is not None:
                name = f.f_code.co_name
                # Skip our own plumbing frames only. Validators/executors and GUI
                # callers are all legitimate creation sites.
                if name in {"__post_init__", "__init__", "add_assertion", "_capture_creation_site"}:
                    f = f.f_back
                    continue
                self.creation_file = f.f_code.co_filename
                self.creation_line = f.f_lineno
                # co_qualname gives "Class.method" for methods (py3.11+), plain name otherwise
                self.creation_qualname = getattr(f.f_code, "co_qualname", name)
                return
        finally:
            # Explicitly break frame reference cycles.
            del frame


@dataclass
class ScenarioStage:
    """Evidence for one stage of a multi-stage or ordinary scenario."""

    name: str
    input_hex: str = ""
    output_hex: str = ""
    changed: bool = False
    assertions: List[ScenarioAssertion] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def input_sha256(self) -> str:
        try:
            return hashlib.sha256(bytes.fromhex(self.input_hex)).hexdigest()
        except Exception:
            return ""

    @property
    def output_sha256(self) -> str:
        try:
            return hashlib.sha256(bytes.fromhex(self.output_hex)).hexdigest()
        except Exception:
            return ""


@dataclass
class ScenarioRunContext:
    """Everything an executor needs; built by GUI/CLI callers."""

    raw_hex: str
    raw_bytes: bytes
    cdcvm: bool = True
    brand: str = "UNKNOWN"
    cdol1_hex: str = ""
    cvm_hex: str = ""
    synth_amount: int = 0
    synth_currency: int = 978
    synth_country: int = 250
    seed: Optional[int] = None
    provenance: str = "synthetic"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.provenance = str(self.provenance).lower()
        if self.provenance not in VALID_PROVENANCE:
            raise ValueError(f"Unsupported provenance: {self.provenance!r}")

        if not isinstance(self.raw_bytes, (bytes, bytearray)):
            raise TypeError("raw_bytes must be bytes or bytearray")

        self.raw_bytes = bytes(self.raw_bytes)
        self.raw_hex = _normalize_hex(self.raw_hex)

        if self.raw_hex and self.raw_hex != self.raw_bytes.hex().upper():
            # Keep the bytes authoritative but preserve the mismatch as metadata.
            self.metadata.setdefault("raw_hex_mismatch", True)
        else:
            self.raw_hex = self.raw_bytes.hex().upper()


@dataclass
class ScenarioOutcome:
    """Machine-readable outcome plus legacy GUI-friendly presentation fields."""

    mutated_bytes: bytes = b""
    mutated_flag: bool = False
    steps: List[str] = field(default_factory=list)
    explanation: List[str] = field(default_factory=list)

    status: str = "UNVERIFIED"
    provenance: str = "synthetic"
    assertions: List[ScenarioAssertion] = field(default_factory=list)
    stages: List[ScenarioStage] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    input_sha256: str = ""
    output_sha256: str = ""
    input_length: int = 0
    output_length: int = 0

    def add_assertion(
        self,
        name: str,
        status: str,
        expected: Any = None,
        observed: Any = None,
        evidence: str = "",
        provenance: str = "synthetic",
    ) -> ScenarioAssertion:
        assertion = ScenarioAssertion(
            name=name,
            status=status,
            expected=expected,
            observed=observed,
            evidence=evidence,
            provenance=provenance,
        )
        self.assertions.append(assertion)
        return assertion

    def add_stage(
        self,
        name: str,
        input_bytes: bytes,
        output_bytes: bytes,
        changed: Optional[bool] = None,
        notes: Optional[Sequence[str]] = None,
    ) -> ScenarioStage:
        stage = ScenarioStage(
            name=name,
            input_hex=bytes(input_bytes).hex().upper(),
            output_hex=bytes(output_bytes).hex().upper(),
            changed=(bytes(input_bytes) != bytes(output_bytes))
            if changed is None
            else bool(changed),
            notes=list(notes or ()),
        )
        self.stages.append(stage)
        return stage

    def finalize(
        self,
        input_bytes: bytes,
        *,
        provenance: Optional[str] = None,
    ) -> "ScenarioOutcome":
        """Compute hashes and derive status from executable assertions."""
        raw = bytes(input_bytes)
        out = bytes(self.mutated_bytes or b"")

        self.mutated_bytes = out
        self.input_length = len(raw)
        self.output_length = len(out)
        self.input_sha256 = hashlib.sha256(raw).hexdigest()
        self.output_sha256 = hashlib.sha256(out).hexdigest()
        self.provenance = provenance or self.provenance

        failed = [a for a in self.assertions if a.status == "FAIL"]
        passed = [a for a in self.assertions if a.status == "PASS"]

        if failed:
            self.status = "FAIL"
        elif passed:
            self.status = "PASS"
        else:
            self.status = "UNVERIFIED"

        return self

    def to_dict(self) -> Dict[str, Any]:
        """Return JSON-friendly evidence data."""
        return asdict(self)


Validator = Callable[[ScenarioRunContext, ScenarioOutcome], None]
ScenarioExecutor = Callable[[ScenarioRunContext], ScenarioOutcome]


@dataclass
class MutationScenario:
    key: str
    title: str
    executor: ScenarioExecutor
    preset_apdu: str = ""
    preset_cdol1: str = ""
    preset_cvm: str = ""

    skip_protected_compare: bool = False
    multi_stage_audit: bool = False
    randomizer: Optional[Callable[[], Dict[str, Any]]] = None
    validator: Optional[Validator] = None

    category: str = "mutation"
    fixture_kind: str = "synthetic"
    description: str = ""
    dependencies: Tuple[str, ...] = ()
    protected_tags: Tuple[int, ...] = ()
    expected_change: str = "unspecified"

    def describe(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "category": self.category,
            "fixture_kind": self.fixture_kind,
            "description": self.description,
            "dependencies": list(self.dependencies),
            "protected_tags": [f"0x{tag:X}" for tag in self.protected_tags],
            "expected_change": self.expected_change,
            "has_randomizer": self.randomizer is not None,
            "has_validator": self.validator is not None,
            "skip_protected_compare": self.skip_protected_compare,
            "multi_stage_audit": self.multi_stage_audit,
        }


# ============================================================================
# Generic helpers
# ============================================================================

def _normalize_hex(value: str) -> str:
    """Normalize whitespace/separators and validate even-length hex."""
    cleaned = re.sub(r"[\s:_-]+", "", str(value or "")).upper()
    if not cleaned:
        return ""
    if len(cleaned) % 2:
        raise ValueError(f"Odd-length hexadecimal value: {value!r}")
    if not re.fullmatch(r"[0-9A-F]+", cleaned):
        raise ValueError(f"Invalid hexadecimal value: {value!r}")
    return cleaned


def _sha256(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def _random_bytes(count: int) -> bytes:
    """Lab fixture randomness; intentionally not cryptographic randomness."""
    if count <= 0:
        return b""
    return random.randbytes(count)


def _safe_html(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _assert_bytes_result(
    ctx: ScenarioRunContext,
    out: ScenarioOutcome,
    *,
    expected_mutation: Optional[bool] = None,
) -> None:
    out.add_assertion(
        "output_is_bytes",
        "PASS" if isinstance(out.mutated_bytes, bytes) else "FAIL",
        expected="bytes",
        observed=type(out.mutated_bytes).__name__,
        evidence="Executor returned bytes.",
    )

    if expected_mutation is not None:
        actual = bool(out.mutated_bytes != ctx.raw_bytes)
        out.add_assertion(
            "mutation_flag_matches_bytes_delta",
            "PASS" if actual == bool(out.mutated_flag) else "FAIL",
            expected=bool(out.mutated_flag),
            observed=actual,
            evidence="Compared input and output byte sequences directly.",
        )

        if actual != bool(expected_mutation):
            out.add_assertion(
                "expected_mutation_occurred",
                "FAIL",
                expected=bool(expected_mutation),
                observed=actual,
                evidence="Scenario-level expectation was not met.",
            )
        else:
            out.add_assertion(
                "expected_mutation_occurred",
                "PASS",
                expected=bool(expected_mutation),
                observed=actual,
                evidence="Scenario-level expectation matched the byte delta.",
            )


def _assert_same_length(
    ctx: ScenarioRunContext,
    out: ScenarioOutcome,
    *,
    name: str = "output_length_preserved",
) -> None:
    out.add_assertion(
        name,
        "PASS" if len(out.mutated_bytes) == len(ctx.raw_bytes) else "FAIL",
        expected=len(ctx.raw_bytes),
        observed=len(out.mutated_bytes),
        evidence="Compared input/output byte lengths.",
    )


def _extract_sw(data: bytes) -> bytes:
    return data[-2:] if len(data) >= 2 else b""


def _strip_sw(data: bytes) -> bytes:
    return data[:-2] if len(data) >= 2 else data


def _find_tlv_value(data: bytes, tag: int) -> Optional[bytes]:
    try:
        return tlv.find_tlv(data, tag)
    except Exception:
        return None


def _compare_protected_tags(
    original: bytes,
    mutated: bytes,
    tags: Sequence[int],
) -> List[str]:
    violations: List[str] = []
    for tag in tags:
        orig = _find_tlv_value(original, tag)
        new = _find_tlv_value(mutated, tag)
        if orig is not None and new is not None and orig != new:
            violations.append(f"0x{tag:X}")
    return violations


def _validate_apdu_envelope(
    apdu: bytes,
    *,
    name: str = "APDU envelope",
) -> Tuple[bool, str]:
    if len(apdu) < 4:
        return False, f"{name}: fewer than 4 header bytes"

    # Short APDU with Lc.
    if len(apdu) >= 5:
        lc = apdu[4]
        available = max(0, len(apdu) - 5)
        if lc > available:
            return False, f"{name}: Lc={lc} but only {available} data bytes available"

    return True, f"{name}: basic structural framing is internally consistent"


def _validate_tag91_fixture(data: bytes) -> Tuple[bool, str]:
    ok, message = _validate_apdu_envelope(data, name="Tag 91 test fixture")
    if not ok:
        return False, message

    # For this laboratory fixture we expect GENERATE AC.
    if len(data) >= 2 and data[1] != constants.INS_GENERATE_AC:
        return False, "Tag 91 fixture does not use GENERATE AC INS=0xAE"

    return True, message


# ============================================================================
# Reproducible randomizers
# ============================================================================

_PAN_PREFIXES = ["411111", "510510", "401288", "550000", "378282"]
_CTQ_VARIANTS = [
    b"\x00\x00",
    b"\x80\x00",
    b"\x20\x00",
    b"\x00\x80",
    b"\x40\x00",
]
_TVR_VARIANTS = [
    b"\x80\x00\x80\x00\x00",
    b"\x00\x80\x40\x00\x00",
    b"\x80\x00\x00\x00\x00",
    b"\x00\x00\x80\x00\x00",
    b"\x00\x00\x00\x00\x00",
]
_ARC_VARIANTS = [b"05", b"51", b"01", b"65", b"N7"]


def _rand_pan() -> str:
    rand_prefix = random.choice(_PAN_PREFIXES)
    rand_tail = f"{random.randint(1000000000, 9999999999)}"[:10]
    return (rand_prefix + rand_tail)[:16]


def _rand_basics() -> Dict[str, Any]:
    pan = _rand_pan()
    amount = random.randint(500, 99900)
    return {
        "pan": pan,
        "pan_bytes": bytes.fromhex(pan),
        "atc": random.randint(1, 255).to_bytes(2, "big"),
        "un": _random_bytes(4),
        "amt_minor": amount,
        "amt_bcd": bytes.fromhex(f"{amount:012d}"),
        "ctq": random.choice(_CTQ_VARIANTS),
        "tvr": random.choice(_TVR_VARIANTS),
        "arc": random.choice(_ARC_VARIANTS),
        "arpc_token": _random_bytes(8),
    }


def _pack_result(basics: Dict[str, Any], apdu_hex: str) -> Dict[str, Any]:
    return {
        "apdu": _normalize_hex(apdu_hex),
        "sim_pan": basics["pan"],
        "sim_un": basics["un"].hex().upper(),
    }


def randomize_gpo() -> Dict[str, Any]:
    b = _rand_basics()
    tags = [
        (0x82, random.choice([b"\x38\x00", b"\x18\x00", b"\x39\x00"])),
        (0x94, b"\x08\x01\x01\x00\x10\x01\x02\x00"),
        (0x9F6C, b["ctq"]),
        (0x9F36, b["atc"]),
        (0x5A, b["pan_bytes"]),
        (0x57, b["pan_bytes"] + b"\xD2\x61\x22\x01\x00\x00\x00\x00\x00\x0F"),
    ]
    if random.random() > 0.3:
        tags.append((0x5F28, b"\x08\x40"))
    if random.random() > 0.5:
        tags.append((0x9F10, b"\x06\x01\x0A\x03\x00\x00"))

    inner = b"".join(protocol.build_tlv(tag, value) for tag, value in tags)
    full_apdu = protocol.build_tlv(0x77, inner) + b"\x90\x00"
    return _pack_result(b, full_apdu.hex().upper())


def randomize_read_record() -> Dict[str, Any]:
    b = _rand_basics()
    cvm_rules = random.choice(
        [
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42\x03\x1E\x03\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x03\x1E\x03\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x41\x03\x42\x03\x1F\x03",
        ]
    )
    tags = [
        (0x8E, cvm_rules),
        (0x9F0D, b"\x00\x10\x00\x00\x00"),
        (0x9F0E, b"\x00\x10\x00\x00\x00"),
        (0x9F0F, b"\x00\x10\x00\x00\x00"),
        (0x5A, b["pan_bytes"]),
        (0x5F24, b"\x26\x12\x31"),
        (0x5F34, b"\x01"),
    ]
    if random.random() > 0.4:
        tags.append((0x5F20, b"TEST/CARDHOLDER "))

    inner = b"".join(protocol.build_tlv(tag, value) for tag, value in tags)
    full_apdu = protocol.build_tlv(0x70, inner) + b"\x90\x00"
    return _pack_result(b, full_apdu.hex().upper())


def randomize_generate_ac() -> Dict[str, Any]:
    b = _rand_basics()
    cdol_tags = [
        (0x9F02, b["amt_bcd"]),
        (0x9F03, b"\x00\x00\x00\x00\x00\x00"),
        (0x9F1A, b"\x08\x40"),
        (0x95, b["tvr"]),
        (0x5F2A, b"\x08\x40"),
        (0x9A, b"\x26\x08\x25"),
        (0x9C, b"\x00"),
        (0x9F37, b["un"]),
        (0x9F35, random.choice([b"\x22", b"\x21", b"\x14"])),
        (0x9F34, random.choice([b"\x1E\x03\x00", b"\x1F\x03\x00", b"\x02\x03\x00"])),
    ]
    if random.random() > 0.5:
        cdol_tags.append((0x9F4C, _random_bytes(8)))

    cdol_data = b"".join(
        protocol.build_tlv(tag, value) for tag, value in cdol_tags
    )
    capdu = bytes([0x80, 0xAE, 0x80, 0x00, len(cdol_data)]) + cdol_data + b"\x00"

    # This is intentionally a laboratory schema representation.
    cdol_schema = "".join(f"{tag:X}{len(value):02X}" for tag, value in cdol_tags)
    out = _pack_result(b, capdu.hex().upper())
    out["cdol1"] = cdol_schema.upper()
    return out


def randomize_arpc_ext_auth() -> Dict[str, Any]:
    b = _rand_basics()
    full_apdu = b"\x00\x82\x00\x00\x0A" + b["arpc_token"] + b["arc"]
    return _pack_result(b, full_apdu.hex().upper())


def randomize_arpc_tag91() -> Dict[str, Any]:
    b = _rand_basics()
    tag91_tlv = protocol.build_tlv(0x91, b["arpc_token"] + b["arc"])
    # Build an internally consistent short APDU for the lab fixture.
    payload_len = len(tag91_tlv)
    if payload_len > 0xFF:
        raise ValueError("Synthetic Tag 91 fixture is too large for short APDU encoding")
    capdu = (
        bytes([0x80, 0xAE, 0x40, 0x00, payload_len])
        + tag91_tlv
        + b"\x00"
    )
    return _pack_result(b, capdu.hex().upper())


def randomize_tc_forge() -> Dict[str, Any]:
    b = _rand_basics()
    return _pack_result(b, "80AE400002910000")


def randomize_synthesizer() -> Dict[str, Any]:
    b = _rand_basics()
    out = _pack_result(b, "80A8000002830000")
    out["synth_amount"] = b["amt_minor"]
    return out


@contextlib.contextmanager
def _temporary_seed(seed: Optional[int]) -> Iterator[None]:
    """Temporarily seed Python's lab PRNG without changing caller state."""
    if seed is None:
        yield
        return

    state = random.getstate()
    random.seed(seed)
    try:
        yield
    finally:
        random.setstate(state)


def randomize_scenario(
    key_or_index: Any,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """Run a scenario's randomizer reproducibly when a seed is supplied."""
    scenario = get_scenario(key_or_index)
    if scenario.randomizer is None:
        raise ValueError(f"Scenario {scenario.key!r} has no randomizer")

    with _temporary_seed(seed):
        result = dict(scenario.randomizer())

    result["seed"] = seed
    result["scenario"] = scenario.key
    result["fixture_sha256"] = _sha256(bytes.fromhex(_normalize_hex(result["apdu"])))
    return result


# ============================================================================
# Scenario validators
# ============================================================================

def validate_gpo_ctq_aip(
    ctx: ScenarioRunContext,
    out: ScenarioOutcome,
) -> None:
    original_ctq = _find_tlv_value(_strip_sw(ctx.raw_bytes), 0x9F6C)
    mutated_ctq = _find_tlv_value(_strip_sw(out.mutated_bytes), 0x9F6C)

    original_aip = _find_tlv_value(_strip_sw(ctx.raw_bytes), 0x82)
    mutated_aip = _find_tlv_value(_strip_sw(out.mutated_bytes), 0x82)

    if ctx.cdcvm and original_ctq is not None and len(original_ctq) >= 2:
        if mutated_ctq is None or len(mutated_ctq) < 2:
            out.add_assertion(
                "ctq_present_after_mutation",
                "FAIL",
                expected="2-byte CTQ",
                observed=None,
                evidence="CTQ disappeared after mutation.",
            )
        else:
            expected_ctq0 = original_ctq[0] & 0x7E
            expected_ctq1 = original_ctq[1] | 0x80
            expected = bytes([expected_ctq0, expected_ctq1])
            out.add_assertion(
                "ctq_transformation",
                "PASS" if mutated_ctq == expected else "FAIL",
                expected=expected.hex().upper(),
                observed=mutated_ctq.hex().upper(),
                evidence="Compared CTQ bytes before/after against the mutation contract.",
            )

    if original_aip is not None and len(original_aip) >= 2:
        expected = bytes([original_aip[0] & 0xEF, original_aip[1]])
        out.add_assertion(
            "aip_bit_clear",
            "PASS" if mutated_aip == expected else "FAIL",
            expected=expected.hex().upper(),
            observed=mutated_aip.hex().upper() if mutated_aip is not None else None,
            evidence="Compared AIP value directly against the defined bit-clear transformation.",
        )

    violations = _compare_protected_tags(
        ctx.raw_bytes,
        out.mutated_bytes,
        (0x5A, 0x57, 0x9F36),
    )
    out.add_assertion(
        "protected_fields_unchanged",
        "PASS" if not violations else "FAIL",
        expected="5A, 57, 9F36 unchanged when present",
        observed=violations or "unchanged",
        evidence="Direct TLV value comparison.",
    )


def validate_read_record_cvm(
    ctx: ScenarioRunContext,
    out: ScenarioOutcome,
) -> None:
    expected_cvm = bytes.fromhex("000000000000000000001F031E030000")
    observed_cvm = _find_tlv_value(_strip_sw(out.mutated_bytes), 0x8E)

    out.add_assertion(
        "cvm_list_replaced",
        "PASS" if observed_cvm == expected_cvm else "FAIL",
        expected=expected_cvm.hex().upper(),
        observed=observed_cvm.hex().upper() if observed_cvm else None,
        evidence="Direct comparison of Tag 8E.",
    )

    iac_failures: List[str] = []
    for tag in (0x9F0D, 0x9F0E, 0x9F0F):
        value = _find_tlv_value(_strip_sw(out.mutated_bytes), tag)
        if value is not None and any(value):
            iac_failures.append(f"0x{tag:X}")

    out.add_assertion(
        "iac_values_zeroed",
        "PASS" if not iac_failures else "FAIL",
        expected="9F0D/9F0E/9F0F all zero when present",
        observed=iac_failures or "all zero",
        evidence="Direct TLV value inspection.",
    )

    violations = _compare_protected_tags(
        ctx.raw_bytes,
        out.mutated_bytes,
        (0x5A, 0x5F24, 0x5F34),
    )
    out.add_assertion(
        "record_identity_fields_preserved",
        "PASS" if not violations else "FAIL",
        expected="5A, 5F24, 5F34 unchanged when present",
        observed=violations or "unchanged",
        evidence="Direct TLV value comparison.",
    )


def validate_generate_ac_tvr(
    ctx: ScenarioRunContext,
    out: ScenarioOutcome,
) -> None:
    _assert_same_length(ctx, out)

    def _find_tvr(capdu: bytes) -> Optional[bytes]:
        if len(capdu) < 5:
            return None
        lc = capdu[4]
        data = capdu[5 : 5 + lc]
        return _find_tlv_value(data, 0x95)

    original_tvr = _find_tvr(ctx.raw_bytes)
    mutated_tvr = _find_tvr(out.mutated_bytes)

    if original_tvr is None:
        out.add_assertion(
            "tvr_fixture_present",
            "UNVERIFIED",
            expected="Tag 95 present in fixture",
            observed=None,
            evidence="No Tag 95 value was discoverable in the input.",
        )
        return

    if mutated_tvr is None or len(mutated_tvr) != len(original_tvr):
        out.add_assertion(
            "tvr_preserved_shape",
            "FAIL",
            expected=len(original_tvr),
            observed=len(mutated_tvr) if mutated_tvr is not None else None,
            evidence="Output Tag 95 missing or wrong length.",
        )
        return

    expected = bytearray(original_tvr)
    expected[0] &= ~0x80
    expected[2] &= ~0x80
    expected[2] &= ~0x40
    expected = bytes(expected)

    out.add_assertion(
        "tvr_bit_clear",
        "PASS" if mutated_tvr == expected else "FAIL",
        expected=expected.hex().upper(),
        observed=mutated_tvr.hex().upper(),
        evidence="Direct byte-wise comparison against the mutation contract.",
    )


def validate_arpc_ext_auth(
    ctx: ScenarioRunContext,
    out: ScenarioOutcome,
) -> None:
    if len(ctx.raw_bytes) < 15:
        out.add_assertion(
            "fixture_minimum_length",
            "FAIL",
            expected=15,
            observed=len(ctx.raw_bytes),
            evidence="EXTERNAL AUTH fixture is too short for the configured positional layout.",
        )
        return

    expected_arc = mutations.ARC_REWRITE_MAP.get(ctx.raw_bytes[13:15])

    # The executor itself determines the supported mapping. We only verify that
    # the reported transformation is internally consistent.
    if expected_arc is not None:
        actual_arc = out.mutated_bytes[13:15] if len(out.mutated_bytes) >= 15 else None
        out.add_assertion(
            "arc_mapping_applied",
            "PASS" if actual_arc == expected_arc else "FAIL",
            expected=expected_arc.hex().upper(),
            observed=actual_arc.hex().upper() if actual_arc else None,
            evidence="Compared the configured ARC mapping at the executor's documented offset.",
        )
    else:
        out.add_assertion(
            "arc_mapping_applicable",
            "UNVERIFIED",
            expected="fixture ARC appears in configured rewrite map",
            observed=ctx.raw_bytes[13:15].hex().upper(),
            evidence="No configured mapping applies to this randomized ARC value.",
        )

    _assert_same_length(ctx, out)


def validate_arpc_tag91(
    ctx: ScenarioRunContext,
    out: ScenarioOutcome,
) -> None:
    ok, reason = _validate_tag91_fixture(ctx.raw_bytes)
    out.add_assertion(
        "fixture_structure",
        "PASS" if ok else "FAIL",
        expected="internally consistent GENERATE AC fixture",
        observed=reason,
        evidence="Validated short-APDU Lc framing before mutation.",
    )

    if not ok:
        return

    tag91_before = _find_tlv_value(ctx.raw_bytes[5 : 5 + ctx.raw_bytes[4]], 0x91)
    tag91_after = _find_tlv_value(out.mutated_bytes[5 : 5 + out.mutated_bytes[4]], 0x91)

    if tag91_before is None or len(tag91_before) < 10:
        out.add_assertion(
            "tag91_payload_available",
            "FAIL",
            expected="Tag 91 with at least 10 payload bytes",
            observed=tag91_before.hex().upper() if tag91_before else None,
            evidence="Tag 91 does not contain the expected fixture payload.",
        )
        return

    if tag91_after is None or len(tag91_after) < 10:
        out.add_assertion(
            "tag91_survives_rewrite",
            "FAIL",
            expected="Tag 91 retained",
            observed=None,
            evidence="Tag 91 disappeared after rewrite.",
        )
        return

    expected = bytearray(tag91_before)
    mapped = mutations.ARC_REWRITE_MAP.get(bytes(expected[8:10]))
    if mapped is None:
        out.add_assertion(
            "tag91_arc_mapping_available",
            "UNVERIFIED",
            expected="configured ARC mapping",
            observed=bytes(expected[8:10]).hex().upper(),
            evidence="Fixture ARC is not in the configured rewrite map.",
        )
        return

    expected[8:10] = mapped
    out.add_assertion(
        "tag91_arc_rewrite",
        "PASS" if tag91_after == bytes(expected) else "FAIL",
        expected=bytes(expected).hex().upper(),
        observed=tag91_after.hex().upper(),
        evidence="Direct comparison of the complete Tag 91 payload.",
    )


def validate_forge(
    ctx: ScenarioRunContext,
    out: ScenarioOutcome,
) -> None:
    data = _strip_sw(out.mutated_bytes)
    status = _extract_sw(out.mutated_bytes)

    out.add_assertion(
        "response_status_9000",
        "PASS" if status == b"\x90\x00" else "FAIL",
        expected="9000",
        observed=status.hex().upper(),
        evidence="Inspected final two bytes of the synthetic response.",
    )

    template = data[:1] if data else b""
    if template not in (bytes([constants.TEMPLATE_77]), bytes([constants.TEMPLATE_80])):
        out.add_assertion(
            "recognized_response_template",
            "FAIL",
            expected="77 or 80",
            observed=template.hex().upper() if template else None,
            evidence="Inspected response template byte.",
        )
        return

    out.add_assertion(
        "recognized_response_template",
        "PASS",
        expected="77 or 80",
        observed=template.hex().upper(),
        evidence="Inspected response template byte.",
    )

    if template == bytes([constants.TEMPLATE_77]):
        for tag in (0x9F27, 0x9F36, 0x9F26, 0x9F10):
            value = _find_tlv_value(data, tag)
            out.add_assertion(
                f"template77_contains_{tag:X}",
                "PASS" if value is not None else "FAIL",
                expected=f"Tag 0x{tag:X} present",
                observed=value.hex().upper() if value else None,
                evidence="Direct TLV lookup.",
            )
    else:
        out.add_assertion(
            "template80_payload_nonempty",
            "PASS" if len(data) > 2 else "FAIL",
            expected="payload present",
            observed=len(data),
            evidence="Template 80 payload length was inspected.",
        )


def validate_universal_gac(
    ctx: ScenarioRunContext,
    out: ScenarioOutcome,
) -> None:
    _assert_same_length(ctx, out)

    ok_before, msg_before = _validate_apdu_envelope(ctx.raw_bytes, name="input GENERATE AC")
    ok_after, msg_after = _validate_apdu_envelope(out.mutated_bytes, name="output GENERATE AC")

    out.add_assertion(
        "input_apdu_structure",
        "PASS" if ok_before else "FAIL",
        expected="internally consistent short APDU framing",
        observed=msg_before,
        evidence="Checked input CLA/INS/Lc framing.",
    )
    out.add_assertion(
        "output_apdu_structure",
        "PASS" if ok_after else "FAIL",
        expected="internally consistent short APDU framing",
        observed=msg_after,
        evidence="Checked output CLA/INS/Lc framing.",
    )


def validate_synth_fields(
    ctx: ScenarioRunContext,
    out: ScenarioOutcome,
) -> None:
    out.add_assertion(
        "synthesizer_returned_bytes",
        "PASS" if isinstance(out.mutated_bytes, bytes) else "FAIL",
        expected="bytes",
        observed=type(out.mutated_bytes).__name__,
        evidence="Direct return-type check.",
    )


def validate_custom(
    ctx: ScenarioRunContext,
    out: ScenarioOutcome,
) -> None:
    if len(ctx.raw_bytes) >= 2 and ctx.raw_bytes[1] == constants.INS_GENERATE_AC:
        _assert_same_length(ctx, out)
    else:
        out.add_assertion(
            "custom_input_classification",
            "PASS",
            expected="non-GENERATE-AC input routed to GPO transformation",
            observed="GPO path",
            evidence="Inspected instruction byte in the supplied fixture.",
        )


# ============================================================================
# Scenario executors
# ============================================================================

def exec_gpo_ctq_aip(ctx: ScenarioRunContext) -> ScenarioOutcome:
    out = ScenarioOutcome(provenance=ctx.provenance)

    body = _strip_sw(ctx.raw_bytes)
    ctq = _find_tlv_value(body, 0x9F6C)
    aip = _find_tlv_value(body, 0x82)

    out.steps.append(
        "<b>[STEP 1: INPUT]</b> Synthetic GPO RAPDU received: "
        + f"<code>{_safe_html(ctx.raw_hex)}</code>"
    )
    out.steps.append(
        f"<b>[STEP 2: TLV INSPECTION]</b> AIP: "
        f"<code>{aip.hex().upper() if aip else 'None'}</code> | "
        f"CTQ: <code>{ctq.hex().upper() if ctq else 'None'}</code>"
    )
    out.steps.append(
        "<b>[STEP 3: EXECUTION]</b> Running "
        f"<code>mutations.mutate_gpo_response(..., cdcvm_verified={ctx.cdcvm})</code>"
    )

    mutated, ok = mutations.mutate_gpo_response(
        ctx.raw_bytes,
        cdcvm_verified=ctx.cdcvm,
    )
    out.mutated_bytes = bytes(mutated or b"")
    out.mutated_flag = out.mutated_bytes != ctx.raw_bytes

    out.steps.append(
        f"<b>[STEP 4: RESULT]</b> Executor status: "
        f"{'success' if ok else 'failure'} | changed={out.mutated_flag}"
    )

    out.explanation.append("<h3>GPO laboratory mutation</h3>")
    out.explanation.append(
        "<p>Executable assertions below determine which transformations actually "
        "occurred. Presentation text is not itself evidence.</p>"
    )

    return out


def exec_read_record_cvm(ctx: ScenarioRunContext) -> ScenarioOutcome:
    out = ScenarioOutcome(provenance=ctx.provenance)
    out.steps.append(
        "<b>[STEP 1: INPUT]</b> Synthetic READ RECORD response supplied."
    )
    out.steps.append(
        "<b>[STEP 2: EXECUTION]</b> Running "
        "<code>mutations.mutate_read_record_response()</code>"
    )

    out.mutated_bytes = bytes(mutations.mutate_read_record_response(ctx.raw_bytes))
    out.mutated_flag = out.mutated_bytes != ctx.raw_bytes

    out.steps.append(
        f"<b>[STEP 3: RESULT]</b> changed={out.mutated_flag} | "
        f"output={len(out.mutated_bytes)} bytes"
    )

    out.explanation.append("<h3>READ RECORD laboratory mutation</h3>")
    return out


def exec_generate_ac_tvr(ctx: ScenarioRunContext) -> ScenarioOutcome:
    out = ScenarioOutcome(provenance=ctx.provenance)
    out.steps.append(
        "<b>[STEP 1: INPUT]</b> Synthetic GENERATE AC CAPDU supplied."
    )
    out.steps.append(
        "<b>[STEP 2: EXECUTION]</b> Running "
        "<code>mutations.mutate_tvr_in_generate_ac()</code>"
    )

    out.mutated_bytes, note = mutations.mutate_tvr_in_generate_ac_capdu(ctx.raw_bytes)
    out.mutated_bytes = bytes(out.mutated_bytes or b"")
    out.mutated_flag = out.mutated_bytes != ctx.raw_bytes

    out.steps.append(
        f"<b>[STEP 3: RESULT]</b> { _safe_html(note or 'No transformation reported') }"
    )

    out.explanation.append("<h3>TVR laboratory transformation</h3>")
    return out


def exec_arpc_ext_auth(ctx: ScenarioRunContext) -> ScenarioOutcome:
    out = ScenarioOutcome(provenance=ctx.provenance)
    out.steps.append(
        "<b>[STEP 1: INPUT]</b> Synthetic EXTERNAL AUTHENTICATE fixture supplied."
    )
    out.steps.append(
        "<b>[STEP 2: EXECUTION]</b> Running "
        "<code>mutations.rewrite_arpc_in_capdu()</code>"
    )

    out.mutated_bytes, note = mutations.rewrite_arpc_in_capdu(ctx.raw_bytes)
    out.mutated_bytes = bytes(out.mutated_bytes or b"")
    out.mutated_flag = out.mutated_bytes != ctx.raw_bytes

    out.steps.append(
        f"<b>[STEP 3: RESULT]</b> {_safe_html(note or 'No configured ARC rewrite applied')}"
    )
    out.explanation.append("<h3>ARC rewrite laboratory test</h3>")
    return out


def exec_arpc_tag91(ctx: ScenarioRunContext) -> ScenarioOutcome:
    out = ScenarioOutcome(provenance=ctx.provenance)
    out.steps.append(
        "<b>[STEP 1: INPUT]</b> Synthetic GENERATE AC + Tag 91 fixture supplied."
    )
    out.steps.append(
        "<b>[STEP 2: EXECUTION]</b> Running "
        "<code>mutations.rewrite_arpc_in_capdu()</code>"
    )

    out.mutated_bytes, note = mutations.rewrite_arpc_in_capdu(ctx.raw_bytes)
    out.mutated_bytes = bytes(out.mutated_bytes or b"")
    out.mutated_flag = out.mutated_bytes != ctx.raw_bytes

    out.steps.append(
        f"<b>[STEP 3: RESULT]</b> {_safe_html(note or 'No configured Tag 91 ARC rewrite applied')}"
    )
    out.explanation.append("<h3>Tag 91 laboratory test</h3>")
    return out


def _synthetic_arqc_cache(
    *,
    template: int,
    atc: bytes,
    ac: bytes,
    iad: bytes,
) -> Any:
    return emv.ArqcCache(
        cid=constants.CID_ARQC,
        atc=atc,
        ac=ac,
        iad=iad,
        template=template,
    )


def exec_forge_template_77(ctx: ScenarioRunContext) -> ScenarioOutcome:
    out = ScenarioOutcome(provenance=ctx.provenance)
    cache = _synthetic_arqc_cache(
        template=constants.TEMPLATE_77,
        atc=bytes.fromhex("0012"),
        ac=bytes.fromhex("1122334455667788"),
        iad=bytes.fromhex("06010A030000"),
    )

    out.steps.append(
        "<b>[STEP 1: SYNTHETIC CACHE]</b> "
        f"template=0x{constants.TEMPLATE_77:02X}, "
        f"ATC={cache.atc.hex().upper()}, AC={cache.ac.hex().upper()}, "
        f"IAD={cache.iad.hex().upper()}"
    )
    out.steps.append(
        "<b>[STEP 2: EXECUTION]</b> Running "
        "<code>mutations.forge_2nd_gac(cache, forced_cid=CID_TC)</code>"
    )

    out.mutated_bytes = bytes(
        mutations.forge_2nd_gac(
            cache,
            forced_cid=constants.CID_TC,
            brand=ctx.brand,
        )
        or b""
    )
    out.mutated_flag = True

    out.steps.append(
        f"<b>[STEP 3: RESULT]</b> "
        f"<code>{out.mutated_bytes.hex().upper()}</code>"
    )
    out.explanation.append(
        "<h3>Template 77 synthetic construction</h3>"
        "<p>This scenario verifies deterministic construction from a synthetic "
        "cache object. It does not claim provenance from a live session.</p>"
    )
    return out


def exec_forge_template_80(ctx: ScenarioRunContext) -> ScenarioOutcome:
    out = ScenarioOutcome(provenance=ctx.provenance)
    cache = _synthetic_arqc_cache(
        template=constants.TEMPLATE_80,
        atc=bytes.fromhex("0025"),
        ac=bytes.fromhex("AABBCCDDEEFF0011"),
        iad=bytes.fromhex("060112030000"),
    )

    out.steps.append(
        "<b>[STEP 1: SYNTHETIC CACHE]</b> "
        f"template=0x{constants.TEMPLATE_80:02X}, "
        f"ATC={cache.atc.hex().upper()}, AC={cache.ac.hex().upper()}, "
        f"IAD={cache.iad.hex().upper()}"
    )
    out.steps.append(
        "<b>[STEP 2: EXECUTION]</b> Running "
        "<code>mutations.forge_2nd_gac_template_80(cache, forced_cid=CID_TC)</code>"
    )

    out.mutated_bytes = bytes(
        mutations.forge_2nd_gac_template_80(
            cache,
            forced_cid=constants.CID_TC,
            brand=ctx.brand,
        )
        or b""
    )
    out.mutated_flag = True

    out.steps.append(
        f"<b>[STEP 3: RESULT]</b> "
        f"<code>{out.mutated_bytes.hex().upper()}</code>"
    )
    out.explanation.append("<h3>Template 80 synthetic construction</h3>")
    return out


def exec_universal_gac(ctx: ScenarioRunContext) -> ScenarioOutcome:
    out = ScenarioOutcome(provenance=ctx.provenance)
    out.steps.append(
        "<b>[STEP 1: INPUT]</b> Synthetic GENERATE AC CAPDU supplied."
    )

    cdol1_text = _normalize_hex(
        ctx.cdol1_hex or "9F02069F03069F1A0295055F2A029A039C019F37049F35019F3403"
    )
    cvm_text = _normalize_hex(
        ctx.cvm_hex or "000000000000000000001F031E030000"
    )

    cdol_entries = mutations.parse_cdol1(bytes.fromhex(cdol1_text))
    cvm_entries = mutations.parse_cvm_list(bytes.fromhex(cvm_text))

    out.steps.append(
        f"<b>[STEP 2: SCHEMA]</b> Parsed {len(cdol_entries)} CDOL1 entries and "
        f"{len(cvm_entries)} CVM rules."
    )

    out.mutated_bytes, patch_notes = mutations.patch_generate_ac_universal(
        ctx.raw_bytes,
        cdol_entries,
        cvm_entries,
    )
    out.mutated_bytes = bytes(out.mutated_bytes or b"")
    out.mutated_flag = out.mutated_bytes != ctx.raw_bytes

    out.steps.append(
        f"<b>[STEP 3: RESULT]</b> {_safe_html(patch_notes)} | "
        f"changed={out.mutated_flag}"
    )

    out.explanation.append("<h3>Universal GENERATE AC laboratory patch</h3>")
    return out


def exec_synth_fields(ctx: ScenarioRunContext) -> ScenarioOutcome:
    out = ScenarioOutcome(provenance=ctx.provenance)

    out.steps.append(
        "<b>[STEP 1: EXECUTION]</b> Calling "
        "<code>mod_emv_synthesizer.EmvSynthesizer.process_apdu()</code>"
    )

    synth = mod_emv_synthesizer.EmvSynthesizer(
        amount=ctx.synth_amount,
        currency_code=ctx.synth_currency,
        country_code=ctx.synth_country,
    )
    out.mutated_bytes, out.mutated_flag = synth.process_apdu(
        ctx.raw_bytes,
        is_card_to_reader=True,
    )
    out.mutated_bytes = bytes(out.mutated_bytes or b"")

    out.steps.append(
        f"<b>[STEP 2: RESULT]</b> changed={out.mutated_flag} | "
        f"output={out.mutated_bytes.hex().upper()}"
    )
    out.explanation.append("<h3>Synthesizer laboratory test</h3>")
    return out


def exec_full_pipeline(ctx: ScenarioRunContext) -> ScenarioOutcome:
    out = ScenarioOutcome(
        provenance=ctx.provenance,
        metadata={"pipeline_mode": "synthetic_staged"},
    )

    # Stage 1 — starts from the caller's GPO fixture.
    out.steps.append(
        "<b>[STAGE 1: GPO]</b> Running synthetic GPO transformation..."
    )
    gpo_out, gpo_ok = mutations.mutate_gpo_response(
        ctx.raw_bytes,
        cdcvm_verified=ctx.cdcvm,
    )
    gpo_out = bytes(gpo_out or b"")
    out.add_stage("GPO", ctx.raw_bytes, gpo_out, notes=[f"executor_ok={gpo_ok}"])

    # Stage 2 — explicit synthetic fixture; deliberately recorded as independent
    # unless metadata says otherwise.
    rec_in = bytes.fromhex(
        "703E8E10000000000000000042031F031E030000"
        "9F0D0500100000009F0E0500100000009F0F050010000000"
        "5A0841111111111111115F24032612315F3401019000"
    )
    rec_out = bytes(mutations.mutate_read_record_response(rec_in))
    out.add_stage("READ_RECORD", rec_in, rec_out)

    # Stage 3 — explicit synthetic GENERATE AC fixture.
    gac_in = bytes.fromhex(
        "80AE80003C9F02060000000025009F03060000000000009F1A020840"
        "950580008000005F2A0208409A032608259C01009F370411223344"
        "9F3501229F34031E030000"
    )
    gac_out, gac_note = mutations.mutate_tvr_in_generate_ac(gac_in)
    gac_out = bytes(gac_out or b"")
    out.add_stage("FIRST_GAC", gac_in, gac_out, notes=[gac_note or ""])

    # Stage 4 — explicit synthetic EXTERNAL AUTH fixture.
    arpc_in = bytes.fromhex("008200000A11223344556677883035")
    arpc_out, arpc_note = mutations.rewrite_arpc_in_capdu(arpc_in)
    arpc_out = bytes(arpc_out or b"")
    out.add_stage("ARC_REWRITE", arpc_in, arpc_out, notes=[arpc_note or ""])

    # Stage 5 — explicit synthetic cache fixture.
    cache = _synthetic_arqc_cache(
        template=constants.TEMPLATE_77,
        atc=b"\x00\x05",
        ac=b"\x41\x42\x43\x44\x45\x46\x47\x48",
        iad=b"\x06\x01\x0A\x03\x00\x00",
    )
    final_out = bytes(
        mutations.forge_2nd_gac(
            cache,
            forced_cid=constants.CID_TC,
            brand=ctx.brand,
        )
        or b""
    )
    out.add_stage(
        "SECOND_GAC_FORGE",
        b"",
        final_out,
        notes=[
            "cache_provenance=synthetic",
            f"template=0x{cache.template:02X}",
            f"atc={cache.atc.hex().upper()}",
            f"ac={cache.ac.hex().upper()}",
        ],
    )

    out.mutated_bytes = final_out
    out.mutated_flag = True

    out.steps.extend(
        [
            f" -> Stage 1 Output: <code>{gpo_out.hex().upper()}</code>",
            f" -> Stage 2 Output: <code>{rec_out.hex().upper()}</code>",
            f" -> Stage 3 Output: <code>{gac_out.hex().upper()}</code>",
            f" -> Stage 4 Output: <code>{arpc_out.hex().upper()}</code>",
            f" -> Stage 5 Output: <code>{final_out.hex().upper()}</code>",
        ]
    )

    out.explanation.append(
        "<h3>Synthetic multi-stage laboratory pipeline</h3>"
        "<p>Each stage records its own input/output provenance. Stages 2–5 "
        "are explicit synthetic fixtures and are not silently presented as "
        "one continuous live session.</p>"
    )
    return out


def exec_custom(ctx: ScenarioRunContext) -> ScenarioOutcome:
    out = ScenarioOutcome(provenance=ctx.provenance)

    if len(ctx.raw_bytes) >= 2 and ctx.raw_bytes[1] == constants.INS_GENERATE_AC:
        out.mutated_bytes, note = mutations.mutate_tvr_in_generate_ac_capdu(ctx.raw_bytes)
        out.mutated_bytes = bytes(out.mutated_bytes or b"")
        out.steps.append(
            f"<b>[CUSTOM]</b> GENERATE AC path: {_safe_html(note or 'no transformation')}"
        )
    else:
        out.mutated_bytes, ok = mutations.mutate_gpo_response(
            ctx.raw_bytes,
            cdcvm_verified=ctx.cdcvm,
        )
        out.mutated_bytes = bytes(out.mutated_bytes or b"")
        out.steps.append(
            f"<b>[CUSTOM]</b> GPO path: executor_ok={ok}"
        )

    out.mutated_flag = out.mutated_bytes != ctx.raw_bytes
    out.explanation.append(
        "<h3>Custom laboratory execution</h3>"
        "<p>The selected deterministic path is derived from the supplied "
        "instruction byte.</p>"
    )
    return out


# ============================================================================
# Scenario definitions
# ============================================================================

def _scenario(
    *,
    key: str,
    title: str,
    executor: ScenarioExecutor,
    preset_apdu: str,
    randomizer: Optional[Callable[[], Dict[str, Any]]] = None,
    validator: Optional[Validator] = None,
    preset_cdol1: str = "",
    preset_cvm: str = "",
    skip_protected_compare: bool = False,
    multi_stage_audit: bool = False,
    category: str = "mutation",
    fixture_kind: str = "synthetic",
    description: str = "",
    dependencies: Sequence[str] = (),
    protected_tags: Sequence[int] = (),
    expected_change: str = "unspecified",
) -> MutationScenario:
    return MutationScenario(
        key=key,
        title=title,
        executor=executor,
        preset_apdu=_normalize_hex(preset_apdu),
        preset_cdol1=_normalize_hex(preset_cdol1) if preset_cdol1 else "",
        preset_cvm=_normalize_hex(preset_cvm) if preset_cvm else "",
        randomizer=randomizer,
        validator=validator,
        skip_protected_compare=skip_protected_compare,
        multi_stage_audit=multi_stage_audit,
        category=category,
        fixture_kind=fixture_kind,
        description=description,
        dependencies=tuple(dependencies),
        protected_tags=tuple(protected_tags),
        expected_change=expected_change,
    )


_MUTATION_SCENARIOS: List[MutationScenario] = [
    _scenario(
        key="gpo_ctq_aip",
        title="1. GPO Response: CTQ (9F6C) & AIP (82) transformation",
        executor=exec_gpo_ctq_aip,
        preset_apdu=(
            "773B82023800940808010100100102009F6C0200005F280208409F3602001A"
            "57124111111111111111D261220100000000000F5A0841111111111111119000"
        ),
        preset_cdol1="9F02069F03069F1A0295055F2A029A039C019F37049F35019F3403",
        preset_cvm="000000000000000000001E031F030000",
        randomizer=randomize_gpo,
        validator=validate_gpo_ctq_aip,
        description="Exercises the GPO mutation function against a synthetic Template 77 fixture.",
        dependencies=("mutations.mutate_gpo_response", "tlv.find_tlv"),
        protected_tags=(0x5A, 0x57, 0x9F36),
        expected_change="AIP/CTQ may change; protected identity fields must remain unchanged.",
    ),
    _scenario(
        key="read_record_cvm",
        title="2. READ RECORD: CVM List (8E) and IAC transformation",
        executor=exec_read_record_cvm,
        preset_apdu=(
            "703E8E10000000000000000042031F031E030000"
            "9F0D0500100000009F0E0500100000009F0F050010000000"
            "5A0841111111111111115F24032612315F3401019000"
        ),
        randomizer=randomize_read_record,
        validator=validate_read_record_cvm,
        description="Verifies CVM/IAC transformations while preserving selected record identity fields.",
        dependencies=("mutations.mutate_read_record_response", "tlv.find_tlv"),
        protected_tags=(0x5A, 0x5F24, 0x5F34),
        expected_change="Tag 8E/IAC fields change when present; selected identity fields remain unchanged.",
    ),
    _scenario(
        key="generate_ac_tvr",
        title="3. GENERATE AC: TVR (95) bit transformation",
        executor=exec_generate_ac_tvr,
        preset_apdu=(
            "80AE80003C9F02060000000025009F03060000000000009F1A020840"
            "950580008000005F2A0208409A032608259C01009F370411223344"
            "9F3501229F34031E030000"
        ),
        randomizer=randomize_generate_ac,
        validator=validate_generate_ac_tvr,
        description="Verifies the exact TVR bit-clearing transformation used by the deterministic mutation function.",
        dependencies=("mutations.mutate_tvr_in_generate_ac",),
        expected_change="Only the defined TVR bits should be cleared.",
    ),
    _scenario(
        key="arpc_ext_auth",
        title="4. EXTERNAL AUTHENTICATE: ARC rewrite fixture",
        executor=exec_arpc_ext_auth,
        preset_apdu="008200000A11223344556677883035",
        randomizer=randomize_arpc_ext_auth,
        validator=validate_arpc_ext_auth,
        description="Tests the configured positional ARC rewrite path using synthetic EXTERNAL AUTH data.",
        dependencies=("mutations.rewrite_arpc_in_capdu",),
        expected_change="Configured ARC values may be rewritten.",
    ),
    _scenario(
        key="arpc_tag91",
        title="5. GENERATE AC + Tag 91: ARC rewrite fixture",
        executor=exec_arpc_tag91,
        # Corrected from the earlier malformed 0x12 Lc fixture.
        preset_apdu="80AE40000C910A1122334455667788353100",
        randomizer=randomize_arpc_tag91,
        validator=validate_arpc_tag91,
        description="Tests Tag 91 detection and ARC rewrite with an internally consistent synthetic APDU.",
        dependencies=("mutations.rewrite_arpc_in_capdu", "tlv.find_tlv"),
        expected_change="Tag 91 ARC bytes may change when the configured mapping applies.",
    ),
    _scenario(
        key="forge_template_77",
        title="6. Synthetic 2nd-GAC construction: Template 77",
        executor=exec_forge_template_77,
        preset_apdu="80AE400002910000",
        skip_protected_compare=True,
        randomizer=randomize_tc_forge,
        validator=validate_forge,
        category="construction",
        description="Constructs a deterministic synthetic Template 77 response from a synthetic cache.",
        dependencies=("emv.ArqcCache", "mutations.forge_2nd_gac"),
        expected_change="Build a new synthetic response from an explicit synthetic cache.",
    ),
    _scenario(
        key="forge_template_80",
        title="7. Synthetic 2nd-GAC construction: Template 80",
        executor=exec_forge_template_80,
        preset_apdu="80AE400000",
        skip_protected_compare=True,
        randomizer=randomize_tc_forge,
        validator=validate_forge,
        category="construction",
        description="Constructs a deterministic synthetic Template 80 response from a synthetic cache.",
        dependencies=("emv.ArqcCache", "mutations.forge_2nd_gac_template_80"),
        expected_change="Build a new synthetic response from an explicit synthetic cache.",
    ),
    _scenario(
        key="universal_gac",
        title="8. GENERATE AC: Universal dynamic patcher",
        executor=exec_universal_gac,
        preset_apdu=(
            "80AE80003C9F02060000000050009F03060000000000009F1A020840"
            "950580800000005F2A0208409A032608259C01009F3704A1B2C3D4"
            "9F3501229F34031F030000"
        ),
        preset_cdol1="9F02069F03069F1A0295055F2A029A039C019F37049F35019F3403",
        preset_cvm="000000000000000000001F031E030000",
        randomizer=randomize_generate_ac,
        validator=validate_universal_gac,
        description="Exercises CDOL1/CVM parsing plus deterministic GENERATE AC patching.",
        dependencies=("mutations.parse_cdol1", "mutations.parse_cvm_list", "mutations.patch_generate_ac_universal"),
        expected_change="Output remains structurally consistent and preserves input length.",
    ),
    _scenario(
        key="synth_fields",
        title="9. Synthetic EMV field synthesizer",
        executor=exec_synth_fields,
        preset_apdu="80A8000002830000",
        randomizer=randomize_synthesizer,
        validator=validate_synth_fields,
        category="synthesis",
        description="Exercises the deterministic synthesizer API with synthetic terminal values.",
        dependencies=("mod_emv_synthesizer.EmvSynthesizer",),
        expected_change="Synthesizer returns a bytes result for the supplied fixture.",
    ),
    _scenario(
        key="full_pipeline",
        title="10. Synthetic multi-stage laboratory scenario suite",
        executor=exec_full_pipeline,
        preset_apdu=(
            "773B82023800940808010100100102009F6C0200005F280208409F3602001A"
            "57124111111111111111D261220100000000000F5A0841111111111111119000"
        ),
        multi_stage_audit=True,
        randomizer=randomize_gpo,
        validator=lambda ctx, out: (
            out.add_assertion(
                "all_pipeline_stages_recorded",
                "PASS" if len(out.stages) == 5 else "FAIL",
                expected=5,
                observed=len(out.stages),
                evidence="Pipeline executor recorded exactly five stage objects.",
            ),
            out.add_assertion(
                "pipeline_provenance_declared",
                "PASS"
                if all(
                    "cache_provenance=synthetic" in " ".join(stage.notes)
                    for stage in out.stages
                    if stage.name == "SECOND_GAC_FORGE"
                )
                else "FAIL",
                expected="SECOND_GAC cache explicitly synthetic",
                observed="synthetic" if any(
                    "cache_provenance=synthetic" in " ".join(stage.notes)
                    for stage in out.stages
                    if stage.name == "SECOND_GAC_FORGE"
                ) else None,
                evidence="Checked stage metadata instead of inferring provenance from prose.",
            )
        ),
        category="pipeline",
        description="Runs five deliberately recorded synthetic stages; later stages identify independent fixture provenance.",
        dependencies=(
            "mutations.mutate_gpo_response",
            "mutations.mutate_read_record_response",
            "mutations.mutate_tvr_in_generate_ac",
            "mutations.rewrite_arpc_in_capdu",
            "mutations.forge_2nd_gac",
        ),
        expected_change="Each stage records its own result and provenance.",
    ),
    _scenario(
        key="custom",
        title="11. Custom synthetic APDU / TLV transformation",
        executor=exec_custom,
        preset_apdu=(
            "80AE80003C9F02060000000010009F03060000000000009F1A020840"
            "950580008000005F2A0208409A032608259C01009F370411223344"
            "9F3501229F34031E030000"
        ),
        randomizer=randomize_generate_ac,
        validator=validate_custom,
        category="custom",
        description="Routes a supplied synthetic input through one of the deterministic mutation paths.",
        dependencies=("mutations.mutate_gpo_response", "mutations.mutate_tvr_in_generate_ac"),
        expected_change="Path chosen from the supplied instruction byte.",
    ),
]


# ============================================================================
# Public registry API
# ============================================================================

def get_scenarios() -> List[MutationScenario]:
    """Return the ordered scenario registry."""
    return list(_MUTATION_SCENARIOS)


MUTATION_SCENARIOS: List[MutationScenario] = _MUTATION_SCENARIOS


def get_scenario(key_or_index: Any) -> MutationScenario:
    """Lookup by registry key or zero-based combo-box index."""
    if isinstance(key_or_index, int):
        return _MUTATION_SCENARIOS[key_or_index]

    key = str(key_or_index)
    for scenario in _MUTATION_SCENARIOS:
        if scenario.key == key:
            return scenario

    raise KeyError(f"Unknown mutation scenario: {key_or_index!r}")


def run_scenario(
    key_or_index: Any,
    ctx: ScenarioRunContext,
) -> ScenarioOutcome:
    """Run one scenario and apply its executable validator."""
    scenario = get_scenario(key_or_index)

    if not isinstance(ctx, ScenarioRunContext):
        raise TypeError("ctx must be ScenarioRunContext")

    outcome = scenario.executor(ctx)
    if not isinstance(outcome, ScenarioOutcome):
        raise TypeError(
            f"Scenario {scenario.key!r} returned "
            f"{type(outcome).__name__}, expected ScenarioOutcome"
        )

    outcome.mutated_bytes = bytes(outcome.mutated_bytes or b"")
    outcome.mutated_flag = outcome.mutated_bytes != ctx.raw_bytes

    _assert_bytes_result(
        ctx,
        outcome,
        expected_mutation=None,
    )

    # Apply scenario-specific executable oracle.
    if scenario.validator is not None:
        scenario.validator(ctx, outcome)

    # Common evidence fields after all assertions.
    outcome.finalize(ctx.raw_bytes, provenance=ctx.provenance)
    outcome.metadata.setdefault("scenario", scenario.key)
    outcome.metadata.setdefault("title", scenario.title)
    outcome.metadata.setdefault("fixture_kind", scenario.fixture_kind)
    outcome.metadata.setdefault("seed", ctx.seed)
    outcome.metadata.setdefault("input_sha256", outcome.input_sha256)
    outcome.metadata.setdefault("output_sha256", outcome.output_sha256)

    return outcome


def run_scenario_with_seed(
    key_or_index: Any,
    ctx: ScenarioRunContext,
    seed: Optional[int],
) -> ScenarioOutcome:
    """Convenience entry point that also records the supplied seed."""
    ctx.seed = seed
    with _temporary_seed(seed):
        return run_scenario(key_or_index, ctx)


def scenario_matrix() -> List[Dict[str, Any]]:
    """Return machine-readable metadata for all registered scenarios."""
    return [scenario.describe() for scenario in _MUTATION_SCENARIOS]


def validate_registry() -> Dict[str, Any]:
    """Validate the registry without executing scenario mutations."""
    errors: List[str] = []
    warnings: List[str] = []
    keys: List[str] = []

    for scenario in _MUTATION_SCENARIOS:
        if scenario.key in keys:
            errors.append(f"Duplicate scenario key: {scenario.key}")
        keys.append(scenario.key)

        if not scenario.preset_apdu:
            errors.append(f"{scenario.key}: missing preset_apdu")

        if not callable(scenario.executor):
            errors.append(f"{scenario.key}: executor is not callable")

        if scenario.randomizer is not None and not callable(scenario.randomizer):
            errors.append(f"{scenario.key}: randomizer is not callable")

        if scenario.validator is None:
            warnings.append(f"{scenario.key}: no executable validator declared")

        try:
            _normalize_hex(scenario.preset_apdu)
        except Exception as exc:
            errors.append(f"{scenario.key}: invalid preset_apdu: {exc}")

    return {
        "status": "FAIL" if errors else "PASS",
        "scenario_count": len(_MUTATION_SCENARIOS),
        "errors": errors,
        "warnings": warnings,
        "keys": keys,
    }


__all__ = [
    "ScenarioAssertion",
    "ScenarioStage",
    "ScenarioRunContext",
    "ScenarioOutcome",
    "MutationScenario",
    "MUTATION_SCENARIOS",
    "get_scenarios",
    "get_scenario",
    "run_scenario",
    "run_scenario_with_seed",
    "randomize_scenario",
    "scenario_matrix",
    "validate_registry",
]
