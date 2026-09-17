# -*- coding: utf-8 -*-
"""EMV Execution Atlas — Phase 1: evidence-driven execution visualizer.

Observational only. Does NOT modify EMV core behavior, does NOT use
sys.setprofile/sys.settrace. All nodes/edges derive from existing evidence:
scenario outcomes, replay fixtures, logger APDU ring, guard status, AST index.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import hashlib


class TruthBadge(str, Enum):
    """Mandatory truth semantics — never invent relationships."""
    STATIC = "STATIC"        # derived from source/AST index only
    EXECUTED = "EXECUTED"    # existing evidence proves execution
    MUTATED = "MUTATED"      # before/after byte evidence proves change
    FAILED = "FAILED"        # explicit failure/exception evidence
    UNKNOWN = "UNKNOWN"      # insufficient evidence


class NodeKind(str, Enum):
    SCENARIO = "SCENARIO"
    EXCHANGE = "EXCHANGE"
    CAPDU = "CAPDU"
    RAPDU = "RAPDU"
    FILE = "FILE"
    FUNCTION = "FUNCTION"
    TRANSFORMATION = "TRANSFORMATION"
    RESULT = "RESULT"
    ASSERTION = "ASSERTION"
    GUARD = "GUARD"
    ENV = "ENV"


@dataclass
class SourceReference:
    """Lightweight AST locator — function → file → line range."""
    file: str
    qualname: str
    line_start: int = 0
    line_end: int = 0
    signature: str = ""
    docstring: str = ""


@dataclass
class Transformation:
    """Byte evidence for one logical change."""
    label: str
    tag: Optional[int] = None
    before_hex: str = ""
    after_hex: str = ""
    badge: TruthBadge = TruthBadge.UNKNOWN
    def in_len(self) -> int: return len(self.before_hex) // 2
    def out_len(self) -> int: return len(self.after_hex) // 2
    @property
    def in_sha(self) -> str:
        return hashlib.sha256(bytes.fromhex(self.before_hex)).hexdigest() if self.before_hex else ""
    @property
    def out_sha(self) -> str:
        return hashlib.sha256(bytes.fromhex(self.after_hex)).hexdigest() if self.after_hex else ""
    @property
    def len_delta(self) -> int: return self.out_len() - self.in_len()


@dataclass
class AssertionInfo:
    name: str
    status: str             # PASS / FAIL / UNVERIFIED
    expected: Any = None
    observed: Any = None
    evidence: str = ""
    provenance: str = "synthetic"
    # Runtime creation-site provenance: the actual validator/helper that
    # created this assertion (never the dispatcher run_scenario()).
    creation_file: str = ""
    creation_line: int = 0
    creation_qualname: str = ""


@dataclass
class FlowNode:
    id: str
    kind: NodeKind
    label: str
    sublabel: str = ""
    badge: TruthBadge = TruthBadge.UNKNOWN
    source: Optional[SourceReference] = None
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FlowEdge:
    src: str
    dst: str
    runtime: bool = True    # False = dashed static-only edge


@dataclass
class EvidenceEvent:
    seq: int
    kind: str
    label: str
    node_id: str
    badge: TruthBadge = TruthBadge.UNKNOWN


@dataclass
class ModulePathInfo:
    name: str
    imported_path: str
    expected_path: str
    stale: bool


@dataclass
class AtlasTrace:
    """One visualized execution — the root object of the Atlas."""
    trace_id: str
    source_kind: str            # "scenario" | "replay"
    title: str
    provenance: str = "synthetic"
    nodes: List[FlowNode] = field(default_factory=list)
    edges: List[FlowEdge] = field(default_factory=list)
    events: List[EvidenceEvent] = field(default_factory=list)
    transformations: List[Transformation] = field(default_factory=list)
    assertions: List[AssertionInfo] = field(default_factory=list)
    guard_context: Optional[Dict[str, Any]] = None
    modules: List[ModulePathInfo] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        def node(n: FlowNode) -> Dict[str, Any]:
            d = {"id": n.id, "kind": n.kind.value, "label": n.label, "sublabel": n.sublabel,
                 "badge": n.badge.value, "meta": n.meta}
            if n.source:
                d["source"] = {"file": n.source.file, "qualname": n.source.qualname,
                               "lines": [n.source.line_start, n.source.line_end],
                               "signature": n.source.signature}
            return d
        return {
            "trace_id": self.trace_id,
            "source_kind": self.source_kind,
            "title": self.title,
            "provenance": self.provenance,
            "nodes": [node(n) for n in self.nodes],
            "edges": [{"src": e.src, "dst": e.dst, "runtime": e.runtime} for e in self.edges],
            "events": [{"seq": ev.seq, "kind": ev.kind, "label": ev.label,
                        "node_id": ev.node_id, "badge": ev.badge.value} for ev in self.events],
            "transformations": [
                {"label": t.label, "tag": (f"0x{t.tag:04X}" if t.tag is not None else None),
                 "in_len": t.in_len(), "out_len": t.out_len(), "len_delta": t.len_delta,
                 "in_sha256": t.in_sha, "out_sha256": t.out_sha,
                 "changed": t.before_hex != t.after_hex, "badge": t.badge.value}
                for t in self.transformations],
            "assertions": [{"name": a.name, "status": a.status,
                            "expected": str(a.expected), "observed": str(a.observed),
                            "provenance": a.provenance, "evidence": a.evidence,
                            "creation_file": a.creation_file,
                            "creation_line": a.creation_line,
                            "creation_qualname": a.creation_qualname}
                           for a in self.assertions],
            "guard_context": self.guard_context,
            "modules": [{"name": m.name, "imported_path": m.imported_path,
                         "expected_path": m.expected_path, "stale": m.stale}
                        for m in self.modules],
            "diagnostics": self.diagnostics,
        }
