# -*- coding: utf-8 -*-
"""Evidence adapters + EMV relevance filter for the Execution Atlas.

All traces derive from EXISTING evidence (scenario outcomes, replay JSON
fixtures, logger APDU ring, guard status). Nothing here mutates EMV core state.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import constants
import mutation_scenarios
import parser as emv_parser

from .code_index import CodeIndex
from .models import (
    AssertionInfo,
    AtlasTrace,
    EvidenceEvent,
    FlowEdge,
    FlowNode,
    ModulePathInfo,
    NodeKind,
    SourceReference,
    Transformation,
    TruthBadge,
)


# ---------------------------------------------------------------------------
# EMV relevance filter (explicit + inspectable)
# ---------------------------------------------------------------------------

EMV_RELEVANT_TOKENS = [
    "CAPDU", "RAPDU", "GPO", "READ RECORD", "GENERATE AC", "ARC", "ARPC", "ARQC",
    "CVM", "CDOL", "TLV", "MUTATE", "MUTATION", "CACHE", "GUARD", "SELECT",
    "VERIFY", "EXTERNAL AUTH", "ASSERTION", "EXCEPTION", "PROVENANCE", "SW",
]
EMV_NOISE_TOKENS = [
    "paint", "timer", "qt", "llm", "paintEvent", "resizeEvent",
]


def is_emv_relevant(text: str) -> bool:
    """The one, explicit, inspectable EMV relevance test."""
    if not text:
        return False
    t = text.upper()
    if any(n.upper() in t for n in EMV_NOISE_TOKENS):
        return False
    return any(tok.upper() in t for tok in EMV_RELEVANT_TOKENS)


def classify_apdu_record(rec: Dict[str, Any]) -> str:
    """CAPDU | RAPDU | OTHER from a logger._apdu_history entry."""
    kind = (rec.get("kind") or "").upper()
    if kind == "CAPDU":
        return "CAPDU"
    if kind == "RAPDU":
        return "RAPDU"
    return "OTHER"


# ---------------------------------------------------------------------------
# TLV helpers (observational only)
# ---------------------------------------------------------------------------

def flatten_tlv(data: bytes) -> Tuple[Dict[str, str], List[str]]:
    """Flatten parsed TLV tree -> {tag: value_hex}; collect parser errors."""
    flat: Dict[str, str] = {}
    try:
        nodes, errs = emv_parser.parse_ber_tlv(data)
    except Exception as exc:
        return flat, [str(exc)]

    def walk(n) -> None:
        tag = str(n.tag).upper()
        key = tag
        i = 1
        while key in flat:  # duplicate tag — disambiguate, don't overwrite
            key = f"{tag}#{i}"
            i += 1
        try:
            flat[key] = n.value.hex().upper()
        except Exception:
            flat[key] = ""
        for c in getattr(n, "children", []):
            walk(c)

    for n in nodes:
        walk(n)
    return flat, errs


def tlv_semantic_diff(before: bytes, after: bytes) -> Tuple[List[Transformation], List[str]]:
    """Semantic tag-level diff. Honest about offsets: reports tag identity,
    not invented pre/post offsets."""
    bf, e1 = flatten_tlv(before)
    af, e2 = flatten_tlv(after)
    diags = e1 + e2
    out: List[Transformation] = []
    for tag, bv in bf.items():
        plain_tag = tag.split("#")[0]
        av = af.get(tag)
        try:
            tag_int = int(plain_tag, 16)
        except Exception:
            tag_int = None
        if av is None:
            badge = TruthBadge.MUTATED
            label = f"Tag {plain_tag} removed"
            out.append(Transformation(label=label, tag=tag_int, before_hex=bv, after_hex="", badge=badge))
        elif av != bv:
            badge = TruthBadge.MUTATED
            label = f"Tag {plain_tag} changed"
            out.append(Transformation(label=label, tag=tag_int, before_hex=bv, after_hex=av, badge=badge))
    for tag, av in af.items():
        if tag not in bf:
            plain_tag = tag.split("#")[0]
            try:
                tag_int = int(plain_tag, 16)
            except Exception:
                tag_int = None
            out.append(Transformation(label=f"Tag {plain_tag} added", tag=tag_int,
                                      before_hex="", after_hex=av, badge=TruthBadge.MUTATED))
    return out, diags


# RAPDU handling: status word is NOT a TLV.
def split_rapdu(raw: bytes) -> Tuple[bytes, Optional[bytes]]:
    if len(raw) >= 2:
        sw = raw[-2:]
        body = raw[:-2]
        # Heuristic: 0x9000 / 0x61xx / 0x6Cxx / 0x6Axx / 0x69xx etc.
        if sw[0] in (0x90, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F):
            return body, sw
    return raw, None


def looks_like_capdu(raw: bytes) -> bool:
    """CLA INS P1 P2 header heuristic."""
    if len(raw) < 4:
        return False
    ins = raw[1]
    return ins in (0x84, 0xA8, 0xB2, 0xA4, 0x20, 0x82, 0xAE, 0xCA, 0xB0, 0x88)


# ---------------------------------------------------------------------------
# Trace builder — scenario
# ---------------------------------------------------------------------------

class AtlasBuilder:
    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root or ROOT_DIR)
        self.index = CodeIndex(self.root)

    def build_index(self) -> None:
        files = [
            "constants.py", "protocol.py", "tlv.py", "emv.py", "parser.py",
            "bypasses.py", "mod_emv_synthesizer.py", "mutations.py",
            "mutation_scenarios.py", "guard.py", "issuer_profiles.py",
            "issuer_simulator.py", "logger.py", "tp_hub.py", "rel8hf.py",
            "rel8hf_launcher.py",
        ]
        self.index.build(files)

    # -- core: scenario trace --------------------------------------------------

    def trace_scenario(self, key_or_index, ctx: Optional[mutation_scenarios.ScenarioRunContext] = None,
                       guard_status_provider: Optional[Callable[[], Optional[Dict[str, Any]]]] = None) -> AtlasTrace:
        """Run a scenario through the EXISTING registry executor and render its
        documented evidence. No instrumentation."""
        if not self.index._built:
            self.build_index()

        scen = mutation_scenarios.get_scenario(key_or_index)
        if ctx is None:
            raw = bytes.fromhex(scen.preset_apdu) if scen.preset_apdu else b""
            ctx = mutation_scenarios.ScenarioRunContext(raw_hex=scen.preset_apdu, raw_bytes=raw)

        # Use the registry's canonical entry point so validators + finalize()
        # run (they produce outcome.assertions and outcome.status).
        outcome = mutation_scenarios.run_scenario(key_or_index, ctx)

        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_key = re.sub(r"[^A-Za-z0-9_]+", "_", scen.key)
        trace = AtlasTrace(
            trace_id=f"ATLAS-{safe_key}-{ts}",
            source_kind="scenario",
            title=scen.title,
            provenance="synthetic",
            guard_context=self._guard_context(guard_status_provider),
        )
        trace.modules = self.index.module_paths(
            ["mutations", "mutation_scenarios", "tlv", "protocol", "emv", "parser", "constants"]
        )

        # Root scenario node
        root_id = "root"
        trace.nodes.append(FlowNode(
            id=root_id, kind=NodeKind.SCENARIO, label=f"Scenario: {scen.title.split(':')[0]}",
            sublabel=f"status: {outcome.status} | provenance: SYNTHETIC",
            badge=TruthBadge.EXECUTED if outcome.status == "PASS" else TruthBadge.FAILED if outcome.status == "FAIL" else TruthBadge.UNKNOWN,
            meta={"key": scen.key, "status": outcome.status},
        ))
        trace.events.append(EvidenceEvent(seq=0, kind="scenario", label=scen.title, node_id=root_id,
                                          badge=trace.nodes[0].badge))

        # Input APDU node
        raw = bytes(ctx.raw_bytes)
        is_capdu = looks_like_capdu(raw)
        apdu_id = "apdu_in"
        apdu_kind = NodeKind.CAPDU if is_capdu else NodeKind.RAPDU
        if not is_capdu:
            body, sw = split_rapdu(raw)
            sub = f"RAPDU {len(raw)} B, body {len(body)} B" + (f", SW={sw.hex().upper()}" if sw else "")
        else:
            sub = f"CAPDU {len(raw)} B, INS=0x{raw[1]:02X}"
        trace.nodes.append(FlowNode(
            id=apdu_id, kind=apdu_kind, label=("CAPDU INPUT" if is_capdu else "RAPDU INPUT"),
            sublabel=sub, badge=TruthBadge.EXECUTED,
            meta={"hex": raw.hex().upper(), "len": len(raw)},
        ))
        trace.edges.append(FlowEdge(src=root_id, dst=apdu_id, runtime=True))
        trace.events.append(EvidenceEvent(seq=len(trace.events), kind="input",
                                          label=f"input {apdu_kind.value} ({len(raw)} B)", node_id=apdu_id,
                                          badge=TruthBadge.EXECUTED))

        # Executor function node (from code index if resolvable, else UNKNOWN static)
        func_nodes: List[str] = []
        exec_count = 0
        for step in outcome.steps:
            step_plain = re.sub(r"<[^>]+>", "", step)  # strip HTML tags
            m = re.search(r"Running\s+([A-Za-z_][\w.]*)\s*\((.*?)\)", step_plain)
            if not m:
                continue
            qfn = m.group(1)
            exec_count += 1
            nid = f"fn_{exec_count}"
            ref = self.index.find([qfn])
            kind_badge = TruthBadge.EXECUTED
            trace.nodes.append(FlowNode(
                id=nid, kind=NodeKind.FUNCTION, label=qfn,
                sublabel=(f"{Path(ref.file).name}:{ref.line_start}" if ref else "source: not in index"),
                badge=kind_badge, source=ref,
                meta={"call_args": m.group(2)},
            ))
            func_nodes.append(nid)
        if not func_nodes:
            # executor didn't log any "Running X(...)" — fall back to executor name marker
            nid = "fn_exec"
            ref = self.index.find([f"mutation_scenarios.exec_{scen.key}"])
            trace.nodes.append(FlowNode(
                id=nid, kind=NodeKind.FUNCTION,
                label=f"executor: {scen.key}",
                sublabel="no inner calls logged",
                badge=TruthBadge.EXECUTED, source=ref,
            ))
            func_nodes.append(nid)

        prev_fn = apdu_id
        for nid in func_nodes:
            trace.edges.append(FlowEdge(src=prev_fn, dst=nid, runtime=True))
            prev_fn = nid

        for nid in func_nodes:
            node = next(n for n in trace.nodes if n.id == nid)
            trace.events.append(EvidenceEvent(seq=len(trace.events), kind="call",
                                              label=node.label, node_id=nid, badge=node.badge))

        # Transformations: TLV semantic diff (semantic, honest about offsets)
        in_bytes = raw
        out_bytes = bytes(outcome.mutated_bytes or b"")
        # RAPDU inputs: strip SW for TLV comparison
        in_body, _in_sw = split_rapdu(in_bytes)
        out_body, _out_sw = split_rapdu(out_bytes)
        if is_capdu:
            in_body, out_body = in_bytes, out_bytes
        t_diffs, diags = tlv_semantic_diff(in_body, out_body)
        trace.diagnostics.extend(diags)
        trace.transformations = [Transformation(
            label="Pipeline total",
            before_hex=in_bytes.hex().upper(),
            after_hex=out_bytes.hex().upper(),
            badge=TruthBadge.MUTATED if in_bytes != out_bytes else TruthBadge.EXECUTED,
        )] + t_diffs
        for t in trace.transformations:
            nid = f"xf_{len([n for n in trace.nodes if n.kind == NodeKind.TRANSFORMATION])}"
            trace.nodes.append(FlowNode(
                id=nid, kind=NodeKind.TRANSFORMATION, label=t.label,
                sublabel=f"{t.in_len()} B → {t.out_len()} B (Δ{t.len_delta:+d})",
                badge=t.badge,
                meta={"before": t.before_hex, "after": t.after_hex,
                      "in_sha256": t.in_sha, "out_sha256": t.out_sha},
            ))
            trace.edges.append(FlowEdge(src=prev_fn, dst=nid, runtime=True))
            trace.events.append(EvidenceEvent(seq=len(trace.events), kind="transform",
                                              label=t.label, node_id=nid, badge=t.badge))
            prev_fn = nid

        # Result node
        res_id = "result"
        changed = outcome.mutated_flag
        trace.nodes.append(FlowNode(
            id=res_id, kind=NodeKind.RESULT,
            label=f"RESULT: {'MUTATED' if changed else 'UNCHANGED'}",
            sublabel=f"{outcome.input_length} B → {outcome.output_length} B | status={outcome.status}",
            badge=TruthBadge.MUTATED if changed else TruthBadge.EXECUTED,
            meta={"in_sha256": outcome.input_sha256, "out_sha256": outcome.output_sha256,
                  "status": outcome.status, "provenance": outcome.provenance},
        ))
        trace.edges.append(FlowEdge(src=prev_fn, dst=res_id, runtime=True))
        trace.events.append(EvidenceEvent(seq=len(trace.events), kind="result",
                                          label=f"result {'mutated' if changed else 'unchanged'}", node_id=res_id,
                                          badge=trace.nodes[-1].badge))

        # Assertions
        for a in outcome.assertions:
            info = AssertionInfo(name=a.name, status=a.status, expected=a.expected,
                                 observed=a.observed, evidence=a.evidence, provenance=a.provenance,
                                 creation_file=a.creation_file, creation_line=a.creation_line,
                                 creation_qualname=a.creation_qualname)
            trace.assertions.append(info)
            aid = f"as_{len([n for n in trace.nodes if n.kind == NodeKind.ASSERTION])}"
            st_badge = TruthBadge.EXECUTED if a.status == "PASS" else TruthBadge.FAILED
            # Source = the runtime creation site (validator/helper that created
            # this assertion), captured at construction. This is the real
            # provenance — NOT the dispatcher that ran the scenario.
            a_ref = SourceReference(
                file=a.creation_file,
                qualname=a.creation_qualname,
                line_start=a.creation_line,
                line_end=a.creation_line,
                signature=a.creation_qualname,
            ) if a.creation_file else None
            trace.nodes.append(FlowNode(
                id=aid, kind=NodeKind.ASSERTION, label=f"assert {a.name}",
                sublabel=f"{a.status}", badge=st_badge, source=a_ref,
                meta={"expected": str(a.expected), "observed": str(a.observed),
                      "evidence": a.evidence, "provenance": a.provenance,
                      "creation_qualname": a.creation_qualname,
                      "creation_file": a.creation_file, "creation_line": a.creation_line},
            ))
            trace.edges.append(FlowEdge(src=res_id, dst=aid, runtime=True))
            trace.events.append(EvidenceEvent(seq=len(trace.events), kind="assertion",
                                              label=f"{a.name}: {a.status}", node_id=aid, badge=st_badge))

        # Guard context node (optional)
        if trace.guard_context:
            g = trace.guard_context
            gid = "guard"
            trace.nodes.append(FlowNode(
                id=gid, kind=NodeKind.GUARD, label=f"GUARD: {g.get('phase', 'IDLE')}",
                sublabel=f"last_sw={g.get('last_sw')} error={g.get('error')}",
                badge=TruthBadge.FAILED if g.get("error") else TruthBadge.EXECUTED,
                meta=dict(g),
            ))
            trace.edges.append(FlowEdge(src=root_id, dst=gid, runtime=True))

        # Environment nodes (stale-module visibility)
        for mp in trace.modules:
            nid = f"env_{mp.name}"
            trace.nodes.append(FlowNode(
                id=nid, kind=NodeKind.ENV, label=f"module {mp.name}",
                sublabel=mp.imported_path, badge=TruthBadge.FAILED if mp.stale else TruthBadge.STATIC,
                meta={"expected_path": mp.expected_path, "stale": mp.stale},
            ))
            # edges from file to env are static relationships → dashed
            fn_nodes = [n for n in trace.nodes if n.kind == NodeKind.FUNCTION]
            for fn in fn_nodes:
                if fn.source and Path(fn.source.file).stem == mp.name:
                    trace.edges.append(FlowEdge(src=nid, dst=fn.id, runtime=False))

        return trace

    # -- test-script trace (subprocess evidence, no profiling) ------------------

    # Output grammar of test_emv_full_flow.py (and similar scripts):
    #   [NNN] name
    #         CALL: <qualname>
    #         OUTPUT: <repr>
    #         RESULT: PASS|FAIL
    #     or  ERROR: <type>: <msg>
    # Section headers:  ====...  <title>  ====...
    _TEST_ENTRY_RE = re.compile(r"^\s*\[(\d{3})\]\s+(.+?)\s*$")
    _TEST_CALL_RE = re.compile(r"^\s*CALL:\s*(.+?)\s*$")
    _TEST_OUTPUT_RE = re.compile(r"^\s*OUTPUT:\s*(.+?)\s*$")
    _TEST_RESULT_RE = re.compile(r"^\s*RESULT:\s*(PASS|FAIL)\s*$")
    _TEST_ERROR_RE = re.compile(r"^\s*ERROR:\s*(.+?)\s*$")
    _TEST_SECTION_RE = re.compile(r"^([A-Z])\.\s+([A-Za-z0-9_]+\.py)\s*[^\w]*\s*(.+?)\s*$")
    def trace_test_script(self, script_path: Path, timeout_s: float = 600.0) -> AtlasTrace:
        """Run a self-executing test script in a subprocess and render its OWN
        printed evidence. No pytest plugin, no setprofile — the script's printed
        CALL/OUTPUT/RESULT lines are the observed evidence."""
        if not self.index._built:
            self.build_index()

        script_path = Path(script_path)
        ts = time.strftime("%Y%m%d_%H%M%S")
        trace = AtlasTrace(trace_id=f"ATLAS-TEST-{ts}", source_kind="test",
                           title=f"Test script {script_path.name}", provenance="synthetic")
        trace.modules = self.index.module_paths(
            ["protocol", "tlv", "emv", "mutations", "mutation_scenarios", "constants"]
        )

        root_id = "root"
        trace.nodes.append(FlowNode(
            id=root_id, kind=NodeKind.SCENARIO, label=f"TEST RUN: {script_path.name}",
            sublabel="subprocess evidence (no profiling)",
            badge=TruthBadge.EXECUTED, meta={"path": str(script_path)},
        ))
        trace.events.append(EvidenceEvent(seq=0, kind="test", label=f"test {script_path.name}",
                                          node_id=root_id, badge=TruthBadge.EXECUTED))

        try:
            # Force UTF-8 for the child so control glyphs (—, │, └) survive the pipe.
            env = dict(os.environ)
            env.setdefault("PYTHONIOENCODING", "utf-8")
            proc = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True, text=True, timeout=timeout_s,
                cwd=str(self.root), encoding="utf-8", errors="replace",
                env=env,
            )
            stdout = proc.stdout or ""
            if proc.returncode != 0:
                trace.diagnostics.append(f"script exit code {proc.returncode}")
                if proc.stderr:
                    trace.diagnostics.append(f"stderr tail: ...{(proc.stderr or '')[-300:]}")
        except subprocess.TimeoutExpired:
            trace.diagnostics.append(f"script exceeded timeout of {timeout_s}s")
            trace.nodes[0].badge = TruthBadge.FAILED
            return trace
        except Exception as exc:
            trace.diagnostics.append(f"script launch failed: {exc}")
            trace.nodes[0].badge = TruthBadge.FAILED
            return trace

        lines = stdout.splitlines()
        # Pass 1: sections like "A. protocol.py — TITLE ..."
        current_file_node: Optional[str] = None
        current_file_name: Optional[str] = None
        section_at_line: Dict[int, Tuple[str, str]] = {}
        for i, line in enumerate(lines):
            sec = self._TEST_SECTION_RE.match(line)
            if sec:
                section_at_line[i] = (sec.group(2), sec.group(3))

        for i, (fname, title) in section_at_line.items():
            nid = f"file_{fname.replace('.', '_')}"
            ref = self.index.find([f"{Path(fname).stem}"])
            # file-level: static relationship between the test script and
            # the module it exercises; dashed edge = static only.
            trace.nodes.append(FlowNode(
                id=nid, kind=NodeKind.FILE, label=fname,
                sublabel=title[:60], badge=TruthBadge.STATIC,
                source=ref, meta={"section_title": title},
            ))
            trace.edges.append(FlowEdge(src=root_id, dst=nid, runtime=False))

        # Pass 2: test-case entries [NNN] name + CALL/OUTPUT/RESULT/ERROR
        entry_idx = 0
        for i, line in enumerate(lines):
            # track current section file
            section_here = [s for li, s in section_at_line.items() if li < i]
            if section_here:
                current_file_name = section_here[-1][0]
                current_file_node = f"file_{current_file_name.replace('.', '_')}"

            m_entry = self._TEST_ENTRY_RE.match(line)
            if not m_entry:
                continue
            entry_idx += 1
            idx_str, entry_name = m_entry.group(1), m_entry.group(2).strip()
            call_q = output_repr = ""
            result_status = "UNKNOWN"
            result_err = ""
            for look in lines[i + 1: i + 6]:
                if self._TEST_ENTRY_RE.match(look):
                    break
                mc = self._TEST_CALL_RE.match(look)
                if mc:
                    call_q = mc.group(1)
                    continue
                mo = self._TEST_OUTPUT_RE.match(look)
                if mo:
                    output_repr = mo.group(1)
                    continue
                mr = self._TEST_RESULT_RE.match(look)
                if mr:
                    result_status = mr.group(1)
                    continue
                me = self._TEST_ERROR_RE.match(look)
                if me:
                    result_status = "ERROR"
                    result_err = me.group(1)

            nid = f"tc_{idx_str}"
            badge = (TruthBadge.EXECUTED if result_status == "PASS"
                     else TruthBadge.FAILED if result_status in ("FAIL", "ERROR")
                     else TruthBadge.UNKNOWN)
            ref = None
            if call_q:
                # try resolve "module.fn" or "Class.fn" style qualnames
                ref = self.index.find([call_q, f"protocol.{call_q}", f"tlv.{call_q}",
                                       f"emv.{call_q}", f"mutations.{call_q}"])
            trace.nodes.append(FlowNode(
                id=nid, kind=NodeKind.FUNCTION,
                label=f"[{idx_str}] {entry_name}",
                sublabel=f"{call_q or 'call'} → {result_status}",
                badge=badge, source=ref,
                meta={"output": output_repr, "result": result_status,
                      "error": result_err, "section_file": current_file_name},
            ))
            parent = current_file_node or root_id
            trace.edges.append(FlowEdge(src=parent, dst=nid, runtime=True))
            trace.events.append(EvidenceEvent(seq=len(trace.events), kind="assertion",
                                              label=f"{entry_name}: {result_status}",
                                              node_id=nid, badge=badge))
            trace.assertions.append(AssertionInfo(
                name=entry_name, status=result_status,
                observed=output_repr or result_err,
                evidence=f"test script {script_path.name} line [{idx_str}]",
                provenance="synthetic",
            ))

        # We may find ALSO scenario-section lines (--- SCENARIO i: key ---).
        n_scen = len([ln for ln in lines if ln.startswith("--- SCENARIO")])
        if n_scen:
            trace.diagnostics.append(f"script also exercised {n_scen} registered scenarios")

        # If we parsed nothing, warn instead of faking a graph.
        if entry_idx == 0 and not any(True for _ in [self._TEST_ENTRY_RE.match(l) for l in lines]):
            trace.diagnostics.append("no [NNN]/CALL/RESULT lines parsed — format drift?")

        # summary node
        n_pass = sum(1 for a in trace.assertions if a.status == "PASS")
        n_fail = sum(1 for a in trace.assertions if a.status in ("FAIL", "ERROR"))
        trace.nodes.append(FlowNode(
            id="test_summary", kind=NodeKind.RESULT,
            label=f"RESULT: {n_pass} PASS / {n_fail} FAIL",
            sublabel=f"{len(trace.assertions)} entries parsed from printed output",
            badge=TruthBadge.FAILED if n_fail else TruthBadge.EXECUTED,
            meta={"pass": n_pass, "fail": n_fail},
        ))
        trace.edges.append(FlowEdge(src=root_id, dst="test_summary", runtime=True))
        return trace

    def trace_replay_exchange(self, replay_path: Path, exchange_index: int) -> AtlasTrace:
        """Render one recorded CAPDU/RAPDU exchange from a replay JSON fixture.
        Malformed records are reported, never repaired."""
        if not self.index._built:
            self.build_index()

        ts = time.strftime("%Y%m%d_%H%M%S")
        trace = AtlasTrace(trace_id=f"ATLAS-REPLAY-{ts}", source_kind="replay",
                           title=f"Replay {Path(replay_path).name} exchange {exchange_index}",
                           provenance="recorded")
        trace.modules = self.index.module_paths(["parser", "tlv", "protocol"])

        try:
            data = json.loads(Path(replay_path).read_text(encoding="utf-8"))
        except Exception as exc:
            trace.diagnostics.append(f"replay read failed: {exc}")
            trace.nodes.append(FlowNode(
                id="root", kind=NodeKind.EXCHANGE, label="REPLAY",
                sublabel="SOURCE: MALFORMED (unreadable JSON)", badge=TruthBadge.FAILED))
            return trace
        if not isinstance(data, list) or not (0 <= exchange_index < len(data)):
            trace.nodes.append(FlowNode(
                id="root", kind=NodeKind.EXCHANGE, label="REPLAY",
                sublabel="SOURCE: MALFORMED (index out of range)", badge=TruthBadge.FAILED))
            return trace

        ex = data[exchange_index]
        cap = ex.get("capdu", "")
        rap = ex.get("rapdu", "")

        rid = "root"
        trace.nodes.append(FlowNode(
            id=rid, kind=NodeKind.EXCHANGE, label=f"Exchange {exchange_index}",
            sublabel=Path(replay_path).name,
            badge=TruthBadge.EXECUTED, meta={"replay": str(replay_path)},
        ))

        def _mk(cap_or_rap: str, which: str) -> str:
            nid = which
            try:
                raw = bytes.fromhex(cap_or_rap)
            except Exception as exc:
                trace.diagnostics.append(f"{which} hex malformed: {exc}")
                raw = b""
            kind = NodeKind.CAPDU if which == "capdu" else NodeKind.RAPDU
            if kind == NodeKind.CAPDU:
                sub = f"{len(raw)} B" + (f", INS=0x{raw[1]:02X}" if len(raw) >= 2 else "")
            else:
                body, sw = split_rapdu(raw)
                sub = f"body {len(body)} B" + (f", SW={sw.hex().upper()}" if sw else ", SW=?")
            trace.nodes.append(FlowNode(
                id=nid, kind=kind, label=which.upper(), sublabel=sub,
                badge=TruthBadge.EXECUTED if raw else TruthBadge.FAILED,
                meta={"hex": cap_or_rap.upper(), "len": len(raw)},
            ))
            trace.edges.append(FlowEdge(src=rid, dst=nid, runtime=True))
            trace.events.append(EvidenceEvent(seq=len(trace.events), kind=which,
                                              label=f"{which.upper()} ({len(raw)} B)", node_id=nid,
                                              badge=TruthBadge.EXECUTED if raw else TruthBadge.FAILED))
            return nid

        cid = _mk(cap, "capdu")
        ridp = _mk(rap, "rapdu")
        # TLV breakdown of RAPDU body as evidence of content (parse happens NOW,
        # observational). Malformed TLV → FAILED node instead of invented nodes.
        try:
            raw_r = bytes.fromhex(rap)
            body, sw = split_rapdu(raw_r)
            nodes, errs = emv_parser.parse_ber_tlv(body)
            if errs:
                trace.diagnostics.append(f"TLV parse warnings: {errs}")
            for n in nodes:
                tid = f"tlv_{n.tag}"
                trace.nodes.append(FlowNode(
                    id=tid, kind=NodeKind.TRANSFORMATION,
                    label=f"Tag {str(n.tag).upper()}",
                    sublabel=f"{len(n.value)} B (recorded)",
                    badge=TruthBadge.EXECUTED,
                    meta={"value": n.value.hex().upper()},
                ))
                trace.edges.append(FlowEdge(src=ridp, dst=tid, runtime=True))
        except Exception as exc:
            trace.diagnostics.append(f"RAPDU TLV structure rejected: {exc}")
            fail_id = "tlv_reject"
            trace.nodes.append(FlowNode(
                id=fail_id, kind=NodeKind.TRANSFORMATION,
                label="SOURCE: MALFORMED — MUTATION: REJECTED",
                sublabel=f"structural parser failure: {exc}",
                badge=TruthBadge.FAILED,
            ))
            trace.edges.append(FlowEdge(src=ridp, dst=fail_id, runtime=True))
            trace.events.append(EvidenceEvent(seq=len(trace.events), kind="reject",
                                              label="malformed structure rejected", node_id=fail_id,
                                              badge=TruthBadge.FAILED))
        return trace

    # -- guard accessories --------------------------------------------------------

    @staticmethod
    def _guard_context(provider: Optional[Callable[[], Optional[Dict[str, Any]]]]) -> Optional[Dict[str, Any]]:
        if provider is None:
            return None
        try:
            st = provider()
            return dict(st) if st else None
        except Exception:
            return None
