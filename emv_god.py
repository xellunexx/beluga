# -*- coding: utf-8 -*-
"""EMV God — event-driven cognitive layer.

This module is intentionally independent from the Qt application.

The Qt application should only need to:

    from emv_god import EMVGod
    god = EMVGod(root)
    god.attach_llm(llm_engine)
    god.attach_runtime(get_runtime_snapshot)
    god.attach_logs(get_recent_logs)
    god.start()

Then publish meaningful events with ``god.emit(...)``.

Design goals:
- keep Qt thin; cognition lives here
- observe runtime/log/code changes without mutating EMV state
- coalesce noisy events and wake the LLM only on meaningful deltas
- maintain durable evidence-backed operational memory
- distinguish observations from learned lessons and open hypotheses
- keep the LLM warm without requiring a chat turn
- never grant permissions by itself; existing tool/omnipotent gates remain authoritative

The module deliberately does NOT implement packet injection, EMV mutation, direct
stack writes, or source modification. Those capabilities stay in the existing
application/tool layer and remain operator-gated.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import queue
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Durable project state
# ---------------------------------------------------------------------------

@dataclass
class FileState:
    path: str
    sha256: str
    size: int
    mtime: float
    lines: int


@dataclass
class Event:
    ts: float
    kind: str
    source: str = "runtime"
    priority: int = 50
    txn_id: Optional[str] = None
    exchange_id: Optional[int] = None
    payload: Dict[str, Any] = field(default_factory=dict)

    def compact(self) -> Dict[str, Any]:
        return {
            "ts": round(self.ts, 3),
            "kind": self.kind,
            "source": self.source,
            "priority": self.priority,
            "txn_id": self.txn_id,
            "exchange_id": self.exchange_id,
            "payload": self.payload,
        }


@dataclass
class Experience:
    ts: float
    kind: str
    statement: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    source_event_ids: List[str] = field(default_factory=list)


class _StateStore:
    """Small atomic JSON store shared by the compatibility APIs and God."""

    def __init__(self, path: Path, schema: int = 3) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.state: Dict[str, Any] = {
            "schema": schema,
            "updated_at": 0.0,
            "files": {},
            "symbols": {},
            "imports": {},
            "dependents": {},
            "journal": [],
            "lessons": [],
            "hypotheses": [],
            "experiences": [],
            "active_task": "",
            "pending_verification": [],
            "runtime": {},
        }
        self.load()

    def load(self) -> None:
        with self.lock:
            try:
                if self.path.exists():
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        self.state.update(data)
            except Exception:
                # Memory corruption must never take the application down.
                pass

    def save(self) -> None:
        with self.lock:
            self.state["updated_at"] = time.time()
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(
                json.dumps(self.state, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            os.replace(tmp, self.path)

    def journal(self, kind: str, data: Any) -> None:
        with self.lock:
            entries = self.state.setdefault("journal", [])
            entries.append({"ts": time.time(), "kind": kind, "data": data})
            del entries[:-500]


# ---------------------------------------------------------------------------
# Project indexing / intelligence
# ---------------------------------------------------------------------------

class EMVGodCore:
    """Persistent project map, lessons, snapshots and verification history."""

    def __init__(self, root: Path, state_path: Optional[Path] = None) -> None:
        self.root = Path(root).resolve()
        self._store = _StateStore(
            state_path or (self.root / "memory" / "emv_god_state.json"),
            schema=3,
        )
        self.state = self._store.state

    def _record(self, kind: str, text: str) -> None:
        events = self.state.setdefault("recent_events", [])
        events.append({"ts": time.time(), "kind": kind, "text": text})
        del events[:-50]
        self._store.journal(kind, text)

    def set_task(self, task: str) -> None:
        self.state["active_task"] = str(task or "").strip()
        self._record("task", self.state["active_task"])
        self._store.save()

    def add_lesson(self, lesson: str, evidence: Optional[Dict[str, Any]] = None) -> None:
        lesson = str(lesson or "").strip()
        if not lesson:
            return
        item = {
            "ts": time.time(),
            "lesson": lesson,
            "evidence": evidence or {},
        }
        lessons = self.state.setdefault("lessons", [])
        # Avoid duplicate spam but preserve the newest evidence timestamp.
        existing = next((x for x in lessons if x.get("lesson") == lesson), None)
        if existing is not None:
            existing.update(item)
        else:
            lessons.append(item)
        del lessons[:-200]
        self._record("lesson", lesson)
        self._store.save()

    def add_hypothesis(
        self,
        claim: str,
        confidence: float = 0.5,
        supporting: Optional[List[Any]] = None,
        contradicting: Optional[List[Any]] = None,
        next_observation: str = "",
    ) -> Dict[str, Any]:
        claim = str(claim or "").strip()
        item = {
            "id": f"H-{int(time.time() * 1000)}",
            "ts": time.time(),
            "claim": claim,
            "confidence": max(0.0, min(1.0, float(confidence))),
            "supporting": list(supporting or []),
            "contradicting": list(contradicting or []),
            "next_observation": str(next_observation or "").strip(),
        }
        hyps = self.state.setdefault("hypotheses", [])
        hyps.append(item)
        del hyps[:-200]
        self._store.save()
        return item

    def record_experience(
        self,
        kind: str,
        statement: str,
        evidence: Optional[Dict[str, Any]] = None,
        confidence: float = 0.0,
        source_event_ids: Optional[List[str]] = None,
    ) -> Experience:
        exp = Experience(
            ts=time.time(),
            kind=str(kind),
            statement=str(statement),
            evidence=dict(evidence or {}),
            confidence=max(0.0, min(1.0, float(confidence))),
            source_event_ids=list(source_event_ids or []),
        )
        arr = self.state.setdefault("experiences", [])
        arr.append(asdict(exp))
        del arr[:-500]
        self._record("experience", exp.statement)
        self._store.save()
        return exp

    def index_project(self, max_files: int = 500) -> Dict[str, Any]:
        files: Dict[str, Any] = {}
        symbols: Dict[str, Any] = {}
        imports: Dict[str, Any] = {}
        ignored = {".git", "__pycache__", ".venv", "venv", "node_modules", "logs", "memory"}
        count = 0

        for p in self.root.rglob("*.py"):
            if count >= max_files:
                break
            if any(part in ignored for part in p.parts):
                continue
            try:
                rel = str(p.relative_to(self.root)).replace("\\", "/")
                raw = p.read_bytes()
                text = raw.decode("utf-8", errors="replace")
                stat = p.stat()
                files[rel] = asdict(
                    FileState(
                        rel,
                        hashlib.sha256(raw).hexdigest(),
                        stat.st_size,
                        stat.st_mtime,
                        len(text.splitlines()),
                    )
                )
                try:
                    tree = ast.parse(text, filename=rel)
                    names: List[Dict[str, Any]] = []
                    imps: List[str] = []
                    for node in ast.walk(tree):
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            names.append({
                                "name": node.name,
                                "kind": type(node).__name__,
                                "line": getattr(node, "lineno", 0),
                                "end_line": getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                            })
                        elif isinstance(node, ast.Import):
                            imps.extend(a.name for a in node.names)
                        elif isinstance(node, ast.ImportFrom) and node.module:
                            imps.append(node.module)
                    symbols[rel] = names[:300]
                    imports[rel] = imps[:100]
                except SyntaxError as exc:
                    symbols[rel] = [{
                        "name": "<syntax-error>",
                        "kind": "error",
                        "line": getattr(exc, "lineno", 0),
                    }]
                    imports[rel] = []
                count += 1
            except Exception:
                continue

        previous = self.state.get("files", {})
        changed = []
        for rel, info in files.items():
            old = previous.get(rel, {})
            if old.get("sha256") and old.get("sha256") != info.get("sha256"):
                changed.append(rel)
        for rel in set(previous) - set(files):
            changed.append(rel)

        self.state["files"] = files
        self.state["symbols"] = symbols
        self.state["imports"] = imports
        self.state["dependents"] = self._build_dependents(imports, files)
        self._record("index", {"files": count, "changed": changed})
        self._store.save()
        return {
            "files": count,
            "symbols": sum(len(v) for v in symbols.values()),
            "changed": changed,
        }

    @staticmethod
    def _build_dependents(imports: Dict[str, List[str]], files: Dict[str, Any]) -> Dict[str, List[str]]:
        module_to_path: Dict[str, str] = {}
        for rel, info in files.items():
            module = rel[:-3].replace("/", ".") if rel.endswith(".py") else rel.replace("/", ".")
            if module.endswith(".__init__"):
                module = module[:-9]
            module_to_path[module] = rel
        dependents: Dict[str, List[str]] = {}
        for rel, imps in imports.items():
            for imp in imps:
                target = module_to_path.get(imp)
                if target:
                    dependents.setdefault(target, []).append(rel)
        return dependents

    def snapshot_file(self, file_path: str) -> Dict[str, Any]:
        p = self._resolve(file_path)
        raw = p.read_bytes()
        st = p.stat()
        rel = str(p.relative_to(self.root)).replace("\\", "/")
        fs = asdict(FileState(rel, hashlib.sha256(raw).hexdigest(), st.st_size, st.st_mtime, len(raw.splitlines())))
        self.state.setdefault("files", {})[rel] = fs
        self._store.save()
        return fs

    def verify_file(self, file_path: str, expected_sha256: str = "") -> Dict[str, Any]:
        p = self._resolve(file_path)
        result: Dict[str, Any] = {"file": str(p), "exists": p.exists()}
        if not p.exists():
            result.update({"ok": False, "error": "file does not exist"})
            return result
        raw = p.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        result.update({"sha256": digest, "size": len(raw), "lines": len(raw.splitlines())})
        if expected_sha256:
            result["hash_match"] = digest.lower() == expected_sha256.lower()
        if p.suffix.lower() == ".py":
            try:
                ast.parse(raw.decode("utf-8", errors="replace"), filename=str(p))
                result["syntax_ok"] = True
            except SyntaxError as exc:
                result["syntax_ok"] = False
                result["syntax_error"] = f"line {exc.lineno}: {exc.msg}"
        result["ok"] = bool(result.get("syntax_ok", True)) and bool(result.get("hash_match", True))
        self._record("verify", f"{p.name}: {'OK' if result['ok'] else 'FAILED'}")
        self._store.state.setdefault("verification", []).append({"ts": time.time(), **result})
        self._store.state["verification"] = self._store.state["verification"][-200:]
        self._store.save()
        return result

    def context(self, max_chars: int = 16000, max_symbols: int = 120) -> str:
        files = self.state.get("files", {})
        symbols = self.state.get("symbols", {})
        lines = ["=== EMV GOD PROJECT MEMORY ==="]
        lines.append(f"Project root: {self.root}")
        lines.append(f"Indexed Python files: {len(files)}")
        if self.state.get("active_task"):
            lines.append(f"Active task: {self.state['active_task']}")
        pending = self.state.get("pending_verification", [])
        if pending:
            lines.append("Pending verification: " + "; ".join(map(str, pending[-10:])))
        lines.append("Recent events:")
        for ev in self.state.get("recent_events", [])[-10:]:
            lines.append(f"- {ev.get('kind')}: {ev.get('text')}")
        lines.append("Known lessons:")
        for lesson in self.state.get("lessons", [])[-12:]:
            if isinstance(lesson, dict):
                lines.append(f"- {lesson.get('lesson', '')}")
            else:
                lines.append(f"- {lesson}")
        lines.append("Open hypotheses:")
        for hyp in self.state.get("hypotheses", [])[-8:]:
            lines.append(
                f"- {hyp.get('claim', '')} | confidence={hyp.get('confidence', 0):.2f}"
            )
        lines.append("Key symbols:")
        n = 0
        for path, names in symbols.items():
            if not names:
                continue
            names_text = ", ".join(x.get("name", "?") for x in names[:12])
            lines.append(f"- {path}: {names_text}")
            n += len(names[:12])
            if n >= max_symbols:
                break
        text = "\n".join(lines)
        return text[:max_chars]

    def get_recent_lessons(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(self.state.get("lessons", [])[-limit:])

    def _resolve(self, file_path: str) -> Path:
        p = Path(str(file_path).strip())
        p = p if p.is_absolute() else (self.root / p)
        p = p.resolve()
        if not self._inside(p):
            raise PermissionError("EMV God project tools are restricted to the project root")
        return p

    def _inside(self, p: Path) -> bool:
        try:
            p.relative_to(self.root)
            return True
        except ValueError:
            return False


class EMVProjectIntelligence(EMVGodCore):
    """Backward-compatible Layer-2 name; now backed by the unified store."""

    def __init__(self, project_root, state_path=None):
        super().__init__(Path(project_root), Path(state_path) if state_path else None)
        self.project_root = self.root

    def refresh(self) -> Dict[str, Any]:
        return self.index_project()

    def project_map(self) -> Dict[str, Any]:
        self.refresh()
        return {
            "project_root": str(self.project_root),
            "python_files": len(self.state.get("files", {})),
            "files": self.state.get("files", {}),
            "dependents": self.state.get("dependents", {}),
            "active_plans": self.state.get("plans", {}),
            "recent_journal": self.state.get("journal", [])[-20:],
            "recent_verification": self.state.get("verification", [])[-20:],
            "lessons": self.state.get("lessons", [])[-30:],
        }

    def record_event(self, kind, data):
        self._record(kind, data)
        self._store.save()

    def set_plan(self, task, steps):
        self.state.setdefault("plans", {})[task] = {
            "task": task,
            "steps": [{"step": str(s), "status": "pending"} for s in steps],
            "updated_at": time.time(),
        }
        self._store.save()

    def update_plan_step(self, task, index, status):
        plan = self.state.setdefault("plans", {}).get(task)
        if not plan or not (0 <= index < len(plan["steps"])):
            return False
        plan["steps"][index]["status"] = status
        plan["updated_at"] = time.time()
        self._store.save()
        return True

    def add_lesson(self, lesson, evidence=None):
        return super().add_lesson(lesson, evidence)


# ---------------------------------------------------------------------------
# Event-driven cognitive orchestrator
# ---------------------------------------------------------------------------

LLMCallable = Callable[[str], Any]
SnapshotGetter = Callable[[], Dict[str, Any]]
LogGetter = Callable[[], Any]


class EMVGod:
    """The single public façade for the cognitive subsystem."""

    DEFAULT_PRIORITY: Dict[str, int] = {
        "EXCEPTION": 100,
        "STALL": 100,
        "TRANSACTION_BOUNDARY": 95,
        "GUARD_TRANSITION": 90,
        "TEST_RESULT": 85,
        "CODEBASE_CHANGE": 80,
        "LOG_ANOMALY": 80,
        "APDU_EXCHANGE": 60,
        "RUNTIME_CHANGE": 55,
        "TELEMETRY": 20,
        "HEARTBEAT": 5,
        "UI": 1,
    }

    def __init__(
        self,
        root: Path,
        *,
        state_path: Optional[Path] = None,
        event_window_sec: float = 0.35,
        poll_interval_sec: float = 2.0,
        keepalive_interval_sec: float = 1200.0,
        min_inference_interval_sec: float = 1.0,
    ) -> None:
        self.root = Path(root).resolve()
        self.core = EMVGodCore(self.root, state_path=state_path)

        self.event_window_sec = max(0.05, float(event_window_sec))
        self.poll_interval_sec = max(0.25, float(poll_interval_sec))
        self.keepalive_interval_sec = max(30.0, float(keepalive_interval_sec))
        self.min_inference_interval_sec = max(0.0, float(min_inference_interval_sec))

        self._queue: "queue.PriorityQueue[Tuple[int, int, Event]]" = queue.PriorityQueue()
        self._counter = 0
        self._counter_lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._watcher: Optional[threading.Thread] = None
        self._keepalive: Optional[threading.Thread] = None
        self._running = False
        self._last_inference = 0.0
        self._last_snapshot: Dict[str, Any] = {}
        self._last_code_hashes: Dict[str, str] = dict(
            (self.core.state.get("files") or {})
        )
        self._last_log_fingerprint: str = ""
        self._last_runtime_fingerprint: str = ""

        self._llm: Any = None
        self._llm_callable: Optional[LLMCallable] = None
        self._runtime_getter: Optional[SnapshotGetter] = None
        self._logs_getter: Optional[LogGetter] = None
        self._event_callback: Optional[Callable[[Dict[str, Any]], None]] = None
        self._cognition_callback: Optional[Callable[[Dict[str, Any]], None]] = None

        self._record_event("god_init", {"root": str(self.root)})

    # ----- binding ---------------------------------------------------------

    def attach_llm(self, llm: Any) -> None:
        """Attach LocalLLMEngine-like object without importing qt_app."""
        self._llm = llm
        self._llm_callable = None

    def attach_llm_callable(self, fn: LLMCallable) -> None:
        self._llm_callable = fn
        self._llm = None

    def attach_runtime(self, getter: Optional[SnapshotGetter]) -> None:
        self._runtime_getter = getter

    def attach_logs(self, getter: Optional[LogGetter]) -> None:
        self._logs_getter = getter

    def on_event(self, callback: Optional[Callable[[Dict[str, Any]], None]]) -> None:
        self._event_callback = callback

    def on_cognition(self, callback: Optional[Callable[[Dict[str, Any]], None]]) -> None:
        self._cognition_callback = callback

    # ----- lifecycle -------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._running

    def start(self, *, index_project: bool = True) -> None:
        if self._running:
            return
        if index_project:
            self.core.index_project()
        self._stop.clear()
        self._running = True
        self._worker = threading.Thread(target=self._cognition_loop, name="EMV-God-Cognition", daemon=True)
        self._watcher = threading.Thread(target=self._watch_loop, name="EMV-God-Watcher", daemon=True)
        self._keepalive = threading.Thread(target=self._keepalive_loop, name="EMV-God-KeepAlive", daemon=True)
        self._worker.start()
        self._watcher.start()
        self._keepalive.start()
        self.emit(
            "RUNTIME_CHANGE",
            source="god",
            payload={"reason": "cognition_started"},
            priority=70,
        )

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        self._wake.set()
        for t in (self._worker, self._watcher, self._keepalive):
            if t and t.is_alive():
                t.join(timeout=max(0.1, timeout))
        self._running = False
        self._record_event("god_stop", {})

    # ----- events ----------------------------------------------------------

    def emit(
        self,
        kind: str,
        *,
        source: str = "runtime",
        priority: Optional[int] = None,
        txn_id: Optional[str] = None,
        exchange_id: Optional[int] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        kind = str(kind or "RUNTIME_CHANGE").upper()
        event = Event(
            ts=time.time(),
            kind=kind,
            source=str(source),
            priority=int(priority if priority is not None else self.DEFAULT_PRIORITY.get(kind, 50)),
            txn_id=txn_id,
            exchange_id=exchange_id,
            payload=dict(payload or {}),
        )
        with self._counter_lock:
            self._counter += 1
            seq = self._counter
        event_id = f"E-{int(event.ts * 1000)}-{seq}"
        event.payload.setdefault("event_id", event_id)
        self._queue.put((-event.priority, seq, event))
        self._record_event("event", event.compact())
        if self._event_callback:
            try:
                self._event_callback(event.compact())
            except Exception:
                pass
        self._wake.set()
        return event_id

    # ----- external snapshots ---------------------------------------------

    def observe_runtime(self, snapshot: Optional[Dict[str, Any]] = None) -> None:
        snap = snapshot if snapshot is not None else self._safe_runtime()
        fp = self._fingerprint(snap)
        if fp != self._last_runtime_fingerprint:
            previous = self._last_snapshot.get("runtime", {})
            self._last_runtime_fingerprint = fp
            self._last_snapshot["runtime"] = snap
            delta = self._dict_delta(previous, snap)
            self.emit("RUNTIME_CHANGE", source="runtime", payload={"delta": delta, "snapshot": snap})

    def observe_logs(self, logs: Any = None) -> None:
        value = logs if logs is not None else self._safe_logs()
        fp = self._fingerprint(value)
        if fp != self._last_log_fingerprint:
            self._last_log_fingerprint = fp
            self.emit("LOG_ANOMALY", source="logger", payload={"delta": self._compact_logs(value)})

    # ----- background watcher ----------------------------------------------

    def _watch_loop(self) -> None:
        last_index = 0.0
        while not self._stop.wait(self.poll_interval_sec):
            try:
                now = time.time()
                # Project scan is intentionally rate-limited. It is a safety net,
                # not a filesystem-event storm.
                if now - last_index >= self.poll_interval_sec:
                    result = self.core.index_project()
                    changed = result.get("changed", [])
                    if changed:
                        self.emit(
                            "CODEBASE_CHANGE",
                            source="filesystem",
                            payload={
                                "changed": changed,
                                "dependents": self._changed_dependents(changed),
                            },
                        )
                    last_index = now
                self.observe_runtime()
                self.observe_logs()
            except Exception as exc:
                self.emit("EXCEPTION", source="god-watcher", priority=100, payload={"error": str(exc)})

    def _keepalive_loop(self) -> None:
        # Immediate warm-up: an event-driven cognitive system should not wait
        # twenty minutes before discovering the model is cold/unreachable.
        self._send_keepalive()
        while not self._stop.wait(self.keepalive_interval_sec):
            self._send_keepalive()

    def _send_keepalive(self) -> None:
        try:
            if self._llm is not None and hasattr(self._llm, "send_keepalive"):
                result = self._llm.send_keepalive()
                self._record_event("llm_keepalive", result)
            else:
                self._record_event("llm_keepalive", {"ok": False, "message": "No keepalive-capable LLM attached"})
        except Exception as exc:
            self._record_event("llm_keepalive_error", {"error": str(exc)})

    # ----- cognition -------------------------------------------------------

    def _cognition_loop(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=0.5)
            if self._stop.is_set():
                break
            self._wake.clear()

            batch = self._drain_coalesced()
            if not batch:
                continue

            now = time.time()
            if now - self._last_inference < self.min_inference_interval_sec:
                # Preserve the information even when throttled. A later event will
                # trigger another synthesis with the accumulated persistent state.
                self._record_event("cognition_deferred", {"events": len(batch)})
                continue

            self._last_inference = now
            try:
                result = self._reason(batch)
                self._record_event("cognition", result)
                if self._cognition_callback:
                    try:
                        self._cognition_callback(result)
                    except Exception:
                        pass
            except Exception as exc:
                self._record_event("cognition_error", {"error": str(exc)})

    def _drain_coalesced(self) -> List[Event]:
        first: List[Event] = []
        deadline = time.time() + self.event_window_sec
        while time.time() < deadline:
            try:
                _, _, event = self._queue.get_nowait()
                first.append(event)
            except queue.Empty:
                time.sleep(0.01)
        if not first:
            try:
                _, _, event = self._queue.get_nowait()
                first.append(event)
            except queue.Empty:
                return []

        # Collapse low-value duplicates but preserve all high-priority events.
        seen_low: set[Tuple[str, str]] = set()
        result: List[Event] = []
        for event in sorted(first, key=lambda e: (-e.priority, e.ts)):
            if event.priority < 50:
                key = (event.kind, json.dumps(event.payload, sort_keys=True, default=str))
                if key in seen_low:
                    continue
                seen_low.add(key)
            result.append(event)
        return result[:64]

    def _reason(self, batch: List[Event]) -> Dict[str, Any]:
        runtime = self._safe_runtime()
        logs = self._safe_logs()
        project = self.core.context(max_chars=14000)
        experiences = self.core.state.get("experiences", [])[-12:]
        lessons = self.core.state.get("lessons", [])[-12:]
        hypotheses = self.core.state.get("hypotheses", [])[-8:]

        event_lines = json.dumps([e.compact() for e in batch], indent=2, ensure_ascii=False, default=str)
        experience_lines = json.dumps(experiences, indent=2, ensure_ascii=False, default=str)
        lesson_lines = json.dumps(lessons, indent=2, ensure_ascii=False, default=str)
        hypothesis_lines = json.dumps(hypotheses, indent=2, ensure_ascii=False, default=str)
        runtime_lines = json.dumps(runtime, indent=2, ensure_ascii=False, default=str)
        log_lines = self._compact_logs(logs, max_chars=8000)

        prompt = f"""EMV GOD — EVENT-DRIVEN COGNITION CYCLE

You are the monitoring/research cognition layer for a deterministic local laboratory.
This is NOT a chat request. A runtime event woke you.

Your job is to learn from evidence over time:
1. correlate the new events with current runtime state, recent logs, project/code changes,
   prior experiences, lessons, and hypotheses;
2. identify what is actually new;
3. distinguish observation from inference;
4. identify contradictions or regressions;
5. propose the next observation needed to resolve uncertainty.

Do not invent protocol values or claim an event occurred unless supported by the supplied evidence.
Do not perform actions. Do not call tools. Do not mutate the stack. You are the observer.
Keep the answer compact and machine-readable using exactly these headings:

OBSERVATION:
INTERPRETATION:
NEW_LESSON:
NEW_HYPOTHESIS:
CONFIDENCE:
NEXT_OBSERVATION:

=== EVENT BATCH ===
{event_lines}

=== CURRENT RUNTIME SNAPSHOT ===
{runtime_lines}

=== PROJECT / CODEBASE MEMORY ===
{project}

=== RECENT LOGS ===
{log_lines}

=== PRIOR EXPERIENCES ===
{experience_lines}

=== PRIOR LESSONS ===
{lesson_lines}

=== OPEN HYPOTHESES ===
{hypothesis_lines}
"""

        response = self._call_llm(prompt)
        learning = self._extract_learning(response)
        event_ids = [str(e.payload.get("event_id")) for e in batch if e.payload.get("event_id")]

        # Persist the model's experience even when it discovers that no lesson is
        # justified. This is what creates a durable audit of cognition itself.
        self.core.record_experience(
            "cognition",
            self._section_value(learning.get("observation")) or "Cognition cycle completed.",
            evidence={
                "events": [e.compact() for e in batch],
                "runtime": runtime,
                "response": response[:12000],
            },
            confidence=learning.get("confidence", 0.0),
            source_event_ids=event_ids,
        )

        if learning.get("lesson"):
            self.core.add_lesson(
                learning["lesson"],
                evidence={
                    "event_ids": event_ids,
                    "confidence": learning.get("confidence", 0.0),
                    "observation": learning.get("observation", ""),
                },
            )
        if learning.get("hypothesis"):
            self.core.add_hypothesis(
                learning["hypothesis"],
                confidence=learning.get("confidence", 0.5),
                supporting=event_ids,
                next_observation=learning.get("next", ""),
            )

        return {
            "ok": True,
            "events": len(batch),
            "response": response,
            "learning": learning,
            "runtime": runtime,
            "event_ids": event_ids,
        }

    def _call_llm(self, prompt: str) -> str:
        if self._llm_callable is not None:
            result = self._llm_callable(prompt)
            return str(result or "").strip()
        if self._llm is None:
            return "OBSERVATION:\nNo LLM attached.\nINTERPRETATION:\nUnavailable.\nNEW_LESSON:\n\nNEW_HYPOTHESIS:\n\nCONFIDENCE:\n0\nNEXT_OBSERVATION:\nAttach a local LLM engine."

        if hasattr(self._llm, "generate_response"):
            # Crucially: use the non-chat generation path. The operator does not
            # need to speak to the model for cognition to run.
            return str(
                self._llm.generate_response(
                    prompt,
                    live_relay_state=self._safe_runtime(),
                    include_history=False,
                    attach_logs=False,
                )
                or ""
            ).strip()
        if callable(self._llm):
            return str(self._llm(prompt) or "").strip()
        raise TypeError("Attached LLM does not expose generate_response() or callable semantics")

    @staticmethod
    def _extract_learning(text: str) -> Dict[str, Any]:
        sections = {
            "observation": "",
            "interpretation": "",
            "lesson": "",
            "hypothesis": "",
            "confidence": 0.0,
            "next": "",
        }
        if not text:
            return sections

        headings = [
            ("observation", "OBSERVATION:"),
            ("interpretation", "INTERPRETATION:"),
            ("lesson", "NEW_LESSON:"),
            ("hypothesis", "NEW_HYPOTHESIS:"),
            ("confidence", "CONFIDENCE:"),
            ("next", "NEXT_OBSERVATION:"),
        ]
        for i, (key, heading) in enumerate(headings):
            start = text.find(heading)
            if start < 0:
                continue
            start += len(heading)
            ends = [text.find(h, start) for _, h in headings[i + 1:] if text.find(h, start) >= 0]
            end = min(ends) if ends else len(text)
            value = text[start:end].strip()
            if key == "confidence":
                m = re.search(r"0(?:\.\d+)?|1(?:\.0+)?", value)
                sections[key] = max(0.0, min(1.0, float(m.group(0)))) if m else 0.0
            else:
                sections[key] = value
        return sections

    @staticmethod
    def _section_value(value: Any) -> str:
        return str(value or "").strip()

    # ----- utilities -------------------------------------------------------

    def _safe_runtime(self) -> Dict[str, Any]:
        if not self._runtime_getter:
            return {}
        try:
            value = self._runtime_getter()
            return value if isinstance(value, dict) else {"value": value}
        except Exception as exc:
            return {"runtime_getter_error": str(exc)}

    def _safe_logs(self) -> Any:
        if not self._logs_getter:
            return []
        try:
            return self._logs_getter()
        except Exception as exc:
            return {"log_getter_error": str(exc)}

    @staticmethod
    def _fingerprint(value: Any) -> str:
        try:
            raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        except Exception:
            raw = repr(value).encode("utf-8", errors="replace")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _dict_delta(before: Any, after: Any) -> Dict[str, Any]:
        if not isinstance(before, dict) or not isinstance(after, dict):
            return {"before": before, "after": after}
        changed: Dict[str, Any] = {}
        for key in set(before) | set(after):
            if before.get(key) != after.get(key):
                changed[key] = {"before": before.get(key), "after": after.get(key)}
        return changed

    @staticmethod
    def _compact_logs(logs: Any, max_chars: int = 6000) -> Any:
        if logs is None:
            return []
        if isinstance(logs, str):
            return logs[-max_chars:]
        if isinstance(logs, list):
            return logs[-80:]
        if isinstance(logs, dict):
            # Keep only bounded recent values; huge logger snapshots are noise.
            clipped = dict(logs)
            for key, value in list(clipped.items()):
                if isinstance(value, list):
                    clipped[key] = value[-80:]
                elif isinstance(value, str) and len(value) > 2000:
                    clipped[key] = value[-2000:]
            return clipped
        return str(logs)[-max_chars:]

    def _changed_dependents(self, changed: Iterable[str]) -> Dict[str, List[str]]:
        deps = self.core.state.get("dependents", {})
        return {path: list(deps.get(path, [])) for path in changed if path in deps}

    def _record_event(self, kind: str, data: Any) -> None:
        try:
            self.core._record(kind, str(data))
            self.core._store.save()
        except Exception:
            pass

    def snapshot(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "root": str(self.root),
            "last_inference": self._last_inference,
            "queue_depth": self._queue.qsize(),
            "runtime": self._safe_runtime(),
            "project": {
                "files": len(self.core.state.get("files", {})),
                "lessons": len(self.core.state.get("lessons", [])),
                "hypotheses": len(self.core.state.get("hypotheses", [])),
                "experiences": len(self.core.state.get("experiences", [])),
            },
        }

    def context(self, max_chars: int = 20000) -> str:
        """Return the durable cognitive context, suitable for external inspection."""
        bundle = {
            "god": self.snapshot(),
            "project": self.core.context(max_chars=max_chars // 2),
            "recent_experiences": self.core.state.get("experiences", [])[-20:],
            "lessons": self.core.state.get("lessons", [])[-20:],
            "hypotheses": self.core.state.get("hypotheses", [])[-12:],
        }
        return json.dumps(bundle, ensure_ascii=False, indent=2, default=str)[:max_chars]

    def learn(self, statement: str, *, evidence: Optional[Dict[str, Any]] = None, confidence: float = 1.0) -> Experience:
        """Explicit human-validated learning hook."""
        exp = self.core.record_experience(
            "operator_validated",
            statement,
            evidence=evidence,
            confidence=confidence,
        )
        self.core.add_lesson(statement, evidence=evidence)
        return exp


# ---------------------------------------------------------------------------
# Convenience singleton for the Qt adapter
# ---------------------------------------------------------------------------

_default_god: Optional[EMVGod] = None
_default_lock = threading.Lock()


def get_god(root: Optional[Path] = None, **kwargs: Any) -> EMVGod:
    global _default_god
    with _default_lock:
        if _default_god is None:
            resolved = Path(root) if root is not None else Path(__file__).resolve().parent
            _default_god = EMVGod(resolved, **kwargs)
        return _default_god


def start_god(root: Optional[Path] = None, **kwargs: Any) -> EMVGod:
    god = get_god(root, **kwargs)
    god.start()
    return god


def stop_god() -> None:
    global _default_god
    with _default_lock:
        if _default_god is not None:
            _default_god.stop()


__all__ = [
    "FileState",
    "Event",
    "Experience",
    "EMVGodCore",
    "EMVProjectIntelligence",
    "EMVGod",
    "get_god",
    "start_god",
    "stop_god",
]
