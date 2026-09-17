# -*- coding: utf-8 -*-
"""Persistent long-term memory store for the REL8 Stack AI agent.

Provides durable fact retention, rolling conversation digests, session
continuity, and prompt rendering so the agent maintains memory, awareness,
and presence across app restarts. All storage lives in a single JSON file
(memory.json) inside the project root and is fully thread-safe.
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

MEMORY_SCHEMA_VERSION = 1
MAX_SESSION_RECORDS = 25
MAX_RESTORED_HISTORY_TURNS = 40
DEFAULT_DIGEST_MAX_CHARS = 1500
DEFAULT_PROMPT_MAX_CHARS = 1800

_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with",
    "is", "are", "was", "were", "be", "been", "it", "this", "that", "these",
    "those", "we", "you", "i", "our", "your", "my", "me", "us", "do", "did",
    "does", "what", "when", "where", "which", "who", "how", "why", "can",
    "could", "should", "would", "please", "tell", "show", "give", "about",
}


class AgentMemoryStore:
    """Durable key-fact memory + rolling session digest persisted to JSON."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.data: Dict[str, Any] = {
            "version": MEMORY_SCHEMA_VERSION,
            "facts": {},
            "session_digest": "",
            "last_session_history": [],
            "sessions": [],
            "stats": {"total_turns": 0, "total_sessions": 0, "total_facts_stored": 0},
        }
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        with self._lock:
            if not self.path.exists():
                return
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                return
            if not isinstance(raw, dict):
                return
            for key in ("facts", "session_digest", "last_session_history", "sessions", "stats"):
                if key in raw and isinstance(raw[key], type(self.data[key])):
                    self.data[key] = raw[key]

    def save(self) -> None:
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                payload = dict(self.data)
                payload["version"] = MEMORY_SCHEMA_VERSION
                self.path.write_text(
                    json.dumps(payload, indent=2, default=str),
                    encoding="utf-8",
                )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Durable facts (agent self-managed via tools)
    # ------------------------------------------------------------------

    def remember(self, key: str, value: str, category: str = "general", source: str = "agent") -> Dict[str, Any]:
        key_clean = (key or "").strip()
        value_clean = (value or "").strip()
        if not key_clean or not value_clean:
            raise ValueError("Both key and value must be non-empty to store a memory fact.")

        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            existing = self.data["facts"].get(key_clean, {})
            self.data["facts"][key_clean] = {
                "value": value_clean,
                "category": (category or "general").strip().lower(),
                "source": source,
                "created": existing.get("created", now),
                "updated": now,
            }
            self.data["stats"]["total_facts_stored"] = int(self.data["stats"].get("total_facts_stored", 0)) + 1
        self.save()
        return {
            "stored": True,
            "key": key_clean,
            "category": (category or "general").strip().lower(),
            "updated": now,
            "total_facts": len(self.data["facts"]),
        }

    def recall(self, query: str = "", max_results: int = 10) -> List[Dict[str, Any]]:
        query_clean = (query or "").strip().lower()
        terms = [t for t in re.split(r"[^a-zA-Z0-9_]+", query_clean) if t and t not in _STOPWORDS]

        with self._lock:
            facts = dict(self.data["facts"])

        scored: List[tuple] = []
        for key, meta in facts.items():
            haystack = f"{key} {meta.get('value', '')} {meta.get('category', '')}".lower()
            if not terms:
                score = 1
            else:
                score = sum(1 for t in terms if t in haystack)
                if query_clean and query_clean in haystack:
                    score += len(terms) + 1
            if score > 0:
                scored.append((score, meta.get("updated", ""), key, meta))

        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        results = []
        for score, _updated, key, meta in scored[:max_results]:
            results.append({
                "key": key,
                "value": meta.get("value", ""),
                "category": meta.get("category", "general"),
                "updated": meta.get("updated", ""),
                "relevance": score,
            })
        return results

    def forget(self, key: str) -> bool:
        key_clean = (key or "").strip()
        with self._lock:
            if key_clean in self.data["facts"]:
                del self.data["facts"][key_clean]
                removed = True
            else:
                removed = False
        if removed:
            self.save()
        return removed

    def fact_count(self) -> int:
        with self._lock:
            return len(self.data["facts"])

    # ------------------------------------------------------------------
    # Rolling conversation digest (memory beyond the verbatim window)
    # ------------------------------------------------------------------

    @staticmethod
    def summarize_turns(turns: List[Dict[str, str]], max_chars: int = DEFAULT_DIGEST_MAX_CHARS) -> str:
        """Heuristically condenses older chat turns into a compact digest (no LLM call)."""
        lines: List[str] = []
        for turn in turns:
            role = turn.get("role", "?")
            content = (turn.get("content", "") or "").strip()
            if not content:
                continue

            label = {"user": "Operator", "assistant": "Agent", "system": "System"}.get(role, role.title())
            salient: List[str] = []

            for tool_name in re.findall(r"!tool\s+([a-zA-Z0-9_]+)", content):
                salient.append(f"invoked tool `{tool_name}`")
            for match in re.findall(r"(?:ACTION|DECISION|RESULT|CONCLUSION)\s*:\s*([^\n]{5,120})", content):
                salient.append(match.strip())

            first_line = next((ln.strip() for ln in content.splitlines() if ln.strip()), "")
            first_line = re.sub(r"\s+", " ", first_line)[:140]
            if first_line:
                salient.append(first_line)

            if not salient:
                continue
            lines.append(f"- {label}: " + " | ".join(dict.fromkeys(salient)))

        digest = "\n".join(lines)
        if len(digest) > max_chars:
            digest = "[...earlier turns condensed...]\n" + digest[-max_chars:]
        return digest

    def get_digest(self) -> str:
        with self._lock:
            return str(self.data.get("session_digest", ""))

    def set_digest(self, digest: str) -> None:
        with self._lock:
            self.data["session_digest"] = digest

    def append_to_digest(self, extra: str, max_chars: int = DEFAULT_DIGEST_MAX_CHARS) -> None:
        extra = (extra or "").strip()
        if not extra:
            return
        with self._lock:
            combined = (self.data.get("session_digest", "") + "\n" + extra).strip()
            if len(combined) > max_chars:
                combined = "[...earlier turns condensed...]\n" + combined[-max_chars:]
            self.data["session_digest"] = combined

    # ------------------------------------------------------------------
    # Session continuity
    # ------------------------------------------------------------------

    def record_session_start(self, session_id: str) -> None:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            self.data["sessions"].append({
                "session_id": session_id,
                "started": now,
                "restored_turns": len(self.data.get("last_session_history", [])),
            })
            self.data["sessions"] = self.data["sessions"][-MAX_SESSION_RECORDS:]
            self.data["stats"]["total_sessions"] = int(self.data["stats"].get("total_sessions", 0)) + 1
        self.save()

    def record_turns(self, count: int = 1) -> None:
        with self._lock:
            self.data["stats"]["total_turns"] = int(self.data["stats"].get("total_turns", 0)) + count

    def persist_chat_history(self, history: List[Dict[str, str]]) -> None:
        with self._lock:
            self.data["last_session_history"] = [
                {"role": m.get("role", "user"), "content": m.get("content", ""), "ts": m.get("ts", "")}
                for m in history[-MAX_RESTORED_HISTORY_TURNS:]
            ]
        self.save()

    def get_restorable_history(self, max_turns: int = 20) -> List[Dict[str, str]]:
        with self._lock:
            history = list(self.data.get("last_session_history", []))
        return history[-max_turns:]

    # ------------------------------------------------------------------
    # Prompt rendering (awareness & presence injection)
    # ------------------------------------------------------------------

    def render_for_prompt(self, max_chars: int = DEFAULT_PROMPT_MAX_CHARS) -> str:
        with self._lock:
            facts = dict(self.data["facts"])
            digest = str(self.data.get("session_digest", ""))
            stats = dict(self.data["stats"])

        lines = [
            f"Memory Stats: {len(facts)} durable fact(s) | "
            f"{stats.get('total_sessions', 0)} total session(s) | "
            f"{stats.get('total_turns', 0)} lifetime turn(s)",
        ]

        if facts:
            by_category: Dict[str, List[str]] = {}
            for key, meta in facts.items():
                by_category.setdefault(meta.get("category", "general"), []).append(
                    f"{key} = {meta.get('value', '')}"
                )
            lines.append("Durable Facts:")
            for category in sorted(by_category):
                lines.append(f"  [{category}]")
                for entry in by_category[category][:12]:
                    lines.append(f"    - {entry}")

        if digest:
            lines.append("Conversation Digest (older turns, condensed):")
            lines.append(digest)

        if len(lines) <= 1 and not digest:
            lines.append("No durable memories recorded yet. Use `remember_fact` to retain important findings.")

        rendered = "\n".join(lines)
        if len(rendered) > max_chars:
            rendered = rendered[:max_chars].rstrip() + "\n[...memory truncated for prompt budget...]"
        return rendered
