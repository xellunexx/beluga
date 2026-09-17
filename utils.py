# -*- coding: utf-8 -*-
"""Logging and auditing utilities."""

from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("RelayServer")


def log_mutation(session_id: str, phase: str, mutation: str,
                 before: bytes, after: bytes, reason: str) -> Dict[str, Any]:
    """Log structured record for a mutation."""
    before_hex = before.hex() if isinstance(before, (bytes, bytearray)) else str(before)
    after_hex = after.hex() if isinstance(after, (bytes, bytearray)) else str(after)
    record = {
        "session_id": str(session_id),
        "phase": str(phase),
        "mutation": str(mutation),
        "before": before_hex,
        "after": after_hex,
        "reason": str(reason),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }
    logger.info(json.dumps(record))
    return record


def record_audit_trail(session_id: str, entry: Dict[str, Any], audit_dir: str = "logs") -> Path:
    """Persist a per-session audit file (session_<id>.json)."""
    p = Path(audit_dir)
    p.mkdir(parents=True, exist_ok=True)
    audit_file = p / f"session_{session_id}.json"
    data = []
    if audit_file.exists():
        try:
            with open(audit_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, list):
                    data = [data]
        except Exception:
            data = []
    data.append(entry)
    with open(audit_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return audit_file
