# -*- coding: utf-8 -*-
# logger.py
# -*- coding: utf-8 -*-
"""Logging configuration, PAN masking, APDU history."""

from __future__ import annotations
import os
import logging
import time
import uuid
import re
from datetime import datetime, timezone
from collections import deque
from threading import Lock
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, List, Optional

from constants import LOG_FILE, LOG_LEVEL, APDU_HISTORY_SIZE

log = logging.getLogger("RelayServer")
LOW_LATENCY_MODE = os.environ.get("RELAY_LOW_LATENCY", "").strip().lower() in {"1", "true", "yes", "on"}
ENABLE_FILE_LOG = os.environ.get("RELAY_ENABLE_FILE_LOG", "1").strip().lower() not in {"0", "false", "no", "off"}
ENABLE_TX_LOG = os.environ.get("RELAY_ENABLE_TX_LOG", "1").strip().lower() not in {"0", "false", "no", "off"}

# --- APDU history ---
_apdu_history: deque = deque(maxlen=APDU_HISTORY_SIZE)
_apdu_history_lock = Lock()
_log_history: deque = deque(maxlen=2000)
_log_history_lock = Lock()


class TransactionFileHandler(logging.Handler):
    """Write each PPSE-delimited transaction to its own log file."""

    PPSE_HEX = "325041592E5359532E4444463031"
    END_MARKERS = (
        "Session epoch opened:",
        "Session reset (card removed)",
        "RelayServer stopped",
    )

    def __init__(self, directory: str) -> None:
        super().__init__(logging.DEBUG)
        self.directory = directory
        self._stream = None
        self._sequence = 0
        os.makedirs(directory, exist_ok=True)

    @classmethod
    def _is_start(cls, message: str) -> bool:
        return (message.startswith("APDU ")
                and " CAPDU SELECT " in message
                and cls.PPSE_HEX in message)

    def _open_transaction(self, created: float) -> None:
        self._close_transaction()
        self._sequence += 1
        timestamp = datetime.fromtimestamp(created, timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        path = os.path.join(self.directory, f"tx_{timestamp}_{self._sequence:04d}.log")
        self._stream = open(path, "a", encoding="utf-8", buffering=1)

    def _close_transaction(self) -> None:
        if self._stream is not None:
            self._stream.flush()
            self._stream.close()
            self._stream = None

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
            if self._is_start(message):
                self._open_transaction(record.created)
            if self._stream is None:
                return
            self._stream.write(self.format(record) + "\n")
            if any(marker in message for marker in self.END_MARKERS):
                self._close_transaction()
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        self._close_transaction()
        super().close()


class RingBufferLogHandler(logging.Handler):
    """In-memory structured log stream for Flask UI polling."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            with _log_history_lock:
                _log_history.append({
                    "ts": record.created,
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                })
        except Exception:
            self.handleError(record)

# --- PAN Masking & Correlation Helpers ---
_current_transaction_id: Optional[str] = None

def set_current_transaction_id(tx_id: Optional[str] = None) -> str:
    """Set or generate current transaction correlation ID."""
    global _current_transaction_id
    if tx_id is None:
        _current_transaction_id = str(uuid.uuid4())
    else:
        _current_transaction_id = tx_id
    return _current_transaction_id

def get_current_transaction_id() -> Optional[str]:
    """Return active transaction correlation ID."""
    return _current_transaction_id

def mask_pan(pan: str | bytes, pan_mask: str = "XXXX-XXXX-XXXX-####") -> str:
    """Mask Primary Account Number (PAN) preserving first 6 and last 4 digits."""
    if isinstance(pan, bytes):
        pan_str = pan.hex().upper()
    else:
        pan_str = str(pan)
    digits = re.sub(r"\D", "", pan_str)
    if len(digits) < 10:
        return pan_str
    masked = digits[:6] + ("*" * (len(digits) - 10)) + digits[-4:]
    return masked


def _record_apdu(direction: str = "C->S", kind: str = "CAPDU", ins_name: str = "",
                 payload: bytes = b"", note: str = "", corr_id: Optional[str] = None) -> None:
    if LOW_LATENCY_MODE:
        return
    hex_str = payload.hex().upper()
    active_corr_id = corr_id or _current_transaction_id
    entry: Dict[str, Any] = {
        "ts": round(time.time(), 3),
        "direction": direction, "kind": kind, "ins": ins_name,
        "hex": hex_str, "len": len(payload), "note": note,
        "corr_id": active_corr_id,
    }
    with _apdu_history_lock:
        _apdu_history.append(entry)
    suffix = f" [{note}]" if note else ""
    corr_prefix = f"[{active_corr_id}] " if active_corr_id else ""
    if log.isEnabledFor(logging.DEBUG):
        log.debug(f"{corr_prefix}APDU {direction} {kind} {ins_name} len={len(payload)}: {hex_str}{suffix}")

def clear_apdu_history() -> None:
    with _apdu_history_lock:
        _apdu_history.clear()


def get_log_records(n: int = 100) -> list:
    with _log_history_lock:
        return list(_log_history)[-n:]


def clear_log_records() -> None:
    with _log_history_lock:
        _log_history.clear()

def configure_logging() -> None:
    """Attach runtime handlers once."""
    log.setLevel(logging.DEBUG)
    if any(getattr(handler, "_relay_runtime_handler", False) for handler in log.handlers):
        return
    formatter = logging.Formatter(
        "%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    ring = RingBufferLogHandler()
    ring._relay_runtime_handler = True
    ring.setLevel(logging.DEBUG)
    log.addHandler(ring)

    stdout = logging.StreamHandler()
    stdout._relay_runtime_handler = True
    stdout.setFormatter(formatter)
    stdout.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    log.addHandler(stdout)
    if ENABLE_FILE_LOG:
        try:
            file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5)
            file_handler._relay_runtime_handler = True
            file_handler.setFormatter(formatter)
            file_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
            log.addHandler(file_handler)
            log.info(f"File logging enabled: {LOG_FILE}")
        except OSError as exc:
            log.warning(f"Could not open log file {LOG_FILE}: {exc} - stdout only")
    if ENABLE_TX_LOG and not LOW_LATENCY_MODE:
        try:
            tx_directory = os.path.join(os.path.dirname(LOG_FILE), "logs")
            tx_handler = TransactionFileHandler(tx_directory)
            tx_handler._relay_runtime_handler = True
            tx_handler.setFormatter(formatter)
            log.addHandler(tx_handler)
            log.info(f"Per-transaction logging enabled: {tx_directory}")
        except OSError as exc:
            log.warning(f"Could not enable per-transaction logging: {exc}")

    # Check for concatenated module files
    try:
        import protocol as _proto_check
        if hasattr(_proto_check, "PacketRouter"):
            raise ImportError("protocol.py and packet_router.py must be separate files")
    except ImportError:
        pass
    try:
        import packet_router as _pr_check
        if hasattr(_pr_check, "CommandAPDU"):
            raise ImportError("protocol.py and packet_router.py must be separate files")
    except ImportError:
        pass

# --- Convenience access for history ---
def get_apdu_history(n: int = 20) -> list:
    with _apdu_history_lock:
        return list(_apdu_history)[-n:]


def set_log_level(level_name: str) -> str:
    """Dynamically change the log level on stdout and file handlers.
    The ring buffer always stays at DEBUG so the web UI can see everything.
    Returns the previous level name."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    prev = "INFO"
    for handler in log.handlers:
        if getattr(handler, "_relay_runtime_handler", False):
            if not isinstance(handler, RingBufferLogHandler):
                prev = logging.getLevelName(handler.level)
                handler.setLevel(level)
    log.info(f"Log level changed: {prev} -> {level_name.upper()}")
    return prev


def get_log_stats() -> dict:
    """Return counts of buffered log records by level for monitoring."""
    with _log_history_lock:
        records = list(_log_history)
    counts: dict = {}
    for r in records:
        lvl = r.get("level", "?")
        counts[lvl] = counts.get(lvl, 0) + 1
    return {
        "total": len(records),
        "by_level": counts,
        "apdu_history_size": len(_apdu_history),
    }


def clear_all() -> None:
    """Clear both APDU history and log ring buffer.
    Called on SOFT_RESET / SESSION_RESET to give a clean slate."""
    clear_apdu_history()
    clear_log_records()
