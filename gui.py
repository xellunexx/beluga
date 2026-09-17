from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, Response, jsonify, request, session

try:
    from .logger import clear_apdu_history, clear_log_records, get_apdu_history, get_log_records
    from .rel8hf import RelayServer
    from .rel8hf_launcher import DEFAULT_CONFIG_PATH, LaunchConfig
except ImportError:
    from logger import clear_apdu_history, clear_log_records, get_apdu_history, get_log_records
    from rel8hf import RelayServer
    from rel8hf_launcher import DEFAULT_CONFIG_PATH, LaunchConfig


ROOT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT_DIR.parent
PROFILES_DIR = ROOT_DIR / "profiles"
LAST_TEST_REPORT = ROOT_DIR / "last_test_report.txt"


def _csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = uuid.uuid4().hex
        session["csrf_token"] = token
    return token


class RelayManager:
    def __init__(self, base_config: LaunchConfig) -> None:
        self.base_config = base_config
        self.thread: Optional[threading.Thread] = None
        self.server: Optional[RelayServer] = None
        self.running = False
        self.lock = threading.Lock()
        self.active_config: Dict[str, Any] = {}
        self.last_start_ts = 0.0
        self.metrics = {
            "starts_total": 0,
            "stops_total": 0,
            "requests_total": 0,
            "success_total": 0,
            "failure_total": 0,
            "last_latency_ms": 0.0,
        }

    def is_running(self) -> bool:
        with self.lock:
            return self.running

    def start(self, config_payload: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            if self.running:
                return {"ok": False, "error": "already_running"}
            cfg = build_config_from_payload(config_payload)
            errors = validate_runtime_dependencies(cfg)
            if errors:
                return {"ok": False, "error": "validation_failed", "details": errors}
            cfg.apply_env()
            srv = RelayServer(host=cfg.host, port=cfg.port)
            cfg.apply_runtime_state(srv)

            def run() -> None:
                try:
                    srv.start()
                except Exception:
                    pass

            t = threading.Thread(target=run, daemon=True)
            t.start()
            deadline = time.time() + 2.0
            while time.time() < deadline:
                if srv.running and srv.sock is not None:
                    break
                if not t.is_alive() and not srv.running:
                    break
                time.sleep(0.01)
            if not srv.running or srv.sock is None:
                return {"ok": False, "error": "start_failed"}
            self.server = srv
            self.thread = t
            self.running = True
            self.last_start_ts = time.time()
            self.active_config = cfg.to_dict()
            cfg.write_json(DEFAULT_CONFIG_PATH)
            self.metrics["starts_total"] += 1
            return {"ok": True}

    def stop(self) -> Dict[str, Any]:
        with self.lock:
            if not self.running or not self.server:
                return {"ok": False, "error": "not_running"}
            try:
                self.server.stop()
            except Exception:
                pass
            self.server = None
            self.thread = None
            self.running = False
            self.active_config = {}
            self.metrics["stops_total"] += 1
            return {"ok": True}


class TestRunner:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.proc: Optional[subprocess.Popen[str]] = None
        self.thread: Optional[threading.Thread] = None
        self.lines: List[str] = []
        self.running = False
        self.return_code: Optional[int] = None
        self.selected: List[str] = []

    def _collect(self) -> None:
        proc = self.proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            with self.lock:
                self.lines.append(line.rstrip("\n"))
        code = proc.wait()
        with self.lock:
            self.return_code = code
            self.running = False
            LAST_TEST_REPORT.write_text("\n".join(self.lines) + "\n", encoding="utf-8")

    def start(self, test_paths: List[str]) -> Dict[str, Any]:
        with self.lock:
            if self.running:
                return {"ok": False, "error": "tests_already_running"}
            self.lines = []
            self.return_code = None
            self.selected = test_paths
            cmd = [sys.executable, "-m", "pytest", "-q", *test_paths]
            self.proc = subprocess.Popen(
                cmd,
                cwd=str(ROOT_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            self.running = True
            self.thread = threading.Thread(target=self._collect, daemon=True)
            self.thread.start()
            return {"ok": True, "command": cmd}

    def stop(self) -> Dict[str, Any]:
        with self.lock:
            if not self.running or not self.proc:
                return {"ok": False, "error": "tests_not_running"}
            self.proc.terminate()
            return {"ok": True}

    def status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "running": self.running,
                "return_code": self.return_code,
                "lines": len(self.lines),
                "selected": self.selected,
            }

    def output_since(self, cursor: int) -> Dict[str, Any]:
        with self.lock:
            safe_cursor = max(0, min(cursor, len(self.lines)))
            return {
                "ok": True,
                "cursor": len(self.lines),
                "chunk": self.lines[safe_cursor:],
                "running": self.running,
                "return_code": self.return_code,
            }


def runtime_descriptors() -> Dict[str, Any]:
    return {
        "settings": {
            "host": "UDP bind host for relay listener.",
            "port": "UDP bind port for relay listener.",
            "policy_mode": "Transaction policy routing mode (OFFLINE_NOCVM, ONLINE, AUTO).",
            "policy_amount_cents": "Amount threshold used by policy logic and routing decisions.",
            "outcome_guard": "Normalize PIN-path failures and prevent lockout cascades.",
            "guard_verbose": "Enable verbose guard state-transition logs.",
            "full_output": "Emit full APDU and protocol trace output.",
            "gpo_force_success": "Fallback to synthetic GPO success on common failure SW codes.",
            "tp_enabled": "Enable terminal-probe hinting integration path.",
            "tp_strict_online": "When TP is enabled, force online-preferred behavior on strict terminals.",
            "capdu_sig_verify": "Verify trailing 9F45 signature on GENERATE AC CAPDU.",
            "capdu_sig_strip": "Strip 9F45 tail after successful verification.",
            "capdu_sig_pubkey": "Public key path used when CAPDU signature verify is enabled.",
            "verify_bypass": "Enable VERIFY APDU bypass behavior.",
            "arpc_forge": "Enable second GAC/ARPC forge path.",
            "arpc_rewrite": "Rewrite ARPC content in CAPDU path.",
            "tvr_mutate": "Enable TVR mutation branch in GAC path.",
            "synth_plugin_enabled": "Enable optional EMV synthesizer plugin bridge for GPO rewrite.",
            "synth_amount": "Synthesizer amount value for 9F02 (numeric, cents).",
            "synth_currency_code": "Synthesizer currency code for 5F2A (numeric code, e.g. 978).",
            "synth_country_code": "Synthesizer country code for 9F1A (numeric code, e.g. 250).",
        }
    }


def validate_runtime_dependencies(cfg: LaunchConfig) -> List[str]:
    errors = list(cfg.validate())
    if not cfg.tp_enabled and cfg.tp_strict_online:
        errors.append("tp_strict_online requires tp_enabled=true")
    if not cfg.capdu_sig_verify and cfg.capdu_sig_pubkey:
        pass
    if not cfg.capdu_sig_verify and not cfg.capdu_sig_strip:
        errors.append("capdu_sig_strip=false is invalid while capdu_sig_verify=false")
    if not cfg.arpc_forge and cfg.arpc_rewrite:
        errors.append("arpc_rewrite requires arpc_forge=true")
    return errors


def build_config_from_payload(payload: Dict[str, Any]) -> LaunchConfig:
    cfg = LaunchConfig()
    for field_name in LaunchConfig.__dataclass_fields__:
        if field_name in payload:
            setattr(cfg, field_name, payload[field_name])
    if not cfg.tp_enabled:
        cfg.tp_strict_online = False
    if not cfg.capdu_sig_verify:
        cfg.capdu_sig_strip = True
    if not cfg.arpc_forge:
        cfg.arpc_rewrite = False
    return cfg


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _normalize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(payload or {})
    plugin_field = normalized.get("plugin")
    if "synth_plugin_enabled" not in normalized and plugin_field is not None:
        if isinstance(plugin_field, str):
            selected_plugins = [p.strip() for p in plugin_field.split(",") if p.strip()]
        elif isinstance(plugin_field, list):
            selected_plugins = [str(p).strip() for p in plugin_field if str(p).strip()]
        else:
            selected_plugins = []
        normalized["synth_plugin_enabled"] = "mod_emv_synthesizer" in selected_plugins

    legacy_map = {
        "amount": "synth_amount",
        "currency_code": "synth_currency_code",
        "country_code": "synth_country_code",
    }
    for legacy_key, modern_key in legacy_map.items():
        if legacy_key in normalized and modern_key not in normalized:
            normalized[modern_key] = normalized[legacy_key]

    bool_fields = {
        "outcome_guard", "guard_verbose", "full_output", "gpo_force_success", "tp_enabled",
        "tp_strict_online", "capdu_sig_verify", "capdu_sig_strip", "verify_bypass", "arpc_forge",
        "arpc_rewrite", "tvr_mutate", "synth_plugin_enabled",
    }
    int_fields = {"port", "policy_amount_cents", "synth_amount", "synth_currency_code", "synth_country_code"}
    for key in bool_fields:
        if key in normalized:
            normalized[key] = _coerce_bool(normalized[key])
    for key in int_fields:
        if key in normalized:
            try:
                normalized[key] = int(normalized[key])
            except (TypeError, ValueError):
                pass
    return normalized


def _list_rel8_tests() -> List[str]:
    tests_dir = ROOT_DIR / "tests"
    return sorted([f"tests/{p.name}" for p in tests_dir.glob("test_*.py")])


def _load_reference_gui_template() -> str:
    ref_file = PROJECT_ROOT / "targetattempt" / "attempt.py"
    try:
        src = ref_file.read_text(encoding="utf-8")
    except Exception:
        src = ""

    html = ""
    anchor = '@app.get("/")'
    i0 = src.find(anchor)
    if i0 >= 0:
        i1 = src.find('html = r"""', i0)
        if i1 >= 0:
            i1 += len('html = r"""')
            i2 = src.find('"""', i1)
            if i2 >= 0:
                html = src[i1:i2]

    if not html:
        html = (
            "<!DOCTYPE html>\n<html>\n<head><title>REL8HF Relay & Orchestrator Pro</title></head>\n"
            "<body>\n<h1>REL8HF Relay & Orchestrator Pro</h1>\n"
            "<div id=\"tab-plugins\"><div id=\"plugin-catalog-grid\">"
            "<div class=\"plugin-item\"><input type=\"checkbox\" value=\"mod_emv_synthesizer\" /></div>"
            "</div></div>\n"
            "<span id=\"plugin-quick-note\"></span>\n"
            "<select id=\"cfg-quick-plugin\"><option value=\"mod_emv_synthesizer\">mod_emv_synthesizer</option></select>\n"
            "<div id=\"log-terminal\"></div>\n"
            "<script>\n"
            "      const el = document.getElementById('log-terminal');\n"
            "      const wasNearBottom = (el.scrollHeight - (el.scrollTop + el.clientHeight)) <= 24;\n"
            "      if (wasNearBottom) el.scrollTop = el.scrollHeight;\n"
            "</script>\n"
            "</body>\n</html>"
        )
    else:
        html = html.replace("EMV Relay & Orchestrator Pro", "REL8HF Relay & Orchestrator Pro")
        html = html.replace("/metrics/prometheus", "/prometheus")
        html = html.replace('renderPluginCatalog(["emv_basic"]);', 'renderPluginCatalog(["mod_emv_synthesizer"]);')
        html = html.replace(
            "      const el = document.getElementById('log-terminal');",
            "      const el = document.getElementById('log-terminal');\n"
            "      const wasNearBottom = (el.scrollHeight - (el.scrollTop + el.clientHeight)) <= 24;",
        )
        html = html.replace(
            "      el.scrollTop = el.scrollHeight;",
            "      if (wasNearBottom) el.scrollTop = el.scrollHeight;",
        )

    inject = r"""
<script>
  (function rel8Bridge(){
    const SYNTH_PLUGIN = 'mod_emv_synthesizer';
    const REL8_FIELDS = ['synth_plugin_enabled', 'synth_amount', 'synth_currency_code', 'synth_country_code'];
    let rel8Cfg = { synth_plugin_enabled: false };
    let rel8Desc = {};
    let rel8CsrfToken = '';

    const _rawFetch = window.fetch.bind(window);

    async function ensureCsrf(){
      if (rel8CsrfToken) return rel8CsrfToken;
      try {
        const r = await _rawFetch('/csrf', { credentials: 'same-origin' });
        const j = await r.json();
        rel8CsrfToken = j.token || '';
      } catch(e) {
        rel8CsrfToken = '';
      }
      return rel8CsrfToken;
    }

    function syncPluginBadge(){
      const note = document.getElementById('plugin-quick-note');
      if (note) note.textContent = 'Active chain: ' + (rel8Cfg.synth_plugin_enabled ? SYNTH_PLUGIN : 'none');
      const quick = document.getElementById('cfg-quick-plugin');
      if (quick) {
        for (const opt of quick.options) {
          const keep = (opt.value === '' || opt.value === 'custom' || opt.value === SYNTH_PLUGIN);
          opt.disabled = !keep;
          opt.hidden = !keep;
        }
        quick.value = rel8Cfg.synth_plugin_enabled ? SYNTH_PLUGIN : 'custom';
      }
    }

    function constrainPluginUi(){
      const rows = document.querySelectorAll('#plugin-catalog-grid .plugin-item');
      let synthCheck = null;
      rows.forEach(row => {
        const chk = row.querySelector('input[type="checkbox"]');
        if (!chk) return;
        if (chk.value === SYNTH_PLUGIN) {
          synthCheck = chk;
          row.style.display = 'flex';
          chk.disabled = false;
          chk.checked = !!rel8Cfg.synth_plugin_enabled;
          chk.onchange = () => {
            rel8Cfg.synth_plugin_enabled = !!chk.checked;
            syncPluginBadge();
          };
        } else {
          chk.checked = false;
          chk.disabled = true;
          row.style.display = 'none';
        }
      });
      if (!synthCheck) {
        rel8Cfg.synth_plugin_enabled = false;
      }
      syncPluginBadge();
    }

    function ensureRuntimeSettingsCard(){
      const tab = document.getElementById('tab-plugins');
      if (!tab || document.getElementById('rel8-runtime-card')) return;
      const card = document.createElement('div');
      card.id = 'rel8-runtime-card';
      card.className = 'card';
      card.style.marginTop = '14px';
      card.innerHTML = `
        <div class="card-title">
          <span><span class="icon">⚙️</span> Synthesizer Runtime Settings</span>
          <span class="badge active-cyan">REL8</span>
        </div>
        <p style="font-size:0.82rem; color:var(--text-muted); margin-bottom:14px;">
          Settings below are applied on next relay start and attached to the start payload.
        </p>
        <div id="rel8-runtime-grid" class="grid grid-2"></div>
      `;
      tab.appendChild(card);
    }

    function renderRuntimeSettings(){
      ensureRuntimeSettingsCard();
      const grid = document.getElementById('rel8-runtime-grid');
      if (!grid) return;
      grid.innerHTML = '';
      REL8_FIELDS.forEach(k => {
        if (!(k in rel8Cfg)) return;
        const val = rel8Cfg[k];
        const wrap = document.createElement('div');
        wrap.className = 'form-group';
        const label = document.createElement('label');
        label.textContent = k;
        wrap.appendChild(label);
        if (typeof val === 'boolean') {
          const cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.checked = !!val;
          cb.onchange = () => {
            rel8Cfg[k] = !!cb.checked;
            constrainPluginUi();
          };
          wrap.appendChild(cb);
        } else {
          const inp = document.createElement('input');
          inp.type = 'number';
          inp.value = Number.isFinite(Number(val)) ? String(val) : '0';
          inp.oninput = () => {
            rel8Cfg[k] = parseInt(inp.value || '0', 10);
          };
          wrap.appendChild(inp);
        }
        if (rel8Desc[k]) {
          const note = document.createElement('small');
          note.style.color = 'var(--text-muted)';
          note.textContent = rel8Desc[k];
          wrap.appendChild(note);
        }
        grid.appendChild(wrap);
      });
    }

    function removeUnsupportedDropdownMenus(){
      const defaults = {
        'cfg-preset': '',
        'cfg-ttq': '36004000',
        'cfg-mode': 'relay',
      };
      Object.entries(defaults).forEach(([id, fallbackValue]) => {
        const original = document.getElementById(id);
        if (!original) return;
        const group = original.closest('.form-group');
        if (group) {
          group.remove();
        } else {
          original.remove();
        }
        const hidden = document.createElement('input');
        hidden.type = 'hidden';
        hidden.id = id;
        hidden.value = String(fallbackValue);
        document.body.appendChild(hidden);
      });
    }

    window.fetch = async function(input, init){
      const opts = Object.assign({}, init || {});
      const method = String(opts.method || 'GET').toUpperCase();
      const headers = new Headers(opts.headers || {});

      if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
        const tok = await ensureCsrf();
        if (tok && !headers.has('X-CSRF-Token')) {
          headers.set('X-CSRF-Token', tok);
        }
      }

      let target = '';
      if (typeof input === 'string') target = input;
      else if (input && typeof input.url === 'string') target = input.url;

      if (method === 'POST' && target.includes('/start')) {
        try {
          const payload = opts.body ? JSON.parse(opts.body) : {};
          const selected = String(payload.plugin || '').split(',').map(s => s.trim()).filter(Boolean);
          const synthEnabled = selected.includes(SYNTH_PLUGIN) || !!rel8Cfg.synth_plugin_enabled;
          payload.synth_plugin_enabled = synthEnabled;
          payload.synth_amount = Number(rel8Cfg.synth_amount || 0);
          payload.synth_currency_code = Number(rel8Cfg.synth_currency_code || 0);
          payload.synth_country_code = Number(rel8Cfg.synth_country_code || 0);
          payload.mode = 'relay';
          opts.body = JSON.stringify(payload);
        } catch (e) {}
      }

      opts.headers = headers;
      if (!opts.credentials) {
        opts.credentials = 'same-origin';
      }
      return _rawFetch(input, opts);
    };

    window.getSelectedPlugins = function(){
      return rel8Cfg.synth_plugin_enabled ? [SYNTH_PLUGIN] : [];
    };

    const _origRenderPluginCatalog = window.renderPluginCatalog;
    if (typeof _origRenderPluginCatalog === 'function') {
      window.renderPluginCatalog = function(activeList){
        _origRenderPluginCatalog(Array.isArray(activeList) ? activeList : [SYNTH_PLUGIN]);
        constrainPluginUi();
      };
    }

    const _origRefresh = window.refresh;
    if (typeof _origRefresh === 'function') {
      window.refresh = async function(){
        await _origRefresh();
        constrainPluginUi();
      };
    }

    (async function initRel8Bridge(){
      try {
        const d = await _rawFetch('/descriptors').then(r => r.json());
        rel8Desc = d && d.settings ? d.settings : {};
      } catch(e) {}
      try {
        const cfg = await _rawFetch('/settings/default').then(r => r.json());
        if (cfg && cfg.config) {
          rel8Cfg = Object.assign({}, rel8Cfg, cfg.config);
        }
      } catch(e) {}
      removeUnsupportedDropdownMenus();
      renderRuntimeSettings();
      setTimeout(constrainPluginUi, 80);
    })();
  })();
</script>
"""

    return html.replace("</body>", inject + "\n</body>")


def _profiles_index() -> Path:
    return PROFILES_DIR / "profiles_index.json"


def _load_profiles() -> Dict[str, Any]:
    idx = _profiles_index()
    if not idx.exists():
        return {}
    try:
        return json.loads(idx.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_profiles(data: Dict[str, Any]) -> None:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    _profiles_index().write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("REL8_GUI_SECRET", uuid.uuid4().hex)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    app.logger.disabled = True
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    mgr = RelayManager(LaunchConfig())
    tests = TestRunner()

    @app.before_request
    def csrf_guard() -> Optional[Response]:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            hdr = request.headers.get("X-CSRF-Token", "")
            if hdr != _csrf_token():
                return jsonify({"ok": False, "error": "csrf_failed"}), 403
        return None

    @app.get("/health")
    def health() -> Response:
        return jsonify({"ok": True})

    @app.get("/csrf")
    def get_csrf() -> Response:
        return jsonify({"ok": True, "token": _csrf_token()})

    @app.get("/status")
    def status() -> Response:
        t0 = time.time()
        relay_metrics = mgr.server.metrics if mgr.server else {}
        uptime = (time.time() - mgr.last_start_ts) if mgr.running else 0.0
        relay_server = mgr.server
        state = relay_server.state if relay_server else None
        card_present = bool(state and getattr(state, "card_present", False))
        payload = {
            "ok": True,
            "running": mgr.running,
            "active_config": mgr.active_config,
            "host": mgr.active_config.get("host", LaunchConfig().host),
            "port": mgr.active_config.get("port", LaunchConfig().port),
            "relay": {
                "epoch": relay_server.active_epoch if relay_server else 0,
                "guard_phase": relay_server.guard.phase.name if relay_server else "IDLE",
                "reader_registered": bool(relay_server and relay_server.reader_addr),
                "emulator_registered": bool(relay_server and relay_server.emulator_addr),
                "reader_peer": list(relay_server.reader_addr) if relay_server and relay_server.reader_addr else None,
                "emulator_peer": list(relay_server.emulator_addr) if relay_server and relay_server.emulator_addr else None,
                "card_present": card_present,
                "reader_card_present": card_present,
                "verify_bypass_enabled": bool(state and getattr(state, "verify_bypass_enabled", False)),
                "arpc_forge_enabled": bool(state and getattr(state, "arpc_forge_enabled", False)),
                "arpc_rewrite_enabled": bool(state and getattr(state, "arpc_rewrite_enabled", False)),
                "tvr_mutation_enabled": bool(state and getattr(state, "tvr_mutation_enabled", False)),
                "metrics": relay_metrics,
            },
            "metrics": {
                **mgr.metrics,
                "uptime_seconds": uptime,
            },
            "tests": tests.status(),
        }
        dt = (time.time() - t0) * 1000.0
        mgr.metrics["requests_total"] += 1
        mgr.metrics["last_latency_ms"] = round(dt, 3)
        return jsonify(payload)

    @app.get("/descriptors")
    def descriptors() -> Response:
        return jsonify(runtime_descriptors())

    @app.get("/summary")
    def summary() -> Response:
        st = status().get_json()
        card_present = bool(st.get("relay", {}).get("card_present", False))
        return jsonify({
            "ok": True,
            "relay_running": st.get("running", False),
            "risk_level": LaunchConfig(**(st.get("active_config") or LaunchConfig().to_dict())).risk_level(),
            "guard_phase": st.get("relay", {}).get("guard_phase", "IDLE"),
            "active_config": st.get("active_config", {}),
            "card_present": card_present,
            "reader_card_present": card_present,
            "metrics": st.get("metrics", {}),
            "relay_metrics": st.get("relay", {}).get("metrics", {}),
        })

    @app.get("/summary/schema")
    def summary_schema() -> Response:
        return jsonify({
            "ok": True,
            "fields": [
                "relay_running", "risk_level", "guard_phase", "active_config", "metrics", "relay_metrics",
            ],
        })

    @app.get("/metrics")
    def metrics() -> Response:
        st = status().get_json()
        return jsonify({"ok": True, "metrics": st.get("metrics", {}), "relay": st.get("relay", {}).get("metrics", {})})

    @app.get("/diagnostics")
    def diagnostics() -> Response:
        st = status().get_json()
        relay = st.get("relay", {})
        issues: List[str] = []
        if st.get("running") and not relay.get("reader_registered"):
            issues.append("Reader endpoint is not registered")
        if st.get("running") and not relay.get("emulator_registered"):
            issues.append("Emulator endpoint is not registered")
        if not st.get("running"):
            issues.append("Relay is stopped")
        return jsonify({"ok": True, "issues": issues, "status": st})

    @app.get("/prometheus")
    def prometheus() -> Response:
        st = status().get_json()
        appm = st.get("metrics", {})
        relaym = st.get("relay", {}).get("metrics", {})
        lines = [
            "# HELP rel8_gui_starts_total Total GUI relay starts",
            "# TYPE rel8_gui_starts_total counter",
            f"rel8_gui_starts_total {appm.get('starts_total', 0)}",
            "# HELP rel8_gui_stops_total Total GUI relay stops",
            "# TYPE rel8_gui_stops_total counter",
            f"rel8_gui_stops_total {appm.get('stops_total', 0)}",
            "# HELP rel8_gui_uptime_seconds Relay uptime in seconds",
            "# TYPE rel8_gui_uptime_seconds gauge",
            f"rel8_gui_uptime_seconds {appm.get('uptime_seconds', 0.0)}",
            "# HELP rel8_gui_requests_total Total status requests",
            "# TYPE rel8_gui_requests_total counter",
            f"rel8_gui_requests_total {appm.get('requests_total', 0)}",
            "# HELP rel8_relay_events_total Relay event counter snapshot",
            "# TYPE rel8_relay_events_total gauge",
            f"rel8_relay_events_total {relaym.get('events_total', 0)}",
        ]
        return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")

    @app.get("/settings/default")
    def settings_default() -> Response:
        return jsonify({"ok": True, "config": LaunchConfig().to_dict()})

    @app.post("/settings/validate")
    def settings_validate() -> Response:
        body = _normalize_payload(request.get_json(silent=True) or {})
        cfg = build_config_from_payload(body)
        errors = validate_runtime_dependencies(cfg)
        return jsonify({"ok": not errors, "errors": errors, "effective": cfg.to_dict()})

    @app.post("/start")
    def post_start() -> Response:
        body = _normalize_payload(request.get_json(silent=True) or {})
        result = mgr.start(body)
        return jsonify(result), (200 if result.get("ok") else 400)

    @app.post("/stop")
    def post_stop() -> Response:
        result = mgr.stop()
        return jsonify(result), (200 if result.get("ok") else 400)

    @app.post("/restart")
    def post_restart() -> Response:
        body = _normalize_payload(request.get_json(silent=True) or {})
        mgr.stop()
        result = mgr.start(body)
        return jsonify(result), (200 if result.get("ok") else 400)

    @app.post("/session/reset")
    def post_session_reset() -> Response:
        if mgr.server:
            try:
                mgr.server._reset_session("gui_reset", unlock_epoch=True)
            except Exception:
                return jsonify({"ok": False, "error": "session_reset_failed"}), 500
        return jsonify({"ok": True})

    @app.post("/apdu/clear")
    def post_apdu_clear() -> Response:
        clear_apdu_history()
        return jsonify({"ok": True})

    @app.post("/logs/clear")
    def post_logs_clear() -> Response:
        clear_log_records()
        try:
            LAST_TEST_REPORT.unlink(missing_ok=True)
        except Exception:
            pass
        return jsonify({"ok": True})

    @app.get("/logs")
    def get_logs() -> Response:
        limit = max(1, min(int(request.args.get("limit", 100)), 2000))
        records = get_log_records(n=limit)
        if records:
            return jsonify(records)
        if not LAST_TEST_REPORT.exists():
            return jsonify([])
        content = LAST_TEST_REPORT.read_text(encoding="utf-8")
        lines = [ln for ln in content.splitlines() if ln.strip()]
        fallback = [
            {
                "ts": time.time(),
                "level": "INFO",
                "logger": "tests",
                "message": line,
            }
            for line in lines[-limit:]
        ]
        return jsonify(fallback)

    @app.get("/apdu/history")
    def apdu_history() -> Response:
        limit = int(request.args.get("limit", 100))
        return jsonify({"ok": True, "history": get_apdu_history(n=limit)})

    @app.get("/profiles")
    def profiles_list() -> Response:
        return jsonify({"ok": True, "profiles": _load_profiles()})

    @app.post("/profiles/save")
    def profiles_save() -> Response:
        body = request.get_json(silent=True) or {}
        name = str(body.get("name", "")).strip()
        if not name:
            return jsonify({"ok": False, "error": "profile_name_required"}), 400
        cfg = build_config_from_payload(body.get("config") or {})
        errors = validate_runtime_dependencies(cfg)
        if errors:
            return jsonify({"ok": False, "error": "validation_failed", "details": errors}), 400
        p = PROFILES_DIR / f"{name}.json"
        cfg.write_json(p)
        idx = _load_profiles()
        idx[name] = {"path": str(p), "updated_at": int(time.time())}
        _save_profiles(idx)
        return jsonify({"ok": True})

    @app.post("/profiles/load")
    def profiles_load() -> Response:
        body = request.get_json(silent=True) or {}
        name = str(body.get("name", "")).strip()
        idx = _load_profiles()
        if name not in idx:
            return jsonify({"ok": False, "error": "profile_not_found"}), 404
        cfg = LaunchConfig.from_json(idx[name]["path"])
        return jsonify({"ok": True, "config": cfg.to_dict()})

    @app.post("/profiles/delete")
    def profiles_delete() -> Response:
        body = request.get_json(silent=True) or {}
        name = str(body.get("name", "")).strip()
        idx = _load_profiles()
        item = idx.pop(name, None)
        if item:
            try:
                Path(item["path"]).unlink(missing_ok=True)
            except Exception:
                pass
            _save_profiles(idx)
        return jsonify({"ok": True})

    @app.get("/profiles/export")
    def profiles_export() -> Response:
        payload = {"profiles": _load_profiles()}
        if DEFAULT_CONFIG_PATH.exists():
            payload["last_config"] = json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
        return jsonify({"ok": True, "bundle": payload})

    @app.post("/profiles/import")
    def profiles_import() -> Response:
        body = request.get_json(silent=True) or {}
        bundle = body.get("bundle") or {}
        idx = _load_profiles()
        imported = 0
        for name, meta in (bundle.get("profiles") or {}).items():
            p = Path(meta.get("path", ""))
            if p.exists():
                idx[name] = {"path": str(p), "updated_at": int(time.time())}
                imported += 1
        _save_profiles(idx)
        if "last_config" in bundle:
            DEFAULT_CONFIG_PATH.write_text(json.dumps(bundle["last_config"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return jsonify({"ok": True, "imported": imported})

    @app.get("/tests/list")
    def tests_list() -> Response:
        return jsonify({"ok": True, "tests": _list_rel8_tests()})

    @app.post("/tests/run")
    def tests_run() -> Response:
        body = request.get_json(silent=True) or {}
        selected = body.get("selected") or _list_rel8_tests()
        selected = [s for s in selected if isinstance(s, str) and s.startswith("tests/test_")]
        result = tests.start(selected)
        return jsonify(result), (200 if result.get("ok") else 400)

    @app.post("/tests/stop")
    def tests_stop() -> Response:
        result = tests.stop()
        return jsonify(result), (200 if result.get("ok") else 400)

    @app.post("/tests/rerun")
    def tests_rerun() -> Response:
        return jsonify(tests.start(copy.deepcopy(tests.selected) or _list_rel8_tests()))

    @app.get("/tests/output")
    def tests_output() -> Response:
        cursor = int(request.args.get("cursor", 0))
        return jsonify(tests.output_since(cursor))

    @app.get("/tests/report")
    def tests_report() -> Response:
        if not LAST_TEST_REPORT.exists():
            return jsonify({"ok": False, "error": "report_not_found"}), 404
        return Response(LAST_TEST_REPORT.read_text(encoding="utf-8"), mimetype="text/plain")

    @app.get("/")
    def index() -> Response:
        html = _load_reference_gui_template()
        if not html:
            return Response("<html><body><h3>REL8HF GUI template load failed.</h3></body></html>", mimetype="text/html"), 500
        return Response(html, mimetype="text/html")

    return app


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="REL8HF Flask GUI launcher")
    parser.add_argument("--http-host", default="0.0.0.0")
    parser.add_argument("--http-port", default=8080, type=int)
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    app = create_app()
    app.run(host=args.http_host, port=args.http_port, debug=False, threaded=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
