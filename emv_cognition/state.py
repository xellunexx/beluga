from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class Transition:
    before: str
    after: str
    allowed: bool
    reason: str


class EMVStateMachine:
    """Read-only semantic model aligned with the project's Guard phases."""

    PHASES = (
        "IDLE",
        "PPSE_SELECTED",
        "AID_SELECTED",
        "GPO_RESPONDED",
        "READ_RECORD_DONE",
        "FIRST_GAC_SENT",
        "ARQC_RECEIVED",
        "SECOND_GAC_FORGED",
        "EXTERNAL_AUTH_DONE",
        "COMPLETE",
        "ERROR",
    )

    TRANSITIONS: Dict[str, Set[str]] = {
        "IDLE": {"PPSE_SELECTED", "ERROR"},
        "PPSE_SELECTED": {"AID_SELECTED", "PPSE_SELECTED", "ERROR"},
        "AID_SELECTED": {"GPO_RESPONDED", "ERROR"},
        "GPO_RESPONDED": {"READ_RECORD_DONE", "ERROR"},
        "READ_RECORD_DONE": {"FIRST_GAC_SENT", "ERROR"},
        "FIRST_GAC_SENT": {"ARQC_RECEIVED", "COMPLETE", "ERROR"},
        "ARQC_RECEIVED": {"SECOND_GAC_FORGED", "EXTERNAL_AUTH_DONE", "COMPLETE", "ERROR"},
        "SECOND_GAC_FORGED": {"EXTERNAL_AUTH_DONE", "COMPLETE", "ERROR"},
        "EXTERNAL_AUTH_DONE": {"SECOND_GAC_FORGED", "COMPLETE", "ERROR"},
        "COMPLETE": {"ERROR"},
        "ERROR": set(),
    }

    STICKY = {"PPSE_SELECTED", "READ_RECORD_DONE"}

    def __init__(self) -> None:
        self.phase = "IDLE"
        self.last_sw: Optional[str] = None
        self.transitions: List[Transition] = []

    def observe_sw(self, sw: Optional[str]) -> None:
        self.last_sw = sw.upper() if sw else None

    def can_transition(self, target: str) -> Tuple[bool, str]:
        target = target.upper()
        if target not in self.PHASES:
            return False, f"Unknown phase {target}"
        if target == self.phase and target in self.STICKY:
            return True, f"{target} is sticky/idempotent"
        allowed = self.TRANSITIONS.get(self.phase, set())
        if target not in allowed:
            return False, (
                f"Transition {self.phase} -> {target} is not allowed; "
                f"allowed={sorted(allowed)}"
            )
        if target != "ERROR" and self.last_sw not in (None, "9000"):
            return False, f"Last observed SW is {self.last_sw}, not 9000"
        return True, "transition allowed"

    def advance(self, target: str) -> Transition:
        allowed, reason = self.can_transition(target)
        event = Transition(self.phase, target.upper(), allowed, reason)
        self.transitions.append(event)
        if allowed:
            self.phase = target.upper()
        return event

    def snapshot(self) -> Dict[str, object]:
        return {
            "phase": self.phase,
            "last_sw": self.last_sw,
            "transitions": [t.__dict__ for t in self.transitions[-20:]],
        }
