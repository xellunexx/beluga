from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Observation:
    kind: str
    value: Any
    source: str = "runtime"
    confidence: float = 1.0
    timestamp: Optional[float] = None
    exchange_id: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "exchange_id": self.exchange_id,
        }


@dataclass
class EvidenceItem:
    statement: str
    evidence_type: str = "observed"
    source: str = "runtime"
    confidence: float = 1.0
    exchange_id: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "statement": self.statement,
            "evidence_type": self.evidence_type,
            "source": self.source,
            "confidence": self.confidence,
            "exchange_id": self.exchange_id,
            "details": self.details,
        }


@dataclass
class Hypothesis:
    claim: str
    supporting: List[EvidenceItem] = field(default_factory=list)
    contradicting: List[EvidenceItem] = field(default_factory=list)
    confidence: float = 0.0
    next_observation: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "claim": self.claim,
            "supporting": [x.as_dict() for x in self.supporting],
            "contradicting": [x.as_dict() for x in self.contradicting],
            "confidence": self.confidence,
            "next_observation": self.next_observation,
        }


@dataclass
class TransactionEvent:
    exchange_id: int
    direction: str
    apdu_hex: str = ""
    response_hex: str = ""
    status_word: Optional[str] = None
    phase_before: Optional[str] = None
    phase_after: Optional[str] = None
    command_name: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    observations: List[Observation] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "exchange_id": self.exchange_id,
            "direction": self.direction,
            "apdu_hex": self.apdu_hex,
            "response_hex": self.response_hex,
            "status_word": self.status_word,
            "phase_before": self.phase_before,
            "phase_after": self.phase_after,
            "command_name": self.command_name,
            "tags": self.tags,
            "observations": [x.as_dict() for x in self.observations],
            "notes": self.notes,
        }
