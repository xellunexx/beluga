from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from .decoder import decode_apdu
from .evidence import EvidenceLedger
from .knowledge import EMVKnowledgeGraph
from .replay import TransactionReplay


class EMVCognitionEngine:
    """Facade used by the LLM layer.

    This is deliberately read-only with respect to EMV runtime state. It parses,
    correlates, compares, and verifies observations; it does not mutate APDUs,
    forge responses, or bypass transaction controls.
    """

    def __init__(self, state_path: Optional[Path] = None) -> None:
        self.evidence = EvidenceLedger()
        self.knowledge = EMVKnowledgeGraph()
        self.replay = TransactionReplay()
        self.state_path = state_path
        self._exchange_counter = 0

    def ingest_exchange(
        self,
        direction: str,
        apdu_hex: str,
        response_hex: str = "",
        phase_after: Optional[str] = None,
        source: str = "runtime",
    ) -> Dict[str, Any]:
        self._exchange_counter += 1
        event = self.replay.add_exchange(
            self._exchange_counter,
            direction,
            apdu_hex,
            response_hex,
            phase_after=phase_after,
        )
        self.knowledge.add_exchange(
            event.exchange_id,
            direction,
            event.command_name or "UNKNOWN",
            event.phase_before or "UNKNOWN",
            event.phase_after or "UNKNOWN",
            event.tags,
        )
        self.evidence.add(
            f"Exchange {event.exchange_id}: {event.command_name or 'UNKNOWN'} observed",
            kind="observed",
            source=source,
            confidence=1.0,
            exchange_id=event.exchange_id,
        )
        for tag, value in event.tags.items():
            self.evidence.add(
                f"Tag {tag} observed with value {value}",
                kind="observed",
                source=source,
                confidence=1.0,
                exchange_id=event.exchange_id,
            )
        return event.as_dict()

    def verify_claim(self, claim: str) -> Dict[str, Any]:
        facts = [str(x["statement"]) for x in self.evidence.recent(100)]
        contradictions = self.evidence.check_contradiction(claim, facts)
        return {
            "claim": claim,
            "supported_by_recent_evidence": any(claim.lower() in x.lower() for x in facts),
            "contradictions": [x.__dict__ for x in contradictions],
            "verdict": "CONTRADICTED" if contradictions else "UNPROVEN",
        }

    def compare_replay(self, other: "EMVCognitionEngine") -> Dict[str, Any]:
        return self.replay.compare(other.replay)

    def context(self, max_chars: int = 12000) -> str:
        payload = {
            "purpose": "read-only EMV interpretation and verification",
            "transaction": self.replay.snapshot(),
            "evidence": self.evidence.context(),
            "knowledge_graph": self.knowledge.snapshot(),
        }
        return json.dumps(payload, ensure_ascii=False, default=str)[:max_chars]

    def save(self) -> None:
        if not self.state_path:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(self.context(200000), encoding="utf-8")
