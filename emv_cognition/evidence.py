from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional
import difflib


@dataclass
class Contradiction:
    claim: str
    conflicting_statement: str
    confidence: float
    source_a: str
    source_b: str


class EvidenceLedger:
    def __init__(self) -> None:
        self.items: List[Dict[str, object]] = []
        self.contradictions: List[Contradiction] = []

    def add(self, statement: str, kind: str = "observed",
            source: str = "runtime", confidence: float = 1.0,
            exchange_id: Optional[int] = None, details: Optional[dict] = None) -> Dict[str, object]:
        item = {
            "statement": statement,
            "kind": kind,
            "source": source,
            "confidence": float(confidence),
            "exchange_id": exchange_id,
            "details": details or {},
        }
        self.items.append(item)
        self.items = self.items[-500:]
        return item

    def check_contradiction(self, claim: str, facts: List[str]) -> List[Contradiction]:
        found: List[Contradiction] = []
        claim_lower = claim.lower()
        for fact in facts:
            f = fact.lower()
            # Simple semantic guardrails; intentionally conservative.
            neg_pairs = [
                ("never", "did"),
                ("not observed", "observed"),
                ("not present", "present"),
                ("failed", "succeeded"),
                ("succeeded", "failed"),
            ]
            conflict = any(a in claim_lower and b in f for a, b in neg_pairs)
            if not conflict:
                continue
            score = difflib.SequenceMatcher(None, claim_lower, f).ratio()
            found.append(
                Contradiction(
                    claim=claim,
                    conflicting_statement=fact,
                    confidence=min(1.0, 0.55 + score * 0.45),
                    source_a="agent",
                    source_b="evidence",
                )
            )
        self.contradictions.extend(found)
        self.contradictions = self.contradictions[-200:]
        return found

    def recent(self, limit: int = 30) -> List[Dict[str, object]]:
        return self.items[-limit:]

    def context(self, limit: int = 40) -> Dict[str, object]:
        return {
            "recent_evidence": self.recent(limit),
            "contradictions": [x.__dict__ for x in self.contradictions[-20:]],
        }
