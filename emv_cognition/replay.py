from __future__ import annotations

from typing import Dict, List, Optional

from .decoder import decode_apdu, summarize_tlv
from .model import TransactionEvent
from .state import EMVStateMachine


class TransactionReplay:
    """Reconstructs a read-only semantic timeline from supplied exchanges."""

    def __init__(self) -> None:
        self.events: List[TransactionEvent] = []
        self.state = EMVStateMachine()

    def add_exchange(
        self,
        exchange_id: int,
        direction: str,
        apdu_hex: str,
        response_hex: str = "",
        phase_after: Optional[str] = None,
    ) -> TransactionEvent:
        before = self.state.phase
        apdu = decode_apdu(apdu_hex)
        status_word = response_hex[-4:].upper() if response_hex and len(response_hex) >= 4 else None
        if status_word:
            self.state.observe_sw(status_word)

        tags: Dict[str, str] = {}
        if response_hex:
            body = response_hex[:-4] if status_word else response_hex
            try:
                tags = summarize_tlv(body).get("tags", {})
            except Exception:
                tags = {}

        after = before
        notes: List[str] = []

        if phase_after:
            transition = self.state.advance(phase_after)
            after = self.state.phase
            if not transition.allowed:
                notes.append(transition.reason)

        event = TransactionEvent(
            exchange_id=exchange_id,
            direction=direction,
            apdu_hex=apdu.get("raw", ""),
            response_hex=response_hex.upper(),
            status_word=status_word,
            phase_before=before,
            phase_after=after,
            command_name=apdu.get("instruction"),
            tags=tags,
            notes=notes,
        )
        self.events.append(event)
        return event

    def compare(self, other: "TransactionReplay") -> Dict[str, object]:
        left = self.events
        right = other.events
        max_len = max(len(left), len(right))
        divergences = []
        for i in range(max_len):
            a = left[i].as_dict() if i < len(left) else None
            b = right[i].as_dict() if i < len(right) else None
            if a != b:
                divergences.append({"index": i, "left": a, "right": b})
        return {
            "left_exchanges": len(left),
            "right_exchanges": len(right),
            "divergences": divergences,
        }

    def snapshot(self) -> Dict[str, object]:
        return {
            "state": self.state.snapshot(),
            "events": [x.as_dict() for x in self.events[-100:]],
        }
