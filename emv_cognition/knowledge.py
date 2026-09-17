from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Tuple


class EMVKnowledgeGraph:
    """Small local graph for protocol-role and data-flow relationships."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, object]] = {}
        self.edges: List[Tuple[str, str, str]] = []

    def add_node(self, node_id: str, kind: str, **attrs) -> None:
        self.nodes[node_id] = {"kind": kind, **attrs}

    def add_edge(self, source: str, relation: str, target: str) -> None:
        if (source, relation, target) not in self.edges:
            self.edges.append((source, relation, target))
        self.edges = self.edges[-1000:]

    def neighbors(self, node_id: str) -> List[Dict[str, str]]:
        result = []
        for source, relation, target in self.edges:
            if source == node_id:
                result.append({"relation": relation, "target": target})
            elif target == node_id:
                result.append({"relation": relation, "source": source})
        return result

    def add_exchange(self, exchange_id: int, direction: str, command: str,
                     phase_before: str, phase_after: str, tags: Dict[str, str]) -> None:
        ex = f"exchange:{exchange_id}"
        self.add_node(ex, "exchange", direction=direction, command=command)
        self.add_node(f"phase:{phase_before}", "phase")
        self.add_node(f"phase:{phase_after}", "phase")
        self.add_edge(ex, "phase_before", f"phase:{phase_before}")
        self.add_edge(ex, "phase_after", f"phase:{phase_after}")
        for tag in tags:
            tag_id = f"tag:{tag.upper()}"
            self.add_node(tag_id, "tag")
            self.add_edge(ex, "contains", tag_id)

    def snapshot(self) -> Dict[str, object]:
        return {
            "nodes": self.nodes,
            "edges": [
                {"source": s, "relation": r, "target": t}
                for s, r, t in self.edges[-500:]
            ],
        }
