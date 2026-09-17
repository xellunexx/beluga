# -*- coding: utf-8 -*-
"""EMV Execution Atlas — Phase 1 (evidence-first, observational only)."""
from .models import (
    AssertionInfo, AtlasTrace, EvidenceEvent, FlowEdge, FlowNode,
    ModulePathInfo, NodeKind, SourceReference, Transformation, TruthBadge,
)
from .evidence import AtlasBuilder, is_emv_relevant
from .code_index import CodeIndex

__all__ = [
    "AssertionInfo", "AtlasTrace", "EvidenceEvent", "FlowEdge", "FlowNode",
    "ModulePathInfo", "NodeKind", "SourceReference", "Transformation",
    "TruthBadge", "AtlasBuilder", "CodeIndex", "is_emv_relevant",
]
