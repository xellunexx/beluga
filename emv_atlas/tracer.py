# -*- coding: utf-8 -*-
"""Phase-3 extension point. INACTIVE in Phase 1 by design.

Phase 1 reconstructs the visual execution model from existing evidence only.
When the optional runtime tracing phase is built, ScopedRuntimeTrace must:
  - install sys.setprofile() only inside __enter__ / remove it in __exit__
  - filter hard: only frames whose file is under the project root and whose
    module is in EMV_TRACE_MODULES; never .venv, never Qt internals
  - enforce an event budget with a truncation marker
  - record thread ident per event
  - restore sys.setprofile exactly (previous value) in a finally block
"""
from __future__ import annotations

from typing import List, Optional

EMV_TRACE_MODULES = [
    "constants", "protocol", "tlv", "emv", "parser", "bypasses",
    "mod_emv_synthesizer", "mutations", "mutation_scenarios",
    "guard", "issuer_profiles", "issuer_simulator", "logger",
    "tp_hub", "rel8hf", "rel8hf_launcher",
]


class ScopedRuntimeTrace:
    """Interface stub for the optional runtime tracing phase.

    Usage contract for Phase 3 (NOT active now):

        with ScopedRuntimeTrace(modules=EMV_TRACE_MODULES, budget=4000) as tr:
            run_something()
        tr.events -> filtered EvidenceEvents

    Phase 1 NEVER instantiates this against real execution.
    """

    def __init__(self, modules: Optional[List[str]] = None, budget: int = 4000) -> None:
        self.modules = modules or list(EMV_TRACE_MODULES)
        self.budget = budget
        self.events: List = []
        self.truncated = False
        self._active = False

    def __enter__(self) -> "ScopedRuntimeTrace":
        raise RuntimeError(
            "ScopedRuntimeTrace is a Phase-3 extension point; runtime profiling "
            "is disabled in Phase 1. Use existing-evidence tracing instead.")

    def __exit__(self, *_exc) -> None:
        # Contract for Phase 3: always restore sys.setprofile exactly here.
        return None
