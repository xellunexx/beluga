# -*- coding: utf-8 -*-
"""
Fallback TPHub implementation for when the original is not available.
"""
from typing import Dict, Any, Optional

class TPHub:
    """Terminal Probe Hub - manages terminal capability hints."""
    
    def __init__(self):
        self.enabled = False
        self.last_hint: Optional[Dict[str, Any]] = None
    
    @staticmethod
    def from_env() -> 'TPHub':
        """Create TPHub instance from environment configuration."""
        return TPHub()
    
    def feed(self, terminal_caps: Dict[str, Any]) -> None:
        """Feed terminal capabilities to the hub."""
        pass
    
    def hint(self, **kwargs) -> Dict[str, Any]:
        """Get recommendation hint based on current state."""
        return {"mode": "AUTO", "reason": "fallback"}
