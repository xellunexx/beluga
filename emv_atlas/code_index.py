# -*- coding: utf-8 -*-
"""Lightweight AST source index. Purpose (Phase 1): function → file → line range,
signature, docstring, file imports. No complete caller inference — static call
relations are labeled candidates only."""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .models import ModulePathInfo, SourceReference


class CodeIndex:
    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self.functions: Dict[str, SourceReference] = {}
        self.file_imports: Dict[str, List[str]] = {}
        self.file_functions: Dict[str, List[str]] = {}
        self._built = False

    # --- building -----------------------------------------------------------

    def build(self, rel_paths: List[str]) -> None:
        for rel in rel_paths:
            p = self.root / rel
            if p.exists():
                self._scan_file(p)
        self._built = True

    def _scan_file(self, path: Path) -> None:
        try:
            src = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src)
        except Exception:
            return
        mod_name = path.stem
        imports: List[str] = []
        funcs: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = f"{mod_name}.{node.name}"
                ref = SourceReference(
                    file=str(path),
                    qualname=qualname,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno) or node.lineno,
                    signature=self._signature(node),
                    docstring=ast.get_docstring(node) or "",
                )
                self.functions[qualname] = ref
                funcs.append(qualname)
            elif isinstance(node, ast.ClassDef):
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qualname = f"{mod_name}.{node.name}.{sub.name}"
                        ref = SourceReference(
                            file=str(path),
                            qualname=qualname,
                            line_start=sub.lineno,
                            line_end=getattr(sub, "end_lineno", sub.lineno) or sub.lineno,
                            signature=self._signature(sub),
                            docstring=ast.get_docstring(sub) or "",
                        )
                        self.functions[qualname] = ref
                        funcs.append(qualname)
        self.file_imports[str(path)] = sorted(set(imports))
        self.file_functions[str(path)] = funcs

    @staticmethod
    def _signature(node: Any) -> str:
        args = []
        for a in node.args.args:
            args.append(a.arg)
        if node.args.vararg:
            args.append("*" + node.args.vararg.arg)
        for a in node.args.kwonlyargs:
            args.append(a.arg)
        if node.args.kwarg:
            args.append("**" + node.args.kwarg.arg)
        return f"{node.name}({', '.join(args)})"

    # --- lookup -------------------------------------------------------------

    def find(self, qualname_variants: List[str]) -> Optional[SourceReference]:
        """Resolve a function by trying several qualname spellings."""
        for q in qualname_variants:
            if q in self.functions:
                return self.functions[q]
        # fallback: match by last component (bare function name)
        for q in qualname_variants:
            last = q.split(".")[-1]
            for k, ref in self.functions.items():
                if k.endswith("." + last) or k == last:
                    return ref
        return None

    def read_lines(self, ref: SourceReference, pad: int = 2) -> List[str]:
        """Read source lines around the function range."""
        try:
            lines = Path(ref.file).read_text(encoding="utf-8", errors="replace").splitlines()
            lo = max(1, ref.line_start - pad)
            hi = min(len(lines), (ref.line_end or ref.line_start) + 0)
            return lines[lo - 1:hi]
        except Exception:
            return []

    # --- stale-module diagnosis ---------------------------------------------

    def module_paths(self, names: List[str]) -> List[ModulePathInfo]:
        """Report where each module ACTUALLY resolved from vs expected project path."""
        out: List[ModulePathInfo] = []
        for name in names:
            mod = sys.modules.get(name)
            imported = getattr(mod, "__file__", None) if mod is not None else None
            expected = str(self.root / f"{name}.py")
            if imported:
                imp_abs = str(Path(imported).resolve())
                stale = Path(imp_abs) != Path(expected)
                out.append(ModulePathInfo(name=name, imported_path=imp_abs,
                                          expected_path=expected, stale=stale))
            else:
                out.append(ModulePathInfo(name=name, imported_path="(not imported)",
                                          expected_path=expected, stale=False))
        return out
