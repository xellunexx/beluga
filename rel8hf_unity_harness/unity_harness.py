#!/usr/bin/env python3
"""
REL8HF Unity Harness
--------------------

A non-destructive CLI for finding architectural "lack of unity" across a Python
application:

* parses every Python source file
* builds import graph and approximate call graph
* finds duplicate definitions
* finds unresolved local symbol / method references where statically obvious
* checks method/call signature mismatches where statically obvious
* checks Qt signal .connect(target) references
* checks AITool registration -> handler consistency
* checks broad API contract drift (same-name functions/classes with incompatible
  signatures)
* checks dead/orphan functions by reachability heuristics
* optionally instantiates the real qt_app.Rel8AppletWindow in offscreen mode
* optionally records actual runtime call edges with sys.settrace
* emits JSON + human-readable evidence

It deliberately does NOT click arbitrary GUI controls or invoke mutating
functions automatically. The static pass can cover the entire tree; dynamic
passes require explicit entrypoints.

Usage from project root:

    python unity_harness.py audit
    python unity_harness.py audit --json report.json
    python unity_harness.py gui
    python unity_harness.py trace --module qt_app --call "Rel8AppletWindow"
"""

from __future__ import annotations

import argparse
import ast
import builtins
import contextlib
import dataclasses
import importlib
import inspect
import io
import json
import os
import re
import runpy
import sys
import traceback
from collections import defaultdict, Counter
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


PROJECT_ROOT = Path.cwd().resolve()
EXCLUDE_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "build", "dist",
    "node_modules", ".mypy_cache", ".pytest_cache", "artifacts",
}
STD_PREFIXES = {
    "sys", "os", "re", "io", "json", "time", "math", "typing", "pathlib",
    "dataclasses", "collections", "contextlib", "inspect", "traceback",
    "threading", "subprocess", "socket", "hashlib", "urllib", "functools",
    "itertools", "enum", "abc", "logging", "datetime", "random", "ast",
    "argparse", "statistics", "textwrap", "shutil", "tempfile", "signal",
    "queue", "weakref", "contextvars", "copy", "sqlite3", "base64", "struct",
}


@dataclasses.dataclass
class Finding:
    severity: str
    kind: str
    file: str
    line: int
    message: str
    evidence: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class FunctionInfo:
    qualname: str
    module: str
    file: str
    line: int
    end_line: int
    is_method: bool
    owner: Optional[str]
    args: List[str]
    returns: Optional[str]
    calls: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ModuleInfo:
    module: str
    file: str
    imports: Set[str] = dataclasses.field(default_factory=set)
    functions: Dict[str, FunctionInfo] = dataclasses.field(default_factory=dict)
    classes: Dict[str, int] = dataclasses.field(default_factory=dict)
    assigned_names: Set[str] = dataclasses.field(default_factory=set)
    tool_registrations: List[Tuple[int, str, str]] = dataclasses.field(default_factory=list)
    qt_connects: List[Tuple[int, str, str]] = dataclasses.field(default_factory=list)
    syntax_ok: bool = True


def relpath(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def discover_python_files() -> List[Path]:
    out = []
    for p in PROJECT_ROOT.rglob("*.py"):
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        out.append(p)
    return sorted(out)


def module_name_for(path: Path) -> str:
    rel = path.relative_to(PROJECT_ROOT)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = Path(parts[-1]).stem
    return ".".join(parts) if parts else PROJECT_ROOT.name


def parse_file(path: Path) -> Tuple[Optional[ast.AST], Optional[str]]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        return ast.parse(source, filename=str(path)), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def annotation_text(node: Optional[ast.AST]) -> Optional[str]:
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:
        return None


class Analyzer(ast.NodeVisitor):
    def __init__(self, module: str, path: Path):
        self.info = ModuleInfo(module=module, file=relpath(path))
        self.function_stack: List[FunctionInfo] = []
        self.class_stack: List[str] = []

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            self.info.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        base = "." * node.level + (node.module or "")
        self.info.imports.add(base)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.info.classes[node.name] = node.lineno
        self.info.assigned_names.add(node.name)
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._function(node)

    def _function(self, node: ast.AST) -> None:
        name = node.name  # type: ignore[attr-defined]
        owner = self.class_stack[-1] if self.class_stack else None
        qualname = f"{self.info.module}:{owner}.{name}" if owner else f"{self.info.module}:{name}"
        args_node = node.args  # type: ignore[attr-defined]
        args = []
        for a in list(args_node.posonlyargs) + list(args_node.args) + list(args_node.kwonlyargs):
            args.append(a.arg)
        if args_node.vararg:
            args.append("*" + args_node.vararg.arg)
        if args_node.kwarg:
            args.append("**" + args_node.kwarg.arg)

        fn = FunctionInfo(
            qualname=qualname,
            module=self.info.module,
            file=self.info.file,
            line=node.lineno,  # type: ignore[attr-defined]
            end_line=getattr(node, "end_lineno", node.lineno),
            is_method=owner is not None,
            owner=owner,
            args=args,
            returns=annotation_text(getattr(node, "returns", None)),
        )
        self.info.functions[qualname] = fn

        self.function_stack.append(fn)
        for stmt in node.body:  # type: ignore[attr-defined]
            self.visit(stmt)
        self.function_stack.pop()

    def visit_Name(self, node: ast.Name) -> Any:
        if isinstance(node.ctx, ast.Store):
            self.info.assigned_names.add(node.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if self.function_stack:
            callee = self._callee_name(node.func)
            if callee:
                self.function_stack[-1].calls.append(callee)

        # Qt signal connections: foo.clicked.connect(self.bar)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "connect":
            if node.args:
                target = self._callee_name(node.args[0])
                if target:
                    self.info.qt_connects.append((node.lineno, self.function_stack[-1].qualname if self.function_stack else "<module>", target))

        # AITool registrations: self.register(AITool(name="x", ..., handler=self._tool_x))
        if isinstance(node.func, ast.Attribute) and node.func.attr == "register":
            for arg in node.args:
                if isinstance(arg, ast.Call) and self._callee_name(arg.func).endswith("AITool"):
                    tool_name = None
                    handler = None
                    for kw in arg.keywords:
                        if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                            tool_name = str(kw.value.value)
                        if kw.arg == "handler":
                            handler = self._callee_name(kw.value)
                    if tool_name:
                        self.info.tool_registrations.append(
                            (node.lineno, tool_name, handler or "")
                        )

        self.generic_visit(node)

    def _callee_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            left = self._callee_name(node.value)
            return f"{left}.{node.attr}" if left else node.attr
        if isinstance(node, ast.Call):
            return self._callee_name(node.func)
        return ""


def analyze_source(files: List[Path]) -> Tuple[Dict[str, ModuleInfo], List[Finding]]:
    modules: Dict[str, ModuleInfo] = {}
    findings: List[Finding] = []

    for path in files:
        module = module_name_for(path)
        tree, err = parse_file(path)
        info = ModuleInfo(module=module, file=relpath(path))
        if err:
            info.syntax_ok = False
            modules[module] = info
            findings.append(Finding(
                "ERROR", "syntax", relpath(path), 1,
                f"Python parse failed: {err}"
            ))
            continue

        analyzer = Analyzer(module, path)
        analyzer.visit(tree)
        modules[module] = analyzer.info

    # Duplicate definitions within the same module.
    for mod in modules.values():
        by_short: Dict[str, List[FunctionInfo]] = defaultdict(list)
        for fn in mod.functions.values():
            by_short[fn.qualname.rsplit(":", 1)[-1].split(".")[-1]].append(fn)

        for short, funcs in by_short.items():
            if len(funcs) > 1:
                findings.append(Finding(
                    "ERROR", "duplicate_definition", mod.file,
                    funcs[-1].line,
                    f"Multiple definitions of '{short}' in module {mod.module}.",
                    {"locations": [f.line for f in funcs]},
                ))

        # Qt connect target existence: only flag obvious local self.method targets.
        method_names = {
            fn.qualname.rsplit(".", 1)[-1]
            for fn in mod.functions.values()
            if fn.owner == mod.module.split(".")[-1] or fn.owner is not None
        }
        for line, owner, target in mod.qt_connects:
            if target.startswith("self.") or target.startswith("window."):
                method = target.split(".")[-1]
                if method and method not in method_names:
                    findings.append(Finding(
                        "ERROR", "qt_missing_slot", mod.file, line,
                        f"Qt signal connects to apparently missing method '{method}'.",
                        {"owner": owner, "target": target},
                    ))

        # Tool handler existence inside same module.
        local_names = set()
        for fn in mod.functions.values():
            local_names.add(fn.qualname.split(":", 1)[1].split(".")[-1])

        for line, tool_name, handler in mod.tool_registrations:
            if handler.startswith("self."):
                h = handler.split(".")[-1]
                if h not in local_names:
                    findings.append(Finding(
                        "ERROR", "tool_missing_handler", mod.file, line,
                        f"Registered tool '{tool_name}' references missing handler '{handler}'.",
                        {"tool": tool_name, "handler": handler},
                    ))

    # Import graph consistency: local import prefixes that map nowhere.
    module_set = set(modules)
    for mod in modules.values():
        for imp in mod.imports:
            plain = imp.lstrip(".")
            if not plain or plain.split(".")[0] in STD_PREFIXES:
                continue
            root = plain.split(".")[0]
            candidates = {m.split(".")[0] for m in module_set}
            if root not in candidates and root not in {"PyQt6", "PySide6"}:
                findings.append(Finding(
                    "WARNING", "unresolved_import", mod.file, 1,
                    f"Import root '{root}' is not a discovered project module or stdlib module.",
                    {"import": imp},
                ))

    return modules, findings


def build_call_graph(modules: Dict[str, ModuleInfo]) -> Dict[str, Set[str]]:
    """Approximate local call graph based on function names."""
    definitions: Dict[str, List[str]] = defaultdict(list)
    for mod in modules.values():
        for fn in mod.functions.values():
            short = fn.qualname.split(":", 1)[1].split(".")[-1]
            definitions[short].append(fn.qualname)

    graph: Dict[str, Set[str]] = defaultdict(set)
    for mod in modules.values():
        for fn in mod.functions.values():
            for call in fn.calls:
                short = call.split(".")[-1]
                targets = definitions.get(short, [])
                for target in targets:
                    graph[fn.qualname].add(target)
    return graph


def reachability_report(modules: Dict[str, ModuleInfo], graph: Dict[str, Set[str]]) -> List[Finding]:
    roots: Set[str] = set()

    # Public / likely entrypoints.
    for mod in modules.values():
        for fn in mod.functions.values():
            short = fn.qualname.split(":", 1)[1].split(".")[-1]
            if short in {
                "main", "launch_applet", "execute_tool", "send_message",
                "on_send_clicked", "run", "start", "stop", "closeEvent",
            }:
                roots.add(fn.qualname)

        for cls in mod.classes:
            roots.update(
                fn.qualname for fn in mod.functions.values()
                if fn.owner == cls and fn.qualname.endswith(f".{cls}")
            )

    reachable: Set[str] = set(roots)
    changed = True
    while changed:
        changed = False
        for src, dsts in graph.items():
            if src in reachable:
                for dst in dsts:
                    if dst not in reachable:
                        reachable.add(dst)
                        changed = True

    findings: List[Finding] = []
    for mod in modules.values():
        for fn in mod.functions.values():
            short = fn.qualname.split(":", 1)[1].split(".")[-1]
            if short.startswith("_") and short not in {"__init__", "__enter__", "__exit__"}:
                continue
            if fn.qualname not in reachable:
                findings.append(Finding(
                    "INFO", "possibly_orphan_function", fn.file, fn.line,
                    f"Function '{fn.qualname}' is not reachable from heuristic entrypoints.",
                ))
    return findings


def api_unity_report(modules: Dict[str, ModuleInfo]) -> List[Finding]:
    findings: List[Finding] = []
    by_short: Dict[str, List[FunctionInfo]] = defaultdict(list)

    for mod in modules.values():
        for fn in mod.functions.values():
            short = fn.qualname.split(":", 1)[1].split(".")[-1]
            by_short[short].append(fn)

    # Same public function name across modules with wildly different signatures.
    for short, funcs in by_short.items():
        if len(funcs) < 2 or short.startswith("_"):
            continue
        shapes = {tuple(f.args) for f in funcs}
        if len(shapes) > 1:
            findings.append(Finding(
                "WARNING", "api_signature_drift", funcs[0].file, funcs[0].line,
                f"Public function name '{short}' has divergent signatures across modules.",
                {"signatures": {
                    f"{f.module}:{f.owner or ''}{short}": f.args for f in funcs
                }},
            ))

    return findings


def run_compile_check(files: List[Path]) -> List[Finding]:
    findings: List[Finding] = []
    for p in files:
        try:
            source = p.read_text(encoding="utf-8", errors="replace")
            compile(source, str(p), "exec")
        except Exception as exc:
            findings.append(Finding(
                "ERROR", "compile", relpath(p), 1,
                f"Compile failed: {type(exc).__name__}: {exc}"
            ))
    return findings


def headless_gui_probe() -> Dict[str, Any]:
    # Match the real app's binding, but do not independently import PySide6/PyQt6.
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    os.environ.setdefault("QT_OPENGL", "software")
    os.environ.setdefault("QT_QUICK_BACKEND", "software")

    import qt_app

    QtWidgets = qt_app.QtWidgets
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
    window = qt_app.Rel8AppletWindow()

    tabs = getattr(window, "tabs", None)
    info: Dict[str, Any] = {
        "qt_binding": getattr(qt_app, "QT_BINDING", "unknown"),
        "window_class": type(window).__name__,
        "window_size": [window.width(), window.height()],
        "tabs_present": tabs is not None,
        "tabs_count": tabs.count() if tabs is not None else None,
        "tabs": (
            [tabs.tabText(i) for i in range(tabs.count())]
            if tabs is not None else []
        ),
        "button_count": 0,
        "widget_count": 0,
        "visible_widget_count": 0,
    }

    # Same Qt classes as qt_app.
    QWidget = QtWidgets.QWidget
    QAbstractButton = QtWidgets.QAbstractButton
    widgets = []

    seen = set()

    def walk(obj):
        ident = id(obj)
        if ident in seen:
            return
        seen.add(ident)
        if isinstance(obj, QWidget):
            widgets.append(obj)
        for child in obj.children():
            walk(child)

    walk(window)
    info["widget_count"] = len(widgets)
    info["visible_widget_count"] = sum(1 for w in widgets if w.isVisible())
    info["button_count"] = sum(1 for w in widgets if isinstance(w, QAbstractButton))

    # Do NOT show or process long enough to fire application timers.
    window.close()
    app.processEvents()
    return info


class RuntimeTracer:
    def __init__(self, project_root: Path):
        self.project_root = str(project_root)
        self.edges: Counter[Tuple[str, str]] = Counter()
        self.calls: List[Tuple[str, str]] = []
        self.stack: List[str] = []

    def _key(self, frame) -> Optional[str]:
        filename = os.path.abspath(frame.f_code.co_filename)
        if not filename.startswith(self.project_root):
            return None
        return f"{Path(filename).name}:{frame.f_code.co_name}:{frame.f_lineno}"

    def trace(self, frame, event, arg):
        if event == "call":
            cur = self._key(frame)
            caller = self.stack[-1] if self.stack else "<root>"
            if cur:
                self.edges[(caller, cur)] += 1
                self.calls.append((caller, cur))
                self.stack.append(cur)
        elif event == "return":
            if self.stack:
                self.stack.pop()
        return self.trace


def runtime_trace_module(module_name: str, function_name: Optional[str] = None) -> Dict[str, Any]:
    tracer = RuntimeTracer(PROJECT_ROOT)

    module = importlib.import_module(module_name)
    target = None
    if function_name:
        target = getattr(module, function_name)

    old = sys.gettrace()
    sys.settrace(tracer.trace)
    try:
        if target is None:
            # Import-time execution already happened; run a non-destructive inspection.
            inspect.getmembers(module)
        else:
            if inspect.isclass(target):
                # Constructor only; no GUI show.
                target()
            else:
                target()
    except Exception as exc:
        return {
            "status": "ERROR",
            "error": f"{type(exc).__name__}: {exc}",
            "trace_edges": [
                {"caller": a, "callee": b, "count": n}
                for (a, b), n in tracer.edges.items()
            ],
        }
    finally:
        sys.settrace(old)

    return {
        "status": "PASS",
        "trace_edges": [
            {"caller": a, "callee": b, "count": n}
            for (a, b), n in tracer.edges.most_common()
        ],
        "unique_edges": len(tracer.edges),
    }


def command_audit(args: argparse.Namespace) -> int:
    files = discover_python_files()
    modules, findings = analyze_source(files)
    findings.extend(run_compile_check(files))

    graph = build_call_graph(modules)
    findings.extend(reachability_report(modules, graph))
    findings.extend(api_unity_report(modules))

    report = {
        "project_root": str(PROJECT_ROOT),
        "python_files": len(files),
        "modules": len(modules),
        "functions": sum(len(m.functions) for m in modules.values()),
        "classes": sum(len(m.classes) for m in modules.values()),
        "imports": sum(len(m.imports) for m in modules.values()),
        "call_graph_nodes": len(graph),
        "findings": [dataclasses.asdict(f) for f in findings],
        "summary": dict(Counter(f.severity for f in findings)),
    }

    print(json.dumps(report, indent=2, ensure_ascii=False))
    if args.json:
        Path(args.json).write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    return 2 if any(f.severity == "ERROR" for f in findings) else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="REL8HF whole-stack function-path and architectural-unity harness"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="Static whole-project unity audit")
    p_audit.add_argument("--json", help="Write report JSON to file")

    sub.add_parser("gui", help="Instantiate the real qt_app GUI offscreen and inspect structure")

    p_trace = sub.add_parser("trace", help="Trace a known module/function dynamically")
    p_trace.add_argument("--module", required=True)
    p_trace.add_argument("--call", default="")

    args = parser.parse_args(argv)

    if args.command == "audit":
        return command_audit(args)

    if args.command == "gui":
        result = headless_gui_probe()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("tabs_present") and result.get("widget_count", 0) > 0 else 2

    if args.command == "trace":
        result = runtime_trace_module(args.module, args.call or None)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("status") == "PASS" else 2

    return 3


if __name__ == "__main__":
    raise SystemExit(main())
