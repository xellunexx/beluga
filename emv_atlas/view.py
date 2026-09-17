# -*- coding: utf-8 -*-
"""EMV Execution Atlas — Qt view. Layered flow graph + inspector + source pane
+ chronological event strip. Observational only."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from PyQt6.QtWidgets import (
        QComboBox, QDialog, QFileDialog, QGraphicsLineItem, QGraphicsRectItem,
        QGraphicsScene, QGraphicsSimpleTextItem, QGraphicsView, QHBoxLayout,
        QLabel, QListWidget, QListWidgetItem, QMessageBox, QPlainTextEdit,
        QPushButton, QSpinBox, QSplitter, QTextBrowser, QVBoxLayout, QWidget,
    )
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPen
    QT_BINDING = "PyQt6"
except ImportError:
    from PySide6.QtWidgets import (
        QComboBox, QDialog, QFileDialog, QGraphicsLineItem, QGraphicsRectItem,
        QGraphicsScene, QGraphicsSimpleTextItem, QGraphicsView, QHBoxLayout,
        QLabel, QListWidget, QListWidgetItem, QMessageBox, QPlainTextEdit,
        QPushButton, QSpinBox, QSplitter, QTextBrowser, QVBoxLayout, QWidget,
    )
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPen
    QT_BINDING = "PySide6"

from .models import AtlasTrace, FlowNode, NodeKind, TruthBadge

try:
    import mutation_scenarios
except Exception:
    mutation_scenarios = None

try:
    from .evidence import AtlasBuilder
except Exception:  # pragma: no cover
    from evidence import AtlasBuilder  # type: ignore


BADGE_STYLES = {
    TruthBadge.EXECUTED: ("#0e3a5c", "#38bdf8"),
    TruthBadge.STATIC: ("#1e293b", "#64748b"),
    TruthBadge.MUTATED: ("#3a2a10", "#f59e0b"),
    TruthBadge.FAILED: ("#450a0a", "#ef4444"),
    TruthBadge.UNKNOWN: ("#0f172a", "#475569"),
}
BADGE_EDGE = {
    TruthBadge.EXECUTED: "#38bdf8",
    TruthBadge.STATIC: "#475569",
    TruthBadge.MUTATED: "#f59e0b",
    TruthBadge.FAILED: "#ef4444",
    TruthBadge.UNKNOWN: "#334155",
}


class AtlasGraphView(QGraphicsView):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHints(QPainter.RenderHint.Antialiasing)
        self.setStyleSheet("background-color: #0b111d; border: 1px solid #243042;")
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self._node_items: Dict[str, QGraphicsRectItem] = {}
        self._trace: Optional[AtlasTrace] = None

    def show_trace(self, trace: AtlasTrace) -> None:
        self._trace = trace
        self.scene.clear()
        self._node_items.clear()
        self._layout(trace)
        self._fit()

    def _layout(self, trace: AtlasTrace) -> None:
        # Layout columns by node kind (hierarchical levels)
        col_w, row_h = 250, 70
        node_w, node_h = 200, 44

        def col_of(n: FlowNode) -> int:
            return {
                NodeKind.SCENARIO: 0, NodeKind.EXCHANGE: 0,
                NodeKind.CAPDU: 1, NodeKind.RAPDU: 1,
                NodeKind.FILE: 2,
                NodeKind.FUNCTION: 2,
                NodeKind.TRANSFORMATION: 3,
                NodeKind.RESULT: 4,
                NodeKind.ASSERTION: 5,
                NodeKind.GUARD: 0,
                NodeKind.ENV: 6,
            }.get(n.kind, 2)

        rows: Dict[int, int] = {}
        pos: Dict[str, Any] = {}
        for n in trace.nodes:
            c = col_of(n)
            r = rows.get(c, 0)
            rows[c] = r + 1
            pos[n.id] = (c * col_w, r * row_h)

        # edges under nodes
        for e in trace.edges:
            if e.src not in pos or e.dst not in pos:
                continue
            sx, sy = pos[e.src]
            dx, dy = pos[e.dst]
            line = QGraphicsLineItem(sx + node_w / 2, sy + node_h / 2, dx + node_w / 2, dy + node_h / 2)
            pen = QPen(QColor("#38bdf8" if e.runtime else "#475569"),
                       2 if e.runtime else 1)
            if not e.runtime:
                pen.setStyle(Qt.PenStyle.DashLine)
            line.setPen(pen)
            line.setZValue(0)
            self.scene.addItem(line)

        for n in trace.nodes:
            x, y = pos[n.id]
            rect = QGraphicsRectItem(x, y, node_w, node_h)
            rect.setData(0, n.id)
            fill, border = BADGE_STYLES.get(n.badge, BADGE_STYLES[TruthBadge.UNKNOWN])
            rect.setBrush(QBrush(QColor(fill)))
            pen = QPen(QColor(border), 2)
            if n.badge == TruthBadge.STATIC:
                pen.setStyle(Qt.PenStyle.DashLine)
            rect.setPen(pen)
            rect.setZValue(1)
            rect.setFlag(QGraphicsRectItem.GraphicsItemFlag.ItemIsSelectable, True)
            self.scene.addItem(rect)
            self._node_items[n.id] = rect

            # label + sublabel
            title = QGraphicsSimpleTextItem(n.label[:38])
            title.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            title.setBrush(QBrush(QColor("#f1f5f9")))
            title.setPos(x + 6, y + 4)
            title.setZValue(2)
            self.scene.addItem(title)
            if n.sublabel:
                sub = QGraphicsSimpleTextItem(n.sublabel[:44])
                sub.setFont(QFont("Segoe UI", 7))
                sub.setBrush(QBrush(QColor("#94a3b8")))
                sub.setPos(x + 6, y + 24)
                sub.setZValue(2)
                self.scene.addItem(sub)

            badge = QGraphicsSimpleTextItem(n.badge.value)
            badge.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
            badge.setBrush(QBrush(QColor(border)))
            br = badge.boundingRect()
            badge.setPos(x + node_w - br.width() - 6, y + node_h - br.height() - 4)
            badge.setZValue(2)
            self.scene.addItem(badge)

        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-20, -20, 20, 20))

    def _fit(self) -> None:
        if self.scene.sceneRect().isValid():
            self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def wheelEvent(self, event) -> None:
        # standard zoom
        factor = 1.25 if event.angleDelta().y() > 0 else 0.8
        self.scale(factor, factor)

    def mousePressEvent(self, event) -> None:
        super().mousePressEvent(event)
        item = self.itemAt(event.pos())
        # bubbles: text items sit on top of rects
        if item is not None:
            rect = item if isinstance(item, QGraphicsRectItem) else None
            if rect is None:
                # find the rect at this position
                for r in self.items(event.pos()):
                    if isinstance(r, QGraphicsRectItem):
                        rect = r
                        break
            if rect is not None:
                nid = rect.data(0)
                if nid is not None and self._trace is not None:
                    parent = self.parent()
                    while parent is not None and not isinstance(parent, EmvAtlasWidget):
                        parent = parent.parent()
                    if parent is not None:
                        parent._inspect_node(nid)


class EmvAtlasWidget(QWidget):
    """Main Atlas mode: trace selector + graph + inspector + evidence strip."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.builder = AtlasBuilder()
        self._trace: Optional[AtlasTrace] = None
        self._guard_provider: Optional[Callable[[], Optional[Dict[str, Any]]]] = None
        self._scenario_ctx_provider: Optional[Callable[[Any], Any]] = None
        self._init_ui()

    def set_guard_provider(self, provider: Callable[[], Optional[Dict[str, Any]]]) -> None:
        self._guard_provider = provider

    def set_scenario_ctx_provider(self, provider: Callable[[Any], Any]) -> None:
        """qt_app hands the live playground fields in here (key_or_index -> ctx)."""
        self._scenario_ctx_provider = provider

    # ---------------- UI ----------------

    def _init_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        head = QHBoxLayout()
        t = QLabel("🗺️ EMV EXECUTION ATLAS")
        t.setStyleSheet("font-size: 13px; font-weight: bold; color: #38bdf8;")
        head.addWidget(t)
        head.addStretch(1)

        self.flow = QListWidget()
        self.flow.setMaximumWidth(0)  # hidden shim; real selectors below
        self.flow.hide()

        self.combo_kind = QComboBox()
        self.combo_kind.addItem("Scenario", "scenario")
        self.combo_kind.addItem("Replay exchange", "replay")
        self.combo_kind.addItem("Test script", "test")
        self.combo_kind.currentIndexChanged.connect(self._on_kind_changed)
        head.addWidget(QLabel("Source:"))
        head.addWidget(self.combo_kind)

        self.combo_scenario = QComboBox()
        if mutation_scenarios is not None:
            for s in mutation_scenarios.get_scenarios():
                self.combo_scenario.addItem(s.title, s.key)
        head.addWidget(self.combo_scenario)

        self.combo_replay = QComboBox()
        self.spin_exchange = QSpinBox()
        self.spin_exchange.setRange(0, 0)
        self._replays = self._find_replays()
        self._test_scripts = self._find_test_scripts()
        for p in self._replays:
            self.combo_replay.addItem(Path(p).name, str(p))

        self.combo_test = QComboBox()
        for p in self._test_scripts:
            self.combo_test.addItem(Path(p).name, str(p))

        self.combo_replay.setVisible(False)
        self.spin_exchange.setVisible(False)
        self.combo_test.setVisible(False)
        head.addWidget(self.combo_test)
        head.addWidget(self.combo_replay)
        self.lbl_excl = QLabel("Exchange #:")
        self.lbl_excl.setVisible(False)
        head.addWidget(self.lbl_excl)
        head.addWidget(self.spin_exchange)

        self.btn_trace = QPushButton("▶ Trace")
        self.btn_trace.setObjectName("btn-primary")
        self.btn_trace.clicked.connect(self.trace_current)
        head.addWidget(self.btn_trace)

        self.btn_fit = QPushButton("Fit")
        self.btn_fit.setObjectName("tab-corner-btn")
        self.btn_fit.clicked.connect(lambda: self.graph._fit())
        head.addWidget(self.btn_fit)

        self.btn_export = QPushButton("💾 Export JSON")
        self.btn_export.setObjectName("tab-corner-btn")
        self.btn_export.clicked.connect(self._export_json)
        head.addWidget(self.btn_export)

        root.addLayout(head)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setObjectName("split_atlas")

        # Left: event strip
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(QLabel("EVENTS / EVIDENCE"))
        self.events_list = QListWidget()
        self.events_list.setStyleSheet("font-family: Consolas, monospace; font-size: 9pt;")
        self.events_list.currentRowChanged.connect(self._on_event_selected)
        lv.addWidget(self.events_list, 1)
        splitter.addWidget(left)

        # Center: graph
        self.graph = AtlasGraphView(self)
        splitter.addWidget(self.graph)

        # Right: inspector (details + source)
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.addWidget(QLabel("INSPECTOR"))
        self.inspector = QTextBrowser()
        self.inspector.setStyleSheet("font-family: Consolas, monospace; font-size: 9pt;")
        rv.addWidget(self.inspector, 2)
        rv.addWidget(QLabel("SOURCE"))
        self.source = QPlainTextEdit()
        self.source.setReadOnly(True)
        self.source.setFont(QFont("Consolas", 9))
        rv.addWidget(self.source, 3)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        splitter.setStretchFactor(2, 2)
        root.addWidget(splitter, 1)

    def _find_replays(self) -> List[str]:
        out: List[str] = []
        for d in ("testlogs",):
            p = Path(self.builder.root) / d
            if p.exists():
                out.extend(str(f) for f in sorted(p.glob("*.json")))
        return out

    def _find_test_scripts(self) -> List[str]:
        out: List[str] = []
        # Dedupe by file name (not path): identical script may be copied to
        # both root and tests/ — show once, prefer the tests/ copy for pytest runs.
        seen = set()

        def _add(p: Path) -> None:
            name = p.name.lower()
            if not p.exists():
                return
            if name in seen:
                return
            out.append(str(p))
            seen.add(name)

        candidates = [
            self.builder.root / "test_emv_full_flow.py",
            self.builder.root / "test_emv_cognition.py",
            self.builder.root / "test_headless_gui.py",
        ]
        for c in candidates:
            _add(c)
        tests_dir = Path(self.builder.root) / "tests"
        if tests_dir.exists():
            for f in sorted(tests_dir.glob("test_*.py")):
                _add(f)
        return out

    def _on_kind_changed(self, idx: int) -> None:
        kind = self.combo_kind.currentData()
        replay = kind == "replay"
        test = kind == "test"
        self.combo_scenario.setVisible(not (replay or test))
        self.combo_replay.setVisible(replay)
        self.spin_exchange.setVisible(replay)
        self.lbl_excl.setVisible(replay)
        self.combo_test.setVisible(test)
        if replay and self.combo_replay.count() > 0:
            self._replay_selected(0)
            self.combo_replay.currentIndexChanged.connect(self._replay_selected)

    def _replay_selected(self, idx: int) -> None:
        if idx < 0:
            return
        path = self.combo_replay.itemData(idx)
        try:
            n = len(json.loads(Path(path).read_text(encoding="utf-8")))
            self.spin_exchange.setRange(0, max(0, n - 1))
        except Exception:
            self.spin_exchange.setRange(0, 0)

    # ---------------- actions ----------------

    def trace_current(self) -> None:
        kind = self.combo_kind.currentData()
        try:
            if kind == "replay":
                path = self.combo_replay.currentData()
                if not path:
                    return
                trace = self.builder.trace_replay_exchange(Path(path), self.spin_exchange.value())
            elif kind == "test":
                path = self.combo_test.currentData()
                if not path:
                    return
                trace = self.builder.trace_test_script(Path(path))
            else:
                scen_key = self.combo_scenario.currentData()
                ctx = None
                if self._scenario_ctx_provider is not None:
                    try:
                        ctx = self._scenario_ctx_provider(scen_key)
                    except Exception:
                        ctx = None
                trace = self.builder.trace_scenario(scen_key, ctx=ctx, guard_status_provider=self._guard_provider)
            self.set_trace(trace)
        except Exception as exc:
            QMessageBox.warning(self, "Atlas", f"Trace failed: {exc}")

    def set_trace(self, trace: AtlasTrace) -> None:
        self._trace = trace
        self.graph.show_trace(trace)
        self.events_list.clear()
        for ev in trace.events:
            item = QListWidgetItem(f"#{ev.seq:03d}  {ev.kind:<11}  {ev.label}")
            item.setData(0x0100, ev.node_id)
            self.events_list.addItem(item)
        n_stale = sum(1 for m in trace.modules if m.stale)
        cap = f"trace: {trace.title} — {len(trace.nodes)} nodes"
        if n_stale:
            cap += f" | ⚠ {n_stale} stale module path(s)"
        self._show_env(trace)

    def _on_event_selected(self, row: int) -> None:
        if row < 0 or self._trace is None:
            return
        item = self.events_list.item(row)
        nid = item.data(0x0100)
        node = next((n for n in self._trace.nodes if n.id == nid), None)
        if node is not None:
            self._inspect_node(node.id)

    # ---------------- inspector ----------------

    def _inspect_node(self, node_id: str) -> None:
        trace = self._trace
        if trace is None:
            return
        node = next((n for n in trace.nodes if n.id == node_id), None)
        if node is None:
            return
        # highlight in graph
        for nid, rect in self.graph._node_items.items():
            base_pen = rect.pen()
            base_pen.setWidth(2)
            rect.setPen(base_pen)
        if node_id in self.graph._node_items:
            r = self.graph._node_items[node_id]
            p = r.pen()
            p.setWidth(4)
            r.setPen(p)
            self.graph.centerOn(r)

        self.inspector.setHtml(self._inspector_html(node))
        self._show_source(node)

    def _inspector_html(self, node: FlowNode) -> str:
        out = [f"<h3 style='color:#38bdf8;margin:0;'>[{node.badge.value}] {node.label}</h3>"]
        out.append(f"<p style='color:#94a3b8;margin:2px 0;'>kind: {node.kind.value}</p>")
        if node.source:
            ref = node.source
            out.append(f"<p>File: <code>{ref.file}</code><br/>"
                       f"Lines: {ref.line_start}–{ref.line_end}<br/>"
                       f"Signature: <code>{ref.signature or node.label}</code><br/>"
                       f"Qualified: <code>{ref.qualname}</code></p>")
            if ref.docstring:
                out.append(f"<p style='color:#94a3b8;'><i>{ref.docstring[:400]}</i></p>")
        if node.kind == NodeKind.TRANSFORMATION:
            before = node.meta.get("before", "")
            after = node.meta.get("after", "")
            out.append(f"<p>BEFORE <code>{before}</code><br/>AFTER&nbsp;&nbsp;<code>{after}</code><br/>"
                       f"in {node.meta.get('in_sha256','')[:16]}… → out {node.meta.get('out_sha256','')[:16]}…</p>")
        if node.kind == NodeKind.ASSERTION:
            out.append(f"<p>expected: <code>{node.meta.get('expected','')}</code><br/>"
                       f"observed: <code>{node.meta.get('observed','')}</code><br/>"
                       f"evidence: {node.meta.get('evidence','')}<br/>"
                       f"provenance: {node.meta.get('provenance','')}</p>")
            cq = node.meta.get("creation_qualname", "")
            cf = node.meta.get("creation_file", "")
            cl = node.meta.get("creation_line", 0)
            if cf:
                out.append(f"<p style='color:#a78bfa;'>CREATED AT (runtime provenance):<br/>"
                           f"<code>{cq or '?'}</code><br/>"
                           f"<code>{cf}:{cl}</code></p>")
        if node.kind == NodeKind.ENV:
            stale = node.meta.get("stale")
            out.append(f"<p>imported: <code>{node.meta.get('imported_path','')}</code><br/>"
                       f"expected: <code>{node.meta.get('expected_path','')}</code><br/>"
                       f"{'⚠ STALE / EXTERNAL PATH' if stale else 'canonical path'}</p>")
        for k, v in node.meta.items():
            if k in ("hex", "signature", "docstring"):
                continue
            out.append(f"<p style='color:#64748b;margin:1px 0;'>{k}: {str(v)[:120]}</p>")
        return "".join(out)

    def _show_source(self, node: FlowNode) -> None:
        if node.source is None:
            self.source.setPlainText("(no source reference)")
            return
        ref = node.source
        lines = self.builder.index.read_lines(ref, pad=2)
        numbered = [f"{ref.line_start - 2 + i:5d}  {ln}" for i, ln in enumerate(lines)]
        self.source.setPlainText("\n".join(numbered))

    def _show_env(self, trace: AtlasTrace) -> None:
        rows = []
        for m in trace.modules:
            mark = "⚠ STALE" if m.stale else "ok"
            rows.append(f"{m.name:22s} {mark:8s} {m.imported_path}")
        self.inspector.setHtml(
            "<h3 style='color:#38bdf8;margin:0;'>ENVIRONMENT / MODULE PATHS</h3><pre>"
            + "\n".join(rows) + "</pre>")

    # ---------------- export ----------------

    def _export_json(self) -> None:
        if self._trace is None:
            self._toast("Nothing to export yet — trace first.", "warn")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Atlas Trace as JSON",
            str(Path(self.builder.root) / f"{self._trace.trace_id}.json"),
            "JSON Files (*.json)")
        if not path:
            return
        try:
            Path(path).write_text(json.dumps(self._trace.to_dict(), indent=2), encoding="utf-8")
            self._toast(f"💾 Exported trace → {Path(path).name}", "ok")
        except Exception as exc:
            QMessageBox.warning(self, "Atlas", f"Export failed: {exc}")

    def _toast(self, msg: str, kind: str = "info") -> None:
        top = self.window()
        fn = getattr(top, "_show_toast", None)
        if callable(fn):
            fn(msg, kind)


class AtlasWindow(QDialog):
    """Modeless standalone window for the Atlas mode."""

    def __init__(self, guard_provider=None, scenario_ctx_provider=None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("🗺️ EMV Execution Atlas — REL8HF")
        self.resize(1280, 800)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.atlas = EmvAtlasWidget(self)
        if guard_provider is not None:
            self.atlas.set_guard_provider(guard_provider)
        if scenario_ctx_provider is not None:
            self.atlas.set_scenario_ctx_provider(scenario_ctx_provider)
        lay.addWidget(self.atlas)


def open_atlas_window(parent: Optional[QWidget] = None, guard_provider=None) -> AtlasWindow:
    win = AtlasWindow(guard_provider=guard_provider, parent=parent)
    win.setModal(False)
    win.show()
    win.raise_()
    win.activateWindow()
    return win
