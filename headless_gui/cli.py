from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

# Project root is one directory above headless_gui/.
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Configure Qt before importing the application.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_OPENGL", "software")
os.environ.setdefault("QT_QUICK_BACKEND", "software")

import qt_app

# IMPORTANT:
# qt_app.py selects PyQt6 first / PySide6 fallback and imports Qt modules.
# Reuse those exact modules.
QtCore = qt_app.QtCore
QtGui = qt_app.QtGui
QtWidgets = qt_app.QtWidgets

QApplication = QtWidgets.QApplication
QMainWindow = QtWidgets.QMainWindow
QWidget = QtWidgets.QWidget
QAbstractButton = QtWidgets.QAbstractButton
QComboBox = QtWidgets.QComboBox
QLineEdit = QtWidgets.QLineEdit
QPlainTextEdit = QtWidgets.QPlainTextEdit
QTextEdit = QtWidgets.QTextEdit
QTextBrowser = QtWidgets.QTextBrowser
QTabWidget = QtWidgets.QTabWidget
QAction = QtGui.QAction

# Keep a strong reference to QApplication for the entire CLI process.
# The v6 harness created QApplication as a local variable and then returned
# only the main window. Under PyQt6 that can allow the QApplication wrapper/C++
# lifetime to end, invalidating child QWidget wrappers such as self.tabs.
_APP: Optional[QApplication] = None


def ensure_app() -> QApplication:
    global _APP
    app = QApplication.instance()
    if app is None:
        _APP = QApplication(sys.argv[:1])
    else:
        _APP = app
    return _APP


def process_events(ms: int = 25) -> None:
    app = ensure_app()
    loop = QtCore.QEventLoop()
    QtCore.QTimer.singleShot(max(0, int(ms)), loop.quit)
    loop.exec()


def qt_deleted(obj: Any) -> bool:
    """Detect invalid Qt wrappers without assuming one binding."""
    try:
        if obj is None:
            return True
        if qt_app.QT_BINDING == "PyQt6":
            try:
                import sip
                return bool(sip.isdeleted(obj))
            except Exception:
                pass
        # PySide6 compatibility.
        try:
            import shiboken6
            return not bool(shiboken6.isValid(obj))
        except Exception:
            pass
    except Exception:
        pass
    return False


def widget_path(widget: QWidget) -> str:
    parts: List[str] = []
    current = widget
    seen = set()

    while isinstance(current, QWidget) and id(current) not in seen:
        seen.add(id(current))
        parts.append(current.objectName() or current.__class__.__name__)
        try:
            current = current.parentWidget()
        except RuntimeError:
            break

    return " > ".join(reversed(parts))


def describe_widget(widget: QWidget) -> Dict[str, Any]:
    if qt_deleted(widget):
        return {
            "python_type": f"{type(widget).__module__}.{type(widget).__name__}",
            "qt_deleted": True,
        }

    result: Dict[str, Any] = {
        "python_type": f"{type(widget).__module__}.{type(widget).__name__}",
        "qt_class": widget.metaObject().className(),
        "object_name": widget.objectName(),
        "path": widget_path(widget),
        "visible": widget.isVisible(),
        "enabled": widget.isEnabled(),
        "geometry": [widget.x(), widget.y(), widget.width(), widget.height()],
    }

    if isinstance(widget, QAbstractButton):
        result.update({
            "text": widget.text(),
            "checkable": widget.isCheckable(),
            "checked": widget.isChecked() if widget.isCheckable() else None,
        })
    elif isinstance(widget, QComboBox):
        result.update({
            "current_index": widget.currentIndex(),
            "current_text": widget.currentText(),
        })
    elif isinstance(widget, QLineEdit):
        result["text_length"] = len(widget.text())
    elif isinstance(widget, (QTextEdit, QPlainTextEdit, QTextBrowser)):
        result["text_length"] = len(widget.toPlainText())

    if isinstance(widget, QTabWidget):
        count = widget.count()
        result["tabs"] = [
            {
                "index": i,
                "title": widget.tabText(i),
                "enabled": widget.isTabEnabled(i),
                "widget_class": (
                    widget.widget(i).metaObject().className()
                    if widget.widget(i) is not None else None
                ),
            }
            for i in range(count)
        ]

    return result


def discover_widgets(window: QMainWindow) -> List[QWidget]:
    widgets: List[QWidget] = []
    seen = set()

    def add(value: Any) -> None:
        if not isinstance(value, QWidget):
            return
        if qt_deleted(value):
            return
        ident = id(value)
        if ident not in seen:
            seen.add(ident)
            widgets.append(value)

    # Direct application roots.
    add(window)
    add(window.centralWidget())
    add(window.menuBar())
    add(window.statusBar())

    # Direct widget attributes created by Rel8AppletWindow.
    for value in vars(window).values():
        if isinstance(value, QWidget):
            add(value)

    # Generic child walk. Deleted wrappers are skipped.
    def walk(obj: QWidget) -> None:
        if qt_deleted(obj):
            return
        try:
            children = obj.children()
        except RuntimeError:
            return
        except Exception:
            return

        for child in children:
            if qt_deleted(child):
                continue
            add(child)
            if isinstance(child, QWidget):
                walk(child)

    for root_widget in list(widgets):
        walk(root_widget)

    # Explicitly interrogate the main tab widget. This gives a strong,
    # application-specific validation independent of generic tree traversal.
    tabs = getattr(window, "tabs", None)
    if isinstance(tabs, QTabWidget) and not qt_deleted(tabs):
        add(tabs)
        try:
            for i in range(tabs.count()):
                page = tabs.widget(i)
                add(page)
                if isinstance(page, QWidget):
                    walk(page)
        except RuntimeError:
            pass

    return widgets


def menu_actions(window: QMainWindow) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()

    def visit(action: QAction) -> None:
        if qt_deleted(action):
            return
        ident = id(action)
        if ident in seen:
            return
        seen.add(ident)

        out.append({
            "text": action.text(),
            "enabled": action.isEnabled(),
            "checkable": action.isCheckable(),
            "checked": action.isChecked() if action.isCheckable() else None,
        })

        menu = action.menu()
        if menu is not None:
            for child in menu.actions():
                visit(child)

    bar = window.menuBar()
    for action in bar.actions():
        visit(action)

    return out


def inventory(window: QMainWindow) -> Dict[str, Any]:
    widgets = discover_widgets(window)

    buttons = [
        {
            "path": widget_path(w),
            "text": w.text(),
            "enabled": w.isEnabled(),
        }
        for w in widgets
        if isinstance(w, QAbstractButton)
    ]

    tabs = [
        {
            "path": widget_path(w),
            "count": w.count(),
            "tabs": [w.tabText(i) for i in range(w.count())],
        }
        for w in widgets
        if isinstance(w, QTabWidget)
    ]

    actions = menu_actions(window)

    return {
        "qt_binding": getattr(qt_app, "QT_BINDING", "unknown"),
        "widget_count": len(widgets),
        "widgets": [describe_widget(w) for w in widgets],
        "button_count": len(buttons),
        "buttons": buttons,
        "tab_widgets": tabs,
        "action_count": len(actions),
        "actions": actions,
    }


def lifecycle_probe(window: QMainWindow) -> Dict[str, Any]:
    app = ensure_app()
    tabs = getattr(window, "tabs", None)

    before = {
        "qapplication_exists": QApplication.instance() is not None,
        "qapplication_python_id": id(app),
        "window_deleted": qt_deleted(window),
        "tabs_attribute_present": tabs is not None,
        "tabs_deleted": qt_deleted(tabs) if tabs is not None else None,
    }

    try:
        before["tabs_count"] = tabs.count() if isinstance(tabs, QTabWidget) else None
    except Exception as exc:
        before["tabs_count_error"] = f"{type(exc).__name__}: {exc}"

    process_events(25)

    after = {
        "qapplication_exists": QApplication.instance() is not None,
        "window_deleted": qt_deleted(window),
        "tabs_deleted": qt_deleted(tabs) if tabs is not None else None,
    }

    try:
        after["tabs_count"] = tabs.count() if isinstance(tabs, QTabWidget) else None
    except Exception as exc:
        after["tabs_count_error"] = f"{type(exc).__name__}: {exc}"

    return {
        "before_events": before,
        "after_events": after,
    }


def safe_runtime_probe(window: QMainWindow) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    try:
        relay_thread = getattr(window, "relay_thread", None)
        result["app_runtime"] = {
            "tab_index": window.tabs.currentIndex(),
            "active_tab": window.tabs.tabText(window.tabs.currentIndex()),
            "relay_running": bool(
                relay_thread is not None
                and hasattr(relay_thread, "isRunning")
                and relay_thread.isRunning()
            ),
            "loaded_modules": list(window.project_runtime.modules.keys()),
        }
    except Exception as exc:
        result["app_runtime"] = {
            "error": f"{type(exc).__name__}: {exc}"
        }
    return result


def build_window() -> QMainWindow:
    ensure_app()
    return qt_app.Rel8AppletWindow()


def audit(window: QMainWindow) -> Dict[str, Any]:
    inv = inventory(window)
    life = lifecycle_probe(window)
    runtime = safe_runtime_probe(window)

    result: Dict[str, Any] = {
        "status": "PASS",
        "errors": [],
        "warnings": [],
        "inventory": inv,
        "lifecycle": life,
        "runtime": runtime,
    }

    if inv["widget_count"] == 0:
        result["errors"].append(
            "Zero widgets discovered using the same Qt binding as qt_app.py."
        )
    if not inv["tab_widgets"]:
        result["errors"].append("No QTabWidget found.")
    if inv["button_count"] == 0:
        result["errors"].append("No QAbstractButton controls found.")

    tabs_after = life["after_events"]
    if tabs_after.get("tabs_deleted"):
        result["errors"].append(
            "self.tabs became an invalid/deleted Qt object after event processing."
        )

    result["status"] = "FAIL" if result["errors"] else "PASS"
    return result
def click_target(window: QMainWindow, target: str) -> Dict[str, Any]:
    """
    Headless GUI action.

    target may match:
      - objectName
      - exact widget text
      - exact widget path
      - QAction text
    """
    process_events(25)

    widgets = discover_widgets(window)

    # 1. QWidget targets
    for widget in widgets:
        if qt_deleted(widget):
            continue

        object_name = widget.objectName()
        text = ""
        if isinstance(widget, QAbstractButton):
            text = widget.text()

        path = widget_path(widget)

        if target not in {object_name, text, path}:
            continue

        if isinstance(widget, QAbstractButton):
            if not widget.isEnabled():
                return {
                    "status": "FAIL",
                    "error": f"Widget found but disabled: {path}",
                }

            before = (
                widget.isChecked()
                if widget.isCheckable()
                else None
            )

            widget.click()
            process_events(100)

            after = (
                widget.isChecked()
                if widget.isCheckable()
                else None
            )

            return {
                "status": "PASS",
                "action": "click",
                "target": target,
                "path": path,
                "text": widget.text(),
                "checked_before": before,
                "checked_after": after,
            }

    # 2. QAction targets
    actions = window.menuBar().actions()

    def find_action(action_list):
        for action in action_list:
            if qt_deleted(action):
                continue

            if action.text() == target:
                return action

            menu = action.menu()
            if menu is not None:
                found = find_action(menu.actions())
                if found is not None:
                    return found

        return None

    action = find_action(actions)

    if action is not None:
        if not action.isEnabled():
            return {
                "status": "FAIL",
                "error": f"Action found but disabled: {target}",
            }

        action.trigger()
        process_events(100)

        return {
            "status": "PASS",
            "action": "trigger",
            "target": target,
            "text": action.text(),
        }

    return {
        "status": "FAIL",
        "error": f"No clickable target found: {target}",
    }

def run(args: argparse.Namespace) -> int:
    try:
        window = build_window()

        if args.command == "audit":
            result = audit(window)
        elif args.command == "inventory":
            result = inventory(window)

            if getattr(args, "summary", False) and not getattr(args, "full", False):
                result = {
                    "status": result.get("status", "PASS"),
                    "qt_binding": result.get("qt_binding"),
                    "widget_count": result.get("widget_count"),
                    "button_count": result.get("button_count"),
                    "action_count": result.get("action_count"),
                    "tab_widgets": result.get("tab_widgets", []),
                    "buttons": result.get("buttons", []),
                    "actions": result.get("actions", []),
                }
        elif args.command == "probe":
            result = safe_runtime_probe(window)
        elif args.command == "lifecycle":
            result = lifecycle_probe(window)
        elif args.command == "click":
            result = click_target(window, args.target)
        elif args.command == "screenshot":
            window.show()
            process_events(50)
            image = window.grab()
            target = os.path.abspath(args.path)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            result = {
                "saved": bool(image.save(target)),
                "path": target,
                "size": [image.width(), image.height()],
            }
        else:
            raise ValueError(args.command)

        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return 0 if result.get("status", "PASS") != "FAIL" else 2

    except Exception as exc:
        print(json.dumps({
            "status": "ERROR",
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        }, indent=2, ensure_ascii=False), file=sys.stderr)
        return 3


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="headless_gui",
        description="Qt-binding-correct, lifetime-safe headless REL8HF GUI QA runner.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("audit")
    inventory_parser = sub.add_parser("inventory")
    inventory_parser.add_argument(
        "--summary",
        action="store_true",
        help="Show compact inventory instead of the full widget dump.",
    )
    inventory_parser.add_argument(
        "--full",
        action="store_true",
        help="Show the complete widget inventory.",
    )
    sub.add_parser("probe")
    sub.add_parser("lifecycle")
    click = sub.add_parser("click")
    click.add_argument("target")

    shot = sub.add_parser("screenshot")
    shot.add_argument("path")

    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
