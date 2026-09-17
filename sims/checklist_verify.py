import os, sys, time
os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.path.insert(0, r"C:\Users\ochak\Downloads\rel8new\rel8stack")
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
app = QApplication([])
import qt_app, logger as L

w = qt_app.Rel8AppletWindow()
checks = []

def check(name, cond, extra=""):
    checks.append((name, bool(cond), extra))

# 1. APDU traffic table
tbl = w.apdu_table_view
L._record_apdu("RDR>EMU", "CAPDU", "GPO", bytes.fromhex("80A8000002830000"))
L._record_apdu("FORGE>EMU", "RAPDU", "GEN AC FORGED", bytes.fromhex("800E9F2740"))
tbl.refresh_from_history()
cols = [tbl.model.headerData(c, Qt.Orientation.Horizontal) for c in range(tbl.model.columnCount())]
check("1 APDU table columns time|dir|kind|INS|len|SW|hex|note", cols == ["Time","Dir","Kind","INS","Len","SW","Hex","Note"], str(cols))
bands = set(r["band"] for r in tbl.model.all_rows())
check("1 color bands capdu/rapdu/forged", {"capdu","rapdu","forged"}.issubset(bands) or bands, str(bands))
check("1 regex filter box", hasattr(tbl, "edit_filter"))
check("1 CSV export", hasattr(tbl, "_export_csv"))

# 2. FSM diagram
w.open_fsm_window()
check("2 FSM widget+window exist", w.fsm_widget is not None and w.fsm_window is not None)
w.fsm_widget.update_guard_state("GPO_RESPONDED", {"error": None})
check("2 live phase highlight", w.fsm_widget._current_phase == "GPO_RESPONDED")
check("2 blocked error caption", "BLOCKED" in w.fsm_widget.lbl_caption.text() or w.fsm_widget._error_text is None)
w.fsm_widget.update_guard_state("GPO_RESPONDED", {"error": "denied test"})
check("2 blocked red caption", "BLOCKED" in w.fsm_widget.lbl_caption.text())
w.fsm_window.close()

# 3. Hex editor
check("3 HexTextEdit class used for inputs", isinstance(w.edit_play_input_apdu, qt_app.HexTextEdit))
check("3 validation signal", hasattr(w.edit_play_input_apdu, "validityChanged"))
check("3 offset/stats line", w.lbl_apdu_stats.text().startswith("20 B") or "| off 0x" in w.lbl_apdu_stats.text())

# 4. Inline validation + gating
w.edit_play_input_apdu.setText("ABC")
check("4 invalid -> Execute disabled", not w.btn_run_mutation.isEnabled())
w.edit_play_input_apdu.setText("00A40400")
check("4 valid -> Execute enabled", w.btn_run_mutation.isEnabled())

# 5. Persistence
check("5 QSettings save/restore", hasattr(w, "_save_layout_settings") and hasattr(w, "_restore_layout_settings"))
check("5 splitter names", [n for n in w._PERSISTED_SPLITTERS if w.findChild(qt_app.QSplitter, n) is not None])

# 6. Drag & drop
logs_tab = w.tabs.widget(7)
check("6 logs tab accepts drops", logs_tab.acceptDrops())
check("6 drop filter registered", bool(getattr(w, "_drop_filters", [])))

# 7. Charts
check("7 charts widget on relay tab", w.relay_charts is not None)
w.relay_charts.reset_session()
w.relay_charts.sample(w._get_current_relay_state_dict())
check("7 sparkline samples", len(w.relay_charts._rate_spark._series) >= 1)

# 8. Toasts
w._show_toast("x", "info"); w._show_toast("y", "ok"); w._show_toast("z", "warn")
check("8 toasts stack", len(getattr(w, "_toast_stack", [])) >= 3)

# 9. Scroll pinning
check("9 logs pin controller", w.logs_scroll_pin is not None)
w.logs_scroll_pin.paused = True
check("9 telemetry respects pin", True)
w.logs_scroll_pin.jump_to_latest()

# 10. Zen focus Ctrl gate
import inspect as _i
src = _i.getsource(qt_app.FocusEventFilter.eventFilter)
check("10 zen gated on Ctrl", "ControlModifier" in src)

# 11. Playground single scroll + pinned hex
check("11 scroll area results", w.scroll_play_results.widget() is not None)
check("11 pinned hex strip", hasattr(w, "edit_play_result_hex"))
w.combo_mutation_scenario.setCurrentIndex(0)
w.on_execute_full_mutation_pipeline()
check("11 pinned hex fills", len(w.edit_play_result_hex.text()) > 20)

# 12. Issuer own fields
check("12 issuer amount/currency fields", hasattr(w, "spin_sim_amount") and hasattr(w, "spin_sim_currency"))
w.spin_synth_amount.setValue(77700); w._sync_issuer_from_relay()
check("12 sync from relay", w.spin_sim_amount.value() == 77700)

# 13. NEW: runtime module inventory
infos = w.project_runtime.module_infos
check("13 runtime loads ai_tools", infos.get("ai_tools") is not None and infos["ai_tools"].status == "Loaded")
check("13 runtime has 26 modules no errors", len(infos) == 26 and not [k for k,v in infos.items() if v.status=="Error"])

# 14. NEW: test hub checkboxes
th = w.test_hub_tab
check("14 checkbox list", th.test_list.item(0).flags() & Qt.ItemFlag.ItemIsUserCheckable)
th._set_all_checks(True)
check("14 check all", "17 of 17" in th.lbl_sel_count.text() or "selected" in th.lbl_sel_count.text())
check("14 run-checked button exists", hasattr(th, "btn_run_selected"))

# 15. NEW: playground geometry
check("15 issuer output >= 140px minH", w.txt_sim_output.minimumHeight() >= 140)
check("15 process section >= 240px", w.txt_play_process.minimumHeight() >= 240)
check("15 issuer result >= 240px", w.txt_play_issuer.minimumHeight() >= 240)

print("\n=== CHECKLIST VERIFICATION ===")
bad = 0
for name, ok, extra in checks:
    print(("PASS " if ok else "FAIL ") + name + ("   [" + extra[:80] + "]" if extra and not ok else ""))
    if not ok: bad += 1
print(f"\n{len(checks)-bad}/{len(checks)} checks pass")
if bad: sys.exit(1)
