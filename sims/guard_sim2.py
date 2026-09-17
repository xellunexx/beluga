import sys
sys.path.insert(0, r"C:\Users\ochak\Downloads\rel8new\rel8stack")
from guard import Guard, Phase

def step(g, target, sw=b"\x90\x00"):
    g.record_sw(sw)
    ok, r = g.advance(target)
    return ok, r

out = []

# Scenario X: PPSE re-arrival in READ_RECORD_DONE (user log case)
# The code path at rel8hf.py:1489-1499 restarts EMV flow THEN advances.
out.append("== X: PPSE SELECT in READ_RECORD_DONE (what rel8hf does) ==")
g = Guard()
for t in (Phase.PPSE_SELECTED, Phase.AID_SELECTED, Phase.GPO_RESPONDED, Phase.READ_RECORD_DONE):
    g.record_sw(b"\x90\x00"); g.advance(t)
out.append(f"  ...phase = {g.phase.name}")
# rel8hf now does: record_sw(sw) [fresh PPSE RAPDU SW] -> _restart_emv_flow -> guard.reset() -> record_sw(sw) -> advance(PPSE_SELECTED)
outsiders_sw = b"\x90\x00"
g.record_sw(outsiders_sw)
out.append(f"  before restart: {g.phase.name}")
g.reset()  # inside _restart_emv_flow
g.record_sw(outsiders_sw)  # rel8hf re-records after reset to re-enable advance
ok, r = g.advance(Phase.PPSE_SELECTED)
out.append(f"  after restart+advance: {ok} | {r}")

# Scenario Y: what WOULD happen if _restart didn't re-record (simulating lost SW)
out.append("== Y: if restart ran without re-recording SW (hypothetical) ==")
g = Guard()
for t in (Phase.PPSE_SELECTED, Phase.AID_SELECTED, Phase.GPO_RESPONDED, Phase.READ_RECORD_DONE):
    g.record_sw(b"\x90\x00"); g.advance(t)
g.reset()
ok, r = g.advance(Phase.PPSE_SELECTED)
out.append(f"  {ok} | {r}")

# Scenario Z: GPO arrives at PPSE_SELECTED (duplicate) — not sticky → blocked
out.append("== Z: GPO in PPSE_SELECTED (duplicate, would-be) ==")
g = Guard()
g.record_sw(b"\x90\x00"); g.advance(Phase.PPSE_SELECTED)
g.record_sw(b"\x90\x00")
ok, r = g.advance(Phase.GPO_RESPONDED)
out.append(f"  {ok} | {r}")

# Scenario W: READ_RECORD done twice legitimately (2 AFL entries)
out.append("== W: second READ RECORD (AFL multi-record) ==")
g = Guard()
for t in (Phase.PPSE_SELECTED, Phase.AID_SELECTED, Phase.GPO_RESPONDED, Phase.READ_RECORD_DONE):
    g.record_sw(b"\x90\x00"); g.advance(t)
g.record_sw(b"\x90\x00")  # second record arrives
ok, r = g.advance(Phase.READ_RECORD_DONE)
out.append(f"  {ok} | {r}")

# Scenario V: Sequence skips (GPO before PPSE granted): IDLE → GPO illegal
out.append("== V: GPO without PPSE ==")
g = Guard()
g.record_sw(b"\x90\x00")
ok, r = g.advance(Phase.GPO_RESPONDED)
out.append(f"  {ok} | {r}")

print("\n".join(out))
