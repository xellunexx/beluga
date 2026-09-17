import sys
sys.path.insert(0, r"C:\Users\ochak\Downloads\rel8new\rel8stack")
from guard import Guard, Phase

E = []
def log(*a): E.append(" ".join(str(x) for x in a))

# A. Baseline happy path
g = Guard()
log("== A: baseline ==")
for target in ("PPSE_SELECTED","AID_SELECTED","GPO_RESPONDED","READ_RECORD_DONE"):
    g.record_sw(b"\x90\x00")
    ok, r = g.advance(getattr(Phase, target))
    log(f"  ->{target}: {ok} | {r}")

# B. Repeated PPSE with SW=9000 (sticky allowed)
g = Guard(); E.append("")
log("== B: repeated PPSE sticky ==")
g.record_sw(b"\x90\x00"); g.advance(Phase.PPSE_SELECTED)
g.record_sw(b"\x90\x00")
ok, r = g.advance(Phase.PPSE_SELECTED)
log(f"  repeatPPSE SW9000: {ok} | {r}")

# C. PPSE_SELECTED sticky WITHOUT sw refresh (stale SW=None after reset not required here)
g = Guard()
log("== C: advance PPSE without any SW record ==")
ok, r = g.advance(Phase.PPSE_SELECTED)
log(f"  {ok} | {r}")

# D. Repeated READ_RECORD: sticky after entering
g = Guard(); log("== D: repeated READ_RECORD sticky ==")
for target in ("PPSE_SELECTED","AID_SELECTED","GPO_RESPONDED","READ_RECORD_DONE"):
    g.record_sw(b"\x90\x00"); g.advance(getattr(Phase, target))
g.record_sw(b"\x90\x00")
ok,r = g.advance(Phase.READ_RECORD_DONE)
log(f"  repeatREADREC SW9000 (sticky): {ok} | {r}")

# E. Sticky READ_RECORD when SW != 9000 (record fail then retry) → blocked
g = Guard(); log("== E: repeated READ_RECORD with failing SW ==")
for target in ("PPSE_SELECTED","AID_SELECTED","GPO_RESPONDED","READ_RECORD_DONE"):
    g.record_sw(b"\x90\x00"); g.advance(getattr(Phase, target))
g.record_sw(b"\x6a\x82")   # non-9000
ok,r = g.advance(Phase.READ_RECORD_DONE)
log(f"  repeatREADREC SW6A82: {ok} | {r}")

# F. GPO sticky? NOT sticky — duplicate GPO gets blocked by SW-rule/transition-table
g = Guard(); log("== F: repeated GPO (NOT sticky) ==")
for t in ("PPSE_SELECTED","AID_SELECTED","GPO_RESPONDED"):
    g.record_sw(b"\x90\x00"); g.advance(getattr(Phase,t))
g.record_sw(b"\x90\x00")
ok,r = g.advance(Phase.GPO_RESPONDED)
log(f"  repeatGPO SW9000: {ok} | {r}")

# G. _last_sw survives reset? reset clears _last_sw to None; next advance w/o record_sw is blocked
g = Guard(); log("== G: SW behavior across reset ==")
g.record_sw(b"\x90\x00"); g.advance(Phase.PPSE_SELECTED)
g.reset()
ok,r = g.advance(Phase.AID_SELECTED)
log(f"  after reset advance AID without record_sw: {ok} | {r}")

# H. ARQC_RECEIVED requires SW — replay-protect: does advance require last_sw==9000?
g = Guard(); log("== H: FIRST_GAC_SENT -> ARQC_RECEIVED without fresh SW record ==")
for t in ("PPSE_SELECTED","AID_SELECTED","GPO_RESPONDED","READ_RECORD_DONE","FIRST_GAC_SENT"):
    g.record_sw(b"\x90\x00"); g.advance(getattr(Phase,t))
# don't record_sw, reuse stale
ok,r = g.advance(Phase.ARQC_RECEIVED)
log(f"  {ok} | {r}")

print("\n".join(E))
