import sys, time, threading, json
sys.path.insert(0, r"C:\Users\ochak\Downloads\rel8new\rel8stack")
sys.path.insert(0, r"C:\Users\ochak\Downloads\rel8new\rel8stack\emv_lab") if False else None

import rel8hf
from rel8hf_launcher import LaunchConfig
import emv_lab

cfg = LaunchConfig()
cfg.apply_env()
srv = rel8hf.RelayServer(host="127.0.0.1", port=5566)
cfg.apply_runtime_state(srv)

t = threading.Thread(target=srv.start, daemon=True)
t.start()
deadline = time.time() + 2.0
while time.time() < deadline and not srv.running:
    time.sleep(0.02)
print("relay running:", srv.running)

ses = emv_lab.EmvLabSession(mode="closed_loop", relay_host="127.0.0.1", relay_port=5566)
ses.start()
res = ses.wait(12.0)
print("=== session result ===")
print(json.dumps(res, indent=2, default=str))
print("=== reader events (tail) ===")
if ses.reader:
    for ev in list(ses.reader.events)[-12:]:
        print(f"  {ev.kind:14} {ev.direction:3} {ev.state_before}->{ev.state_after} {ev.detail[:90]}")
print("=== tag events (tail) ===")
if ses.tag:
    for ev in list(ses.tag.events)[-12:]:
        print(f"  {ev.kind:14} {ev.direction:3} {ev.state_before}->{ev.state_after} {ev.detail[:90]}")
ses.stop()
srv._shutdown_requested = True
srv.stop()
