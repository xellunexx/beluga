import sys, time, threading, json
sys.path.insert(0, r"C:\Users\ochak\Downloads\rel8new\rel8stack")
import rel8hf
from rel8hf_launcher import LaunchConfig
import emv_lab

cfg = LaunchConfig()
cfg.apply_env()
srv = rel8hf.RelayServer(host="127.0.0.1", port=5577)
cfg.apply_runtime_state(srv)
threading.Thread(target=srv.start, daemon=True).start()
deadline = time.time() + 2.0
while time.time() < deadline and not srv.running:
    time.sleep(0.02)
print("relay running:", srv.running)

def run_once(tag):
    ses = emv_lab.EmvLabSession(mode="closed_loop", relay_host="127.0.0.1", relay_port=5577,
                                session_id=f"{tag}-1")
    ses.start()
    res = ses.wait(8.0)
    st = ses.status()
    print(f"{tag}: state={st.get('state')} reader={st.get('reader_state')} tag={st.get('tag_state')}")
    ses.stop()

# FIRST run complete, then a SECOND run against the SAME relay (matches the
# "fresh PPSE SELECT during AID_SELECTED" evidence in your log).
run_once("run-A")
time.sleep(0.4)
run_once("run-B")
srv._shutdown_requested = True
srv.stop()
