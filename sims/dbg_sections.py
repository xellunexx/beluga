import subprocess, sys, re
proc = subprocess.run([sys.executable, 'test_emv_full_flow.py'], capture_output=True, text=True, encoding='utf-8', errors='replace', cwd=r'C:\Users\ochak\Downloads\rel8new\rel8stack')
lines = proc.stdout.splitlines()
rx = re.compile(r'^([A-Z])\.\s+([A-Za-z0-9_]+\.py)\s+(.+?)\s*$')
hits = [l for l in lines if rx.match(l)]
print('section matches:', len(hits))
for h in hits: print('  ', h[:70])
print('script rc:', proc.returncode, 'lines:', len(lines))
