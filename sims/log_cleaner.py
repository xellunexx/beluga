import os
import re
import json
from pathlib import Path

LOGS_DIR = Path("logs")
OUT_DIR = Path("testlogs")

def clean_log(file_path):
    with open(file_path, "r") as f:
        lines = f.readlines()

    sequence = []
    current_capdu = None
    
    # Mutation tracking for the *current* exchange
    original_values = {} # tag -> original_hex
    
    for line in lines:
        # 1. Track CAPDUs
        m = re.search(r"CAPDU_TRACE seq=\d+ len=\d+ src=\S+ dst=\S+ data=([0-9A-F]+)", line)
        if m:
            current_capdu = m.group(1)
            original_values = {} # reset for new exchange
            continue

        # 2. Track original values from mutation logs
        # IAC-Default zeroed: B450840000 -> 0000000000
        m = re.search(r"IAC-(Default|Online|Denial) zeroed: ([0-9A-F]+) -> ([0-9A-F]+)", line)
        if m:
            orig = m.group(2)
            mut = m.group(3)
            original_values["IAC"] = (mut, orig)

        # [CVM] CVM List parsed: ... from ([0-9A-F]+)
        m = re.search(r"\[CVM\] CVM List parsed:.* from ([0-9A-F]+)", line)
        if m:
            original_values["CVM"] = m.group(1)

        # TVR mutated 8000800000 -> 0000000000
        m = re.search(r"TVR mutated ([0-9A-F]+) -> ([0-9A-F]+)", line)
        if m:
            original_values["TVR"] = (m.group(2), m.group(1))

        # 3. Track RAPDUs and revert mutations
        m = re.search(r"RAPDU_TRACE seq=\d+ len=\d+ sw=[0-9A-F]+ src=\S+ dst=\S+ data=([0-9A-F]+)", line)
        if m:
            mutated_rapdu = m.group(1)
            clean_rapdu = mutated_rapdu
            
            # Revert IACs
            if "IAC" in original_values:
                mut, orig = original_values["IAC"]
                clean_rapdu = clean_rapdu.replace(mut, orig)
            
            # Revert CVM
            if "CVM" in original_values:
                # CVM is usually in tag 8E. The mutated value is usually 000000000000000000001F031E030000
                mut_cvm = "000000000000000000001F031E030000"
                orig_cvm = original_values["CVM"]
                clean_rapdu = clean_rapdu.replace(mut_cvm, orig_cvm)

            if current_capdu:
                sequence.append({
                    "capdu": current_capdu,
                    "rapdu": clean_rapdu
                })
                current_capdu = None
                original_values = {}

    return sequence

def main():
    if not OUT_DIR.exists():
        OUT_DIR.mkdir()

    for log_file in LOGS_DIR.glob("tx_*.log"):
        print(f"Processing {log_file.name}...")
        clean_seq = clean_log(log_file)
        if clean_seq:
            out_file = OUT_DIR / (log_file.stem + "_clean.json")
            with open(out_file, "w") as f:
                json.dump(clean_seq, f, indent=2)
            print(f"  Saved to {out_file.name}")

if __name__ == "__main__":
    main()
