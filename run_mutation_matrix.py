#!/usr/bin/env python3
"""
test_mutation_matrix.py
----------------------
A lightweight test harness that exercises the EMV relay stack by
applying a matrix of mutations and recording the outcome.

Author: Rel8HF Team
"""

import json
import time
import os
import sys
from datetime import datetime
from pathlib import Path

from tests.test_mutation_matrix import execute_python


# ----------------------------------------------------------------------
# Helper wrappers around the provided tooling
# ----------------------------------------------------------------------

def get_stack_status():
    return execute_python({"code": "import rel8hf; print(rel8hf.get_stack_status())"})  # placeholder


def inject_packet(apdu_hex, target="auto", frame_type="auto", epoch=None, force_guard_bypass=True):
    return execute_python({
        "code": f"""
from rel8hf import inject_packet
inject_packet(apdu_hex="{apdu_hex}",
              target="{target}",
              frame_type="{frame_type}",
              epoch={epoch},
              force_guard_bypass={force_guard_bypass})
"""
    })


def search_logs(query="", log_file="", max_lines=50):
    return execute_python({
        "code": f"""
from rel8hf import search_logs
print(search_logs(query="{query}", log_file="{log_file}", max_lines={max_lines}))
"""
    })


def get_recent_trace(max_entries=20):
    return execute_python({
        "code": f"""
from rel8hf import get_recent_trace
print(get_recent_trace(max_entries={max_entries}))
"""
    })


def evaluate_issuer_authorization(**kwargs):
    # Build the call string
    args = ", ".join(f"{k}={repr(v)}" for k, v in kwargs.items())
    return execute_python({
        "code": f"""
from rel8hf import evaluate_issuer_authorization
print(evaluate_issuer_authorization({args}))
"""
    })


def simulate_apdu_mutation(**kwargs):
    args = ", ".join(f"{k}={repr(v)}" for k, v in kwargs.items())
    return execute_python({
        "code": f"""
from rel8hf import simulate_apdu_mutation
print(simulate_apdu_mutation({args}))
"""
    })

# ----------------------------------------------------------------------
# Test harness configuration
# ----------------------------------------------------------------------
# Basic CAPDU templates
GPO_CAPDU = "00A4040007A0000000041010"          # SELECT AID
SELECT_CAPDU = "00A4040007A0000000041010"
GENERATE_AC_CAPDU = "80AE40000000"              # GENERATE AC (P1=0x40)
GENERATE_AC_TC_CAPDU = "80AE80000000"           # GENERATE AC (P1=0x80)

# Mutation matrix
MUTATIONS = [
    # 1. GPO – missing mandatory tag 9F02 (amount)
    {
        "name": "GPO_missing_9F02",
        "capdu": GPO_CAPDU,
        "mutation_type": "gpo",
        "clear_tvr": False,
        "set_cvm_list": None,
        "arqc_hex": None,
        "tc": False
    },
    # 2. GPO – extra unknown tag 9F99
    {
        "name": "GPO_extra_9F99",
        "capdu": GPO_CAPDU,
        "mutation_type": "gpo",
        "clear_tvr": False,
        "set_cvm_list": None,
        "arqc_hex": None,
        "tc": False
    },
    # 3. TVR – clear all bytes
    {
        "name": "TVR_clear_all",
        "capdu": GPO_CAPDU,
        "mutation_type": "gpo",
        "clear_tvr": True,
        "set_cvm_list": None,
        "arqc_hex": None,
        "tc": False
    },
    # 4. CVM – set to PIN only
    {
        "name": "CVM_pin_only",
        "capdu": GPO_CAPDU,
        "mutation_type": "gpo",
        "clear_tvr": False,
        "set_cvm_list": "pin",
        "arqc_hex": None,
        "tc": False
    },
    # 5. AC – forged CMAC (valid)
    {
        "name": "AC_forged_cmac_valid",
        "capdu": GENERATE_AC_CAPDU,
        "mutation_type": "arpc",
        "clear_tvr": False,
        "set_cvm_list": None,
        "arqc_hex": "0102030405060708",
        "tc": False
    },
    # 6. AC – forged CMAC (invalid)
    {
        "name": "AC_forged_cmac_invalid",
        "capdu": GENERATE_AC_CAPDU,
        "mutation_type": "arpc",
        "clear_tvr": False,
        "set_cvm_list": None,
        "arqc_hex": "FFFFFFFFFFFFFFFF",
        "tc": False
    },
    # 7. TC – forged TC with valid CMAC
    {
        "name": "TC_forged_cmac_valid",
        "capdu": GENERATE_AC_TC_CAPDU,
        "mutation_type": "tc",
        "clear_tvr": False,
        "set_cvm_list": None,
        "arqc_hex": "0102030405060708",
        "tc": True
    },
    # 8. Full path – GPO + TVR + CVM + AC + TC
    {
        "name": "Full_path",
        "capdu": GPO_CAPDU,
        "mutation_type": "gpo",
        "clear_tvr": True,
        "set_cvm_list": "pin",
        "arqc_hex": "0102030405060708",
        "tc": True
    }
]

# ----------------------------------------------------------------------
# Utility functions
# ----------------------------------------------------------------------

def log_audit(entry: dict):
    """Append a JSON line to mutation_audit.jsonl."""
    audit_file = Path("mutation_audit.jsonl")
    with audit_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def run_mutation(test: dict):
    """Execute a single mutation test."""
    name = test["name"]
    print(f"\n=== Running test: {name} ===")

    # 1. Inject the CAPDU (or SELECT) – we assume the reader is ready
    inject_packet(apdu_hex=test["capdu"])

    # 2. Wait a short moment for the relay to process
    time.sleep(0.5)

    # 3. If a mutation is requested, apply it
    if test["mutation_type"]:
        mutate_kwargs = {
            "capdu_hex": test["capdu"],
            "mutation_type": test["mutation_type"],
            "clear_tvr": test.get("clear_tvr", False),
            "set_cvm_list": test.get("set_cvm_list"),
            "cdcvm_verified": True
        }
        if test["arqc_hex"]:
            mutate_kwargs["arqc_hex"] = test["arqc_hex"]
        simulate_apdu_mutation(**mutate_kwargs)

    # 4. Capture the latest RAPDU
    trace = get_recent_trace(max_entries=1)
    rapdu_hex = trace.get("rapdu_hex", "N/A")

    # 5. Capture guard logs
    guard_logs = search_logs(query="[GUARD]", max_lines=20)

    # 6. Build audit record
    audit = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "test_name": name,
        "capdu": test["capdu"],
        "mutation": test["mutation_type"],
        "clear_tvr": test.get("clear_tvr"),
        "cvm_list": test.get("set_cvm_list"),
        "arqc_hex": test.get("arqc_hex"),
        "tc": test.get("tc"),
        "rapdu": rapdu_hex,
        "guard_logs": guard_logs,
        "status": "PASS" if "9000" in rapdu_hex else "FAIL"
    }
    log_audit(audit)

    print(f"Result: {audit['status']}")
    print(f"RAPDU: {rapdu_hex}")
    print(f"Guard logs:\n{guard_logs}")

# ----------------------------------------------------------------------
# Main entry point
# ----------------------------------------------------------------------

def main():
    # Ensure the relay is running
    status = get_stack_status()
    if not status.get("running"):
        print("Starting relay server...")
        execute_python({"code": "import rel8hf; rel8hf.start_relay()"})
        time.sleep(1)  # give it a moment

    # Clean audit file
    audit_path = Path("mutation_audit.jsonl")
    if audit_path.exists():
        audit_path.unlink()

    # Run all tests
    for test in MUTATIONS:
        run_mutation(test)

    print("\nAll tests completed. Audit written to mutation_audit.jsonl")

if __name__ == "__main__":
    main()
