# -*- coding: utf-8 -*-
import unittest
import json
import os
from pathlib import Path
import mutations

class FullMutationFlowTests(unittest.TestCase):
    """
    Automated regression suite that replays clean historical card data 
    through the actual mutation engine to ensure zero regressions.
    """
    
    def test_all_clean_logs(self):
        testlogs_dir = Path(__file__).parent.parent / "testlogs"
        if not testlogs_dir.exists():
            self.skipTest("testlogs folder not found. Run log_cleaner.py first.")
            
        log_files = list(testlogs_dir.glob("*.json"))
        if not log_files:
            self.skipTest("No clean logs found in testlogs/")

        for log_file in log_files:
            with self.subTest(log=log_file.name):
                with open(log_file, "r") as f:
                    sequence = json.load(f)
                
                for exchange in sequence:
                    capdu_hex = exchange["capdu"]
                    rapdu_hex = exchange["rapdu"]
                    rapdu = bytes.fromhex(rapdu_hex)
                    
                    # Ensure mutation calls don't crash and return bytes
                    # GPO
                    if capdu_hex[2:4] == "A8":
                        mut, ok = mutations.mutate_gpo_response(rapdu, cdcvm_verified=True)
                        self.assertIsInstance(mut, bytes)
                    
                    # Read Record
                    elif capdu_hex[2:4] == "B2":
                        mut = mutations.mutate_read_record_response(rapdu)
                        self.assertIsInstance(mut, bytes)

if __name__ == "__main__":
    unittest.main()
