# -*- coding: utf-8 -*-
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from emv import parse_read_record_cdol
from parser import RelayAnalyzer, parsed_path, transaction_logs


PPSE = "00A404000E325041592E5359532E444446303100"
PPSE_R = "6F009000"


class RelayAnalyzerSessionTests(unittest.TestCase):
    def analyze(self, lines: list[str]) -> RelayAnalyzer:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "relay.log"
            source.write_text("\n".join(lines), encoding="utf-8")
            analyzer = RelayAnalyzer(source)
            analyzer.analyze()
            return analyzer

    def test_current_epoch_format_splits_transactions(self) -> None:
        analyzer = self.analyze([
            f"10:00:00.000 [DEBUG] APDU EMU>REA CAPDU SELECT len=20: {PPSE}",
            f"10:00:00.100 [DEBUG] APDU REA>EMU RAPDU SELECT len=4: {PPSE_R} [SW=9000]",
            "10:00:01.000 [INFO] Session epoch opened: 4 [guard=IDLE]",
            f"10:00:02.000 [DEBUG] APDU EMU>REA CAPDU SELECT len=20: {PPSE}",
            f"10:00:02.100 [DEBUG] APDU REA>EMU RAPDU SELECT len=4: {PPSE_R} [SW=9000]",
        ])

        self.assertEqual(analyzer.epochs, [(4, "not-logged", "10:00:01.000")])
        self.assertEqual([exchange.transaction for exchange in analyzer.exchanges], [1, 2])
        self.assertIsNone(analyzer.exchanges[0].epoch)
        self.assertEqual(analyzer.exchanges[1].epoch, 4)

    def test_ppse_fallback_splits_capture_without_epoch_lines(self) -> None:
        analyzer = self.analyze([
            f"10:00:00.000 [DEBUG] APDU EMU>REA CAPDU SELECT len=20: {PPSE}",
            f"10:00:00.100 [DEBUG] APDU REA>EMU RAPDU SELECT len=4: {PPSE_R} [SW=9000]",
            f"10:00:01.000 [DEBUG] APDU EMU>REA CAPDU SELECT len=20: {PPSE}",
            f"10:00:01.100 [DEBUG] APDU REA>EMU RAPDU SELECT len=4: {PPSE_R} [SW=9000]",
        ])

        self.assertEqual([exchange.transaction for exchange in analyzer.exchanges], [1, 2])

    def test_legacy_epoch_token_is_preserved(self) -> None:
        analyzer = self.analyze([
            "10:00:00.000 [INFO] Session epoch opened: 7 token=ABC",
            f"10:00:01.000 [DEBUG] APDU EMU>REA CAPDU SELECT len=20: {PPSE}",
            f"10:00:01.100 [DEBUG] APDU REA>EMU RAPDU SELECT len=4: {PPSE_R} [SW=9000]",
        ])

        self.assertEqual(analyzer.epochs, [(7, "ABC", "10:00:00.000")])
        self.assertEqual(analyzer.exchanges[0].epoch, 7)


class DOLGuardTests(unittest.TestCase):
    def test_dol_values_are_not_reparsed_as_nested_tlv(self) -> None:
        dol_bytes = bytes.fromhex(
            "8C279F02069F03069F1A0295055F2A029A039C019F37049F35019F45029F4C089F34039F21039F7C14"
        )
        nodes, errors = __import__("parser").parse_ber_tlv(dol_bytes)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].tag, "8C")
        self.assertEqual(nodes[0].children, [])
        self.assertEqual(nodes[0].value.hex().upper(), dol_bytes[2:].hex().upper())
        self.assertFalse(errors)


class DOLParsingTests(unittest.TestCase):
    def test_parse_read_record_cdol_handles_dol_stream_without_tlv(self) -> None:
        cdol = bytes.fromhex(
            "9F02069F03069F1A0295055F2A029A039C019F37049F35019F45029F4C089F34039F1D089F15029F4E14"
        )
        parsed = parse_read_record_cdol(cdol)
        self.assertEqual(
            parsed,
            [
                (0x9F02, 6),
                (0x9F03, 6),
                (0x9F1A, 2),
                (0x95, 5),
                (0x5F2A, 2),
                (0x9A, 3),
                (0x9C, 1),
                (0x9F37, 4),
                (0x9F35, 1),
                (0x9F45, 2),
                (0x9F4C, 8),
                (0x9F34, 3),
                (0x9F1D, 8),
                (0x9F15, 2),
                (0x9F4E, 20),
            ],
        )


class BatchInputTests(unittest.TestCase):
    def test_adjacent_report_name_preserves_log_suffix(self) -> None:
        self.assertEqual(
            parsed_path(Path("logs/tx_20260721_0001.log")),
            Path("logs/tx_20260721_0001_parsed.log"),
        )

    def test_transaction_logs_exclude_generated_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tx_0002.log").touch()
            (root / "tx_0001.log").touch()
            (root / "tx_0001_parsed.log").touch()
            (root / "relay.log").touch()

            self.assertEqual(
                transaction_logs(root),
                [root / "tx_0001.log", root / "tx_0002.log"],
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
