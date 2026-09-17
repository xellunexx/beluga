# -*- coding: utf-8 -*-

import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from constants import SID_ACK, SID_CTRL, SID_REGISTER, build_frame, parse_frame
from rel8hf import RelayServer


class TestSourceCtrlStateGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        cls.port = s.getsockname()[1]
        s.close()

        cls.server = RelayServer(host="127.0.0.1", port=cls.port)
        cls._server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls._server_thread.start()
        deadline = time.time() + 2.0
        while not cls.server.running and time.time() < deadline:
            time.sleep(0.01)
        if not cls.server.running:
            raise RuntimeError("RelayServer failed to start for tests")

    @classmethod
    def tearDownClass(cls):
        cls.server._shutdown_requested = True
        cls.server.stop()
        if hasattr(cls, "_server_thread"):
            cls._server_thread.join(timeout=2.0)

    def tearDown(self):
        with self.server.lock:
            self.server.reader_addr = None
            self.server.emulator_addr = None
            self.server.reader_id = None
            self.server.emulator_id = None
            self.server.active_epoch = 0
            self.server.active_session_token = None
            self.server._session_requests.clear()
            self.server._session_token_seen.clear()
            if hasattr(self.server, "_session_token_global_seen"):
                self.server._session_token_global_seen.clear()
            if hasattr(self.server, "_last_card_event_kind"):
                self.server._last_card_event_kind = None
            if hasattr(self.server, "_last_card_event_ts"):
                self.server._last_card_event_ts = 0.0
            self.server.state.reset()

    def test_session_begin_requires_both_peers(self):
        sock_r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_r.settimeout(2.0)
        sock_r.bind(("127.0.0.1", 0))
        sock_r.sendto(build_frame(SID_REGISTER, b"READER V1 id=readerOnly", 0, 0), ("127.0.0.1", self.port))
        self.assertEqual(parse_frame(sock_r.recvfrom(4096)[0])[0], SID_ACK)

        sock_r.sendto(build_frame(SID_CTRL, b"SESSION_BEGIN only-reader", 0, 0), ("127.0.0.1", self.port))
        sid_err, _, _, payload_err = parse_frame(sock_r.recvfrom(4096)[0])
        self.assertEqual(sid_err, SID_CTRL)
        self.assertIn(b"ERR PEERS_NOT_READY", payload_err)

        sock_e = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_e.settimeout(2.0)
        sock_e.bind(("127.0.0.1", 0))
        sock_e.sendto(build_frame(SID_REGISTER, b"EMULATOR V1 id=emuReady", 0, 0), ("127.0.0.1", self.port))
        self.assertEqual(parse_frame(sock_e.recvfrom(4096)[0])[0], SID_ACK)

        sock_r.sendto(build_frame(SID_CTRL, b"SESSION_BEGIN paired", 0, 0), ("127.0.0.1", self.port))
        sid_ok, _, _, payload_ok = parse_frame(sock_r.recvfrom(4096)[0])
        self.assertEqual(sid_ok, SID_CTRL)
        self.assertIn(b"SESSION_ACK", payload_ok)

        sock_e.recvfrom(4096)
        sock_r.close()
        sock_e.close()

    def test_card_events_are_reader_only(self):
        sock_r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_r.settimeout(2.0)
        sock_r.bind(("127.0.0.1", 0))
        sock_r.sendto(build_frame(SID_REGISTER, b"READER V1 id=readerA", 0, 0), ("127.0.0.1", self.port))
        self.assertEqual(parse_frame(sock_r.recvfrom(4096)[0])[0], SID_ACK)

        sock_e = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_e.settimeout(2.0)
        sock_e.bind(("127.0.0.1", 0))
        sock_e.sendto(build_frame(SID_REGISTER, b"EMULATOR V1 id=emuA", 0, 0), ("127.0.0.1", self.port))
        self.assertEqual(parse_frame(sock_e.recvfrom(4096)[0])[0], SID_ACK)

        sock_e.sendto(build_frame(SID_CTRL, b"CARD_PRESENT", 0, 0), ("127.0.0.1", self.port))
        sid, _, _, payload = parse_frame(sock_e.recvfrom(4096)[0])
        self.assertEqual(sid, SID_CTRL)
        self.assertIn(b"ERR CARD_EVENT_READER_ONLY", payload)

        sock_r.close()
        sock_e.close()

    def test_duplicate_card_events_are_debounced(self):
        sock_r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_r.settimeout(2.0)
        sock_r.bind(("127.0.0.1", 0))
        sock_r.sendto(build_frame(SID_REGISTER, b"READER V1 id=readerD", 0, 0), ("127.0.0.1", self.port))
        self.assertEqual(parse_frame(sock_r.recvfrom(4096)[0])[0], SID_ACK)

        sock_e = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_e.settimeout(2.0)
        sock_e.bind(("127.0.0.1", 0))
        sock_e.sendto(build_frame(SID_REGISTER, b"EMULATOR V1 id=emuD", 0, 0), ("127.0.0.1", self.port))
        self.assertEqual(parse_frame(sock_e.recvfrom(4096)[0])[0], SID_ACK)

        sock_r.sendto(build_frame(SID_CTRL, b"CARD_PRESENT", 0, 0), ("127.0.0.1", self.port))
        self.assertIn(b"OK CARD_PRESENT", parse_frame(sock_r.recvfrom(4096)[0])[3])
        self.assertIn(b"CARD_PRESENT", parse_frame(sock_e.recvfrom(4096)[0])[3])

        before = int(self.server.metrics.get("card_events_debounced_total", 0))
        sock_r.sendto(build_frame(SID_CTRL, b"CARD_PRESENT", 0, 0), ("127.0.0.1", self.port))
        self.assertIn(b"OK CARD_PRESENT", parse_frame(sock_r.recvfrom(4096)[0])[3])
        after = int(self.server.metrics.get("card_events_debounced_total", 0))
        self.assertGreaterEqual(after, before + 1)

        sock_r.close()
        sock_e.close()

    def test_unknown_unframed_packet_is_quarantined(self):
        outsider = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        outsider.settimeout(0.25)
        outsider.bind(("127.0.0.1", 0))

        before_malformed = int(self.server.metrics.get("malformed_frames_total", 0))
        before_quarantine = int(self.server.metrics.get("unframed_quarantine_total", 0))

        outsider.sendto(b"THIS_IS_NOT_A_FRAME", ("127.0.0.1", self.port))
        with self.assertRaises(socket.timeout):
            outsider.recvfrom(4096)
        time.sleep(0.05)

        after_malformed = int(self.server.metrics.get("malformed_frames_total", 0))
        after_quarantine = int(self.server.metrics.get("unframed_quarantine_total", 0))
        self.assertGreaterEqual(after_malformed, before_malformed + 1)
        self.assertGreaterEqual(after_quarantine, before_quarantine + 1)

        outsider.close()


if __name__ == "__main__":
    unittest.main()
