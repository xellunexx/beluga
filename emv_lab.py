# -*- coding: utf-8 -*-
"""
REL8HF EMV Lab -- state-aware reader/tag endpoint simulators.

Purpose
-------
Provide two deterministic UDP peers that attach to an already-running rel8hf
relay and exercise the real relay/protocol/EMV/mutation/Guard path.

Important relay-role mapping in the current REL8HF implementation:
    logical READER/PCD simulator -> registers as relay role EMULATOR
    logical TAG/PICC simulator   -> registers as relay role READER

This looks inverted, but it matches the production handler contracts:
    EMULATOR-origin CAPDU -> relay -> READER-origin endpoint
    READER-origin RAPDU  -> relay -> EMULATOR-origin endpoint

Modes
-----
closed_loop : start both simulated endpoints and run a transaction automatically.
reader      : start only the logical reader/PCD simulator.
tag         : start only the logical tag/PICC simulator (passive, response-driven).

The module is laboratory-only.  It does not open bank/issuer connections and
does not claim cryptographic or formal EMV compliance.  The default GAC values
are deliberately deterministic synthetic values.  The relay itself remains
the system under test.

Wire contract:
    Every UDP packet uses constants.py's 11-byte header:
        Length(4) + SID(1) + Epoch(4) + Seq(2) + Payload(N)
    APDU payloads are sent raw.  Seq is the request/response correlation ID.
    The optional EXCHANGE_MAGIC wrapper is intentionally NOT used by this lab.
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

import constants
import parser as emv_parser
import protocol
import tlv


LOG = logging.getLogger("REL8HF.EmvLab")


def _hex(data: bytes) -> str:
    return bytes(data).hex().upper()


def _sw(data: bytes) -> bytes:
    return data[-2:] if len(data) >= 2 else b""


def _status_name(sw: bytes) -> str:
    if sw == b"\x90\x00":
        return "9000"
    if not sw:
        return "NONE"
    return _hex(sw)


@dataclass
class LabEvent:
    ts: float
    actor: str
    direction: str
    kind: str
    exchange_id: Optional[int]
    apdu_hex: str = ""
    status: str = ""
    state_before: str = ""
    state_after: str = ""
    detail: str = ""
    parsed: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LabCardProfile:
    """Replay-oriented PICC/card profile from a known-good Mastercard run.

    PPSE, AID SELECT, GPO, and first-GAC RAPDUs are captured wire values from
    the supplied transaction log. READ RECORD preserves the observed mutated
    card data except PAN/Track-2, which are replaced with test values.
    No claim of issuer/card cryptographic validity is made.
    """

    name: str = "captured-working-mastercard-v1"
    aid: bytes = bytes.fromhex("A0000000041010")
    ppse_name: bytes = bytes.fromhex("325041592E5359532E4444463031")
    pan: bytes = bytes.fromhex("5555555555555555")
    expiry: bytes = bytes.fromhex("251101")
    psn: bytes = b"\x01"
    country: bytes = bytes.fromhex("0586")
    currency: bytes = bytes.fromhex("0840")
    aid_priority: bytes = b"\x01"

    # Canonical 16-byte laboratory No-CVM value already used by the project.
    cvm_list: bytes = bytes.fromhex("000000000000000000001F031E030000")

    # Exact first GAC CAPDU from the 05:40:22 captured transaction.
    gac1_capdu: bytes = bytes.fromhex(
        "80AE80004200000000100000000000000009780000000000097826081700B152"
        "5BA122000000000000000000001F0302084018000000000000000000000000000000000000000000"
    )

    ext_auth_capdu: bytes = bytes.fromhex(
        "008200000A11223344556677883035"
    )

    # Exact second-GAC CAPDU from the 05:40:22 capture after ARQC.
    gac2_capdu: bytes = bytes.fromhex(
        "80AE40002B000000000000000000003030000000000062C98EBC"
        "00000000000000002488E000100000000000001F030000"
    )

    def ppse_response(self) -> bytes:
        # Structurally valid 84-byte PPSE reconstructed from the
        # 05:40:22 captured application entries.
        return bytes.fromhex(
            "6F50"
            "840E325041592E5359532E4444463031"
            "A53E"
            "BF0C3B"
            "611E"
            "4F07A0000000041010"
            "50104465626974204D617374657263617264"
            "870101"
            "6119"
            "4F07A0000000031010"
            "500B5669736120437265646974"
            "870101"
            "9000"
        )
    def aid_response(self) -> bytes:
        # Exact AID SELECT RAPDU from the 05:40:22 captured transaction.
        return bytes.fromhex(
            "6F658407A0000000041010A55A50104465626974204D617374657263617264870101"
            "9F38039F5C085F2D02656E9F1101019F12104465626974204D617374657263617264"
            "BF0C209F4D020B0A9F6E07082600003030009F5D030100069F0A0800010501000000009000"
        )

    def gpo_response(self) -> bytes:
        # Exact GPO RAPDU from the 05:40:22 captured transaction.
        return bytes.fromhex(
            "770E82020980940810010101200103009000"
        )

    def record_response(self) -> bytes:
        # Exact SFI=2 record=1 RAPDU from the 05:40:22 capture.
        return bytes.fromhex(
            "7081BE9F420208265F25032512015F24033012315A085355222091779157"
            "5F3401009F0702FFC09F080200028C279F02069F03069F1A0295055F2A029A"
            "039C019F37049F35019F45029F4C089F34039F21039F7C148D12910A8A029505"
            "9F37049F4C089F02069F03068E10000000000000000000001F031E030000"
            "9F51039F37049F5B0CDF6008DF6108DF6201DF63A09F0D050000000000"
            "9F0E0500000000009F0F0500000000005F28020826570E5355222091779157"
            "D301222106109F4A01829000"
        )

    def record_4_1_response(self) -> bytes:
        return bytes.fromhex(
            "7081C5"
            "9F4681B02945DCF8866BFE7D91990DE7D55370D79EFCA75F58B183E07F0053183955853AA0513A5E12320C01404D17ADF58D2ED6F80C155F0C887B4AA17F15AC928DAAA688E96B0C5DA2760FDE6A3FE3D4FA80677DD29FE637B13E8C4FB7DEC287E6DF27DA04545A964DAA49F4624B0EDBDA68897A6BB5886D6D7A671584772B54054062B34B6F8E8DB8EA6658E092CAA0B993323FB19A5D14DED37CE10503A2C782AFE989D76B0023DD62BDCEC61CE33825C5C69F4701039F480AEE122B67AA85775FA6CD"
            "9000"
        )

    def record_4_2_response(self) -> bytes:
        return bytes.fromhex(
            "70078F01069F3201039000"
        )

    def record_4_3_response(self) -> bytes:
        # Exact 256-byte READ RECORD response from the 05:40:22 capture.
        return bytes.fromhex(
            "7081FB"
            "9081F888A05F6427BE068DF350CC9DBDBD91EBBCF0D1BE8B6464FFA67818D2B82154CF43BFDB82C1500E8936EED9C6C3BEC13B2E07C848B14C7B9120C2ED99B8904DCDEF89B3AC3D0C6FA1E4BA044FCE39F5DEC94E35A26038B1DD44AF5737A2CCC811D02B1ADFD8EE2D75F6E032EFAE3042E742406409E64F804247E7BEC8D3117DBFBAA178EE72B23AF25E72D99BEC2AA78C51F23FEB343E34C854DA2FD19521E6451EC23D1E19D4D4C2D5D91ADD540A1B3DDAB0A28E1EF190994A01A8C08DD151DDF090AC627B79CAEEC373C99507CED18C211A1DB48F2067C1FD3B37DBE4DAB82E44D036C4D4FCE3853C795493C65D1452F0C0E4DEA6C45576"
            "9000"
        )

    def gac_arqc_response(self, atc: bytes = bytes.fromhex("000D")) -> bytes:
        # Exact first-GAC ARQC RAPDU from the 05:40:22 capture.
        return bytes.fromhex(
            "77339F2701809F3602000D"
            "9F26084FFA29CF6FD34076"
            "9F101C3014A04303A40004AE74E26D0A8185D4B460E545E9F534369037000E"
            "9000"
        )

    def gac_tc_response(self, atc: bytes = bytes.fromhex("0012")) -> bytes:
        inner = (
            tlv.build_tlv(0x9F27, bytes([constants.CID_TC]))
            + tlv.build_tlv(0x9F36, bytes(atc))
            + tlv.build_tlv(0x9F26, bytes.fromhex("1122334455667788"))
            + tlv.build_tlv(0x9F10, bytes.fromhex("06010A030000"))
        )
        return tlv.build_tlv(0x77, inner) + constants.SW_9000

    def gac_aac_response(self, atc: bytes) -> bytes:
        inner = (
            tlv.build_tlv(0x9F27, bytes([getattr(constants, "CID_AAC", 0x00)]))
            + tlv.build_tlv(0x9F36, bytes(atc))
            + tlv.build_tlv(0x9F26, bytes.fromhex("0000000000000000"))
            + tlv.build_tlv(0x9F10, bytes.fromhex("06010A030000"))
        )
        return tlv.build_tlv(0x77, inner) + constants.SW_9000

    def ext_auth_response(self) -> bytes:
        return constants.SW_9000


class _Peer:
    def __init__(
        self,
        *,
        logical_role: str,
        relay_role: str,
        relay_host: str,
        relay_port: int,
        client_id: str,
        epoch: int = 0,
        event_sink: Optional[Callable[[LabEvent], None]] = None,
    ) -> None:
        self.logical_role = logical_role
        self.relay_role = relay_role
        self.relay_addr = (relay_host, int(relay_port))
        self.client_id = client_id
        self.epoch = int(epoch)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.settimeout(0.25)
        self.local_addr = self.sock.getsockname()
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.exchange_id = 0
        self.received_ctrl: Deque[str] = deque(maxlen=50)
        self.events: Deque[LabEvent] = deque(maxlen=500)
        self.event_sink = event_sink
        self._started = False
        self.registered = threading.Event()
        self.registration_error: Optional[str] = None

    def _emit(
        self,
        kind: str,
        direction: str,
        *,
        exchange_id: Optional[int] = None,
        apdu: bytes = b"",
        status: bytes = b"",
        state_before: str = "",
        state_after: str = "",
        detail: str = "",
        parsed: Optional[Dict[str, Any]] = None,
    ) -> None:
        event = LabEvent(
            ts=time.time(),
            actor=self.logical_role,
            direction=direction,
            kind=kind,
            exchange_id=exchange_id,
            apdu_hex=_hex(apdu),
            status=_status_name(status),
            state_before=state_before,
            state_after=state_after,
            detail=detail,
            parsed=parsed or {},
        )
        self.events.append(event)
        if self.event_sink:
            self.event_sink(event)

    def _build(self, sid: int, payload: bytes, exchange_id: int = 0) -> bytes:
        return constants.build_frame(
            sid,
            payload,
            seq=exchange_id & 0xFFFF,
            epoch=self.epoch,
        )

    def register(self) -> None:
        payload = f"{self.relay_role} V{constants.PROTOCOL_VERSION} ID={self.client_id}".encode()
        self.sock.sendto(self._build(constants.SID_REGISTER, payload, 0), self.relay_addr)
        self._emit(
            "REGISTER",
            "TX",
            detail=f"{self.relay_role} V{constants.PROTOCOL_VERSION} ID={self.client_id}",
        )

    def send_ctrl(self, text: str) -> None:
        payload = text.encode()
        self.sock.sendto(self._build(constants.SID_CTRL, payload, 0), self.relay_addr)
        self._emit("CTRL", "TX", detail=text)

    def send_apdu(self, apdu: bytes, *, exchange_id: Optional[int] = None) -> int:
        """Send one APDU using the production wire contract.

        Protocol contract:
          [4] Length
          [1] SID
          [4] Epoch
          [2] Seq / exchange ID
          [N] raw APDU bytes

        IMPORTANT:
          Do NOT add the optional RLY1 exchange wrapper here. The Android
          reader contract uses the outer 2-byte Seq as the sole request/response
          correlation value. REL8HF forwards that sequence and expects the
          RAPDU to return with the same Seq.
        """
        if exchange_id is None:
            self.exchange_id += 1
            exchange_id = self.exchange_id
        else:
            self.exchange_id = max(self.exchange_id, exchange_id)

        sid = (
            constants.SID_CAPDU
            if self.relay_role == "EMULATOR"
            else constants.SID_RAPDU
        )
        raw_apdu = bytes(apdu)
        frame = self._build(sid, raw_apdu, exchange_id)
        self.sock.sendto(frame, self.relay_addr)
        self._emit(
            "APDU",
            "TX",
            exchange_id=exchange_id,
            apdu=raw_apdu,
            detail=(
                f"sid=0x{sid:02X} relay_role={self.relay_role} "
                f"wire=11-byte-header+raw-apdu"
            ),
        )
        return exchange_id

    def start(self) -> None:
        if self._started:
            return
        self.running = True
        self._started = True
        self.thread = threading.Thread(
            target=self._recv_loop,
            name=f"REL8HF-{self.logical_role}",
            daemon=True,
        )
        self.thread.start()
        self.register()

    def stop(self) -> None:
        # Stop locally. Do not inject an unsolicited APDU into the relay.
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass

    def _recv_loop(self) -> None:
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            parsed = constants.parse_frame(data)
            if parsed is None:
                self._emit(
                    "FRAME",
                    "RX",
                    detail=f"malformed frame from {addr[0]}:{addr[1]}",
                )
                continue

            sid, epoch, seq, payload = parsed
            self._handle_frame(sid, epoch, seq, payload)

    def _handle_frame(self, sid: int, epoch: int, seq: int, payload: bytes) -> None:
        if sid == constants.SID_CTRL:
            text = payload.decode("utf-8", errors="replace")
            self.received_ctrl.append(text)
            command = text.strip().upper()

            if command.startswith("ERR "):
                self.registration_error = command
            self._emit(
                "CTRL",
                "RX",
                detail=text,
                parsed={"epoch": epoch, "seq": seq, "command": text},
            )
            self.on_ctrl(epoch=epoch, seq=seq, text=text)
            return

        if sid == constants.SID_ACK:
            text = payload.decode("utf-8", errors="replace")
            self._emit(
                "ACK",
                "RX",
                detail=text,
                parsed={"epoch": epoch, "seq": seq},
            )
            if text.strip().upper() == "REGISTER":
                self.registered.set()
            return

        if sid not in (constants.SID_CAPDU, constants.SID_RAPDU):
            self._emit("FRAME", "RX", detail=f"sid=0x{sid:02X} epoch={epoch} seq={seq}")
            return

        try:
            inner_exchange_id, apdu = constants.parse_exchange_payload(payload)
            # Production Android contract: raw APDU payload + outer Seq.
            # Backward compatibility: accept an explicitly wrapped payload too,
            # but the outer sequence remains the authoritative fallback.
            exchange_id = (
                inner_exchange_id
                if inner_exchange_id is not None
                else seq
            )
        except Exception as exc:
            self._emit("APDU", "RX", detail=f"exchange header parse failed: {exc}")
            return

        self.on_apdu(
            sid=sid,
            epoch=epoch,
            seq=seq,
            exchange_id=exchange_id,
            apdu=apdu,
        )

    def on_ctrl(self, *, epoch: int, seq: int, text: str) -> None:
        """Control-plane hook. Default is observe-only."""
        return

    def on_apdu(
        self,
        *,
        sid: int,
        epoch: int,
        seq: int,
        exchange_id: Optional[int],
        apdu: bytes,
    ) -> None:
        raise NotImplementedError

    def status(self) -> Dict[str, Any]:
        return {
            "logical_role": self.logical_role,
            "relay_role": self.relay_role,
            "client_id": self.client_id,
            "local_addr": list(self.local_addr),
            "relay_addr": list(self.relay_addr),
            "running": self.running,
            "exchange_id": self.exchange_id,
            "received_ctrl_tail": list(self.received_ctrl)[-10:],
            "events": len(self.events),
        }


class LabTag(_Peer):
    """Logical PICC/tag.  Registers as relay-side READER.

    DATA-ONLY CARD MODEL:
        The tag does not run an EMV state machine and never generates a new
        APDU.  It only looks up the CAPDU actually received from the relay and
        returns the stored RAPDU fixture associated with that request.

    This is intentionally useful for real-POS diagnosis: the terminal decides
    what command comes next; this endpoint only supplies card data for commands
    that have a fixture.
    """

    def __init__(self, profile: LabCardProfile, **kwargs: Any) -> None:
        super().__init__(
            logical_role="TAG",
            relay_role="READER",
            **kwargs,
        )
        self.profile = profile
        self.state = "DATA_ONLY"
        self.last_ins: Optional[int] = None
        self.ready = False

        # Exact request -> stored response fixtures.
        # Keep this table deliberately dumb: no phase transitions, no inferred
        # next command, no synthetic response generation based on state.
        self.response_fixtures: Dict[bytes, Tuple[bytes, str]] = {
            bytes.fromhex("00A404000E325041592E5359532E444446303100"):
                (profile.ppse_response(), "SELECT PPSE"),

            bytes.fromhex("00A4040007A000000004101000"):
                (profile.aid_response(), "SELECT AID"),

            bytes.fromhex("80A800000A8308000000000000000000"):
                (profile.gpo_response(), "GET PROCESSING OPTIONS"),

            bytes.fromhex("00B2011400"):
                (profile.record_response(), "READ RECORD SFI=2 record=1"),

            bytes.fromhex("00B2012400"):
                (profile.record_4_1_response(), "READ RECORD SFI=4 record=1"),

            bytes.fromhex("00B2022400"):
                (profile.record_4_2_response(), "READ RECORD SFI=4 record=2"),

            bytes.fromhex("00B2032400"):
                (profile.record_4_3_response(), "READ RECORD SFI=4 record=3"),

            profile.gac1_capdu:
                (profile.gac_arqc_response(), "GENERATE AC (captured ARQC fixture)"),

            profile.ext_auth_capdu:
                (profile.ext_auth_response(), "EXTERNAL AUTHENTICATE (LAB)"),

            profile.gac2_capdu:
                (
                    profile.gac_tc_response(atc=bytes.fromhex("000D")),
                    "GENERATE AC #2 (LAB)",
                ),
        }

        # Optional per-request statistics. This is observational only.
        self.request_counts: Dict[str, int] = {}
        self.missing_fixtures: List[str] = []

    def start(self) -> None:
        """Register, then advertise CARD_PRESENT once; no EMV traffic is emitted."""
        super().start()
        threading.Thread(
            target=self._announce_present,
            name="REL8HF-Lab-CardPresent",
            daemon=True,
        ).start()

    def _announce_present(self) -> None:
        deadline = time.time() + 5.0
        while self.running and time.time() < deadline:
            if self.registered.is_set():
                self.send_ctrl("CARD_PRESENT")
                return
            if self.registration_error:
                self._emit(
                    "REGISTER_REJECTED",
                    "LOCAL",
                    detail=self.registration_error,
                )
                return
            time.sleep(0.05)

        if self.running:
            self._emit(
                "REGISTER_TIMEOUT",
                "LOCAL",
                detail="REGISTER ACK not received; CARD_PRESENT not sent",
            )

    def on_ctrl(self, *, epoch: int, seq: int, text: str) -> None:
        """Track only transport/session control; never generate EMV APDUs."""
        command = text.strip().upper()

        if command.startswith("SESSION_BEGIN"):
            parts = command.split()
            if len(parts) >= 2:
                try:
                    self.epoch = int(parts[1])
                except ValueError:
                    pass
            self.ready = True
            self._emit(
                "STATE",
                "LOCAL",
                state_before=self.state,
                state_after=self.state,
                detail=(
                    f"relay session announced; epoch={self.epoch}; "
                    "data-only mode waiting for EMULATOR CAPDU"
                ),
                parsed={"epoch": self.epoch, "session_command": command},
            )
            return

        if command.startswith("ERR ROLE_OCCUPIED"):
            self.ready = False
            self.registration_error = command
            self._emit(
                "REGISTER_REJECTED",
                "RX",
                detail=command,
                parsed={"control": command},
            )
            return

        if command.startswith("CARD_REMOVED") or command.startswith("PEER_DISCONNECTED"):
            self.ready = False
            self._emit(
                "STATE",
                "LOCAL",
                state_before=self.state,
                state_after=self.state,
                detail=f"relay control: {command}; data fixtures retained",
                parsed={"epoch": epoch, "control": command},
            )
            return

        # SESSION_ACK/STATUS and unrelated controls are observation-only.

    def _fixture_for_apdu(self, apdu: bytes) -> Optional[Tuple[bytes, str]]:
        """Return only an explicitly stored response fixture."""
        fixture = self.response_fixtures.get(bytes(apdu))
        if fixture is not None:
            return fixture

        # The real POS may vary CDOL1 values in GAC. For diagnosis, recognize
        # the command class but still return the stored lab ARQC response rather
        # than inventing a cryptogram from the incoming data.
        if len(apdu) >= 2 and apdu[1] == constants.INS_GENERATE_AC:
            p1 = apdu[2] if len(apdu) >= 3 else 0
            if (p1 & 0xC0) == constants.CID_ARQC:
                return (self.profile.gac_arqc_response(),
                        "GENERATE AC (stored ARQC response; request data not re-derived)")
            if (p1 & 0xC0) == constants.CID_TC:
                return (self.profile.gac_tc_response(atc=bytes.fromhex("006A")),
                        "GENERATE AC #2 (stored TC response)")

        return None

    def on_apdu(
        self,
        *,
        sid: int,
        epoch: int,
        seq: int,
        exchange_id: Optional[int],
        apdu: bytes,
    ) -> None:
        """Answer exactly the CAPDU received; never initiate the next command."""
        before = self.state
        raw_apdu = bytes(apdu)
        sw = b""

        try:
            cmd = protocol.CommandAPDU.from_bytes(raw_apdu)
            if cmd is None:
                raise ValueError("CommandAPDU parser returned None")
            self.last_ins = cmd.ins

            key = raw_apdu.hex().upper()
            self.request_counts[key] = self.request_counts.get(key, 0) + 1
            fixture = self._fixture_for_apdu(raw_apdu)

            parsed: Dict[str, Any] = {
                "ins": cmd.ins,
                "p1": cmd.p1,
                "p2": cmd.p2,
                "command": constants.INS_MAP.get(cmd.ins, f"0x{cmd.ins:02X}"),
                "lc": getattr(cmd, "lc", None),
                "data_len": len(getattr(cmd, "data", b"")),
                "lab_epoch": self.epoch,
                "relay_epoch": epoch,
                "fixture_lookup": "HIT" if fixture else "MISS",
            }

            if fixture is None:
                # Do not lie about unavailable card data. Return a deterministic
                # error so the POS can be observed reacting to a missing fixture.
                response = bytes.fromhex("6A83")
                reason = (
                    f"NO_FIXTURE for CAPDU={key}; returning 6A83 so missing card data "
                    "is explicit. Add the exact real-card RAPDU to response_fixtures."
                )
                self.missing_fixtures.append(key)
            else:
                response, reason = fixture

            sw = _sw(response)
            try:
                body = response[:-2] if len(response) >= 2 else response
                if body:
                    nodes, errors = emv_parser.parse_ber_tlv(body)
                    parsed["response_tlv_tags"] = [n.tag for n in nodes]
                    if errors:
                        parsed["response_tlv_errors"] = errors
            except Exception as exc:
                parsed["response_tlv_parse_note"] = str(exc)

            self._emit(
                "APDU",
                "RX",
                exchange_id=exchange_id,
                apdu=raw_apdu,
                status=sw,
                state_before=before,
                state_after=self.state,
                detail=reason,
                parsed=parsed,
            )

            # The only transmission is the answer to this exact request.
            self.send_apdu(response, exchange_id=exchange_id)

        except Exception as exc:
            error_response = bytes.fromhex("6F00")
            self._emit(
                "ERROR",
                "RX",
                exchange_id=exchange_id,
                apdu=raw_apdu,
                status=_sw(error_response),
                state_before=before,
                state_after=self.state,
                detail=f"data-only tag processing failed: {type(exc).__name__}: {exc}",
            )
            if exchange_id is not None:
                self.send_apdu(error_response, exchange_id=exchange_id)

    def status(self) -> Dict[str, Any]:
        out = super().status()
        out.update({
            "state": self.state,
            "ready": self.ready,
            "registered": self.registered.is_set(),
            "registration_error": self.registration_error,
            "passive": True,
            "data_only": True,
            "wire_contract": "11-byte-header + raw-payload; Seq correlates APDU",
            "last_ins": (
                constants.INS_MAP.get(self.last_ins, f"0x{self.last_ins:02X}")
                if self.last_ins is not None else None
            ),
            "last_exchange_id": self._last_exchange_id if hasattr(self, "_last_exchange_id") else None,
            "last_capdu_hex": self._last_capdu.hex().upper() if hasattr(self, "_last_capdu") and self._last_capdu else "",
            "last_rapdu_hex": self._last_rapdu.hex().upper() if hasattr(self, "_last_rapdu") and self._last_rapdu else "",
            "fixture_count": len(self.response_fixtures),
            "missing_fixture_count": len(self.missing_fixtures),
            "profile": self.profile.name,
            "next_action": "WAIT_FOR_EMULATOR_CAPDU" if self.running else "STOPPED",
        })
        return out


class LabReader(_Peer):
    """Logical PCD/reader.  Registers as relay-side EMULATOR."""

    def __init__(self, profile: LabCardProfile, **kwargs: Any) -> None:
        super().__init__(
            logical_role="READER",
            relay_role="EMULATOR",
            **kwargs,
        )
        self.profile = profile
        self.state = "IDLE"
        self.last_response: bytes = b""
        self.last_capdu: bytes = b""
        self.expected = "SELECT_PPSE"
        self.running_transaction = False
        self._read_queue: List[Tuple[int, int]] = []

    def start(self) -> None:
        super().start()
        threading.Thread(target=self._kickoff, daemon=True).start()

    def _kickoff(self) -> None:
        time.sleep(0.35)
        if not self.running:
            return
        self.running_transaction = True
        self._send_select_ppse()

    def _send_select_ppse(self) -> None:
        apdu = bytes.fromhex("00A404000E") + self.profile.ppse_name + b"\x00"
        self.last_capdu = apdu
        self.expected = "PPSE_RAPDU"
        self.send_apdu(apdu)

    def _send_select_aid(self) -> None:
        apdu = bytes.fromhex("00A4040007") + self.profile.aid
        self.last_capdu = apdu
        self.expected = "AID_RAPDU"
        self.send_apdu(apdu)

    def _send_gpo(self) -> None:
        apdu = bytes.fromhex("80A800000A8308000000000000000000")
        self.last_capdu = apdu
        self.expected = "GPO_RAPDU"
        self.send_apdu(apdu)

    def _send_read_record(self, p2: int, record_no: int = 1) -> None:
        apdu = bytes((0x00, constants.INS_READ_RECORD, record_no & 0xFF, p2 & 0xFF, 0x00))
        self.last_capdu = apdu
        self.expected = "READ_RECORD_RAPDU"
        self.send_apdu(apdu)

    def _send_gac1(self) -> None:
        self.last_capdu = self.profile.gac1_capdu
        self.expected = "GAC1_RAPDU"
        self.send_apdu(self.profile.gac1_capdu)

    def _send_ext_auth(self) -> None:
        self.last_capdu = self.profile.ext_auth_capdu
        self.expected = "EXT_AUTH_RAPDU"
        self.send_apdu(self.profile.ext_auth_capdu)

    def _send_gac2(self) -> None:
        self.last_capdu = self.profile.gac2_capdu
        self.expected = "GAC2_RAPDU"
        self.send_apdu(self.profile.gac2_capdu)

    def on_apdu(
        self,
        *,
        sid: int,
        epoch: int,
        seq: int,
        exchange_id: Optional[int],
        apdu: bytes,
    ) -> None:
        before = self.state
        self.last_response = bytes(apdu)
        sw = _sw(apdu)

        parsed: Dict[str, Any] = {"expected": self.expected}

        try:
            resp = protocol.ResponseAPDU.from_bytes(apdu)
            body = resp.data
            parsed["status_word"] = _status_name(resp.sw)
            if body:
                try:
                    nodes, errs = emv_parser.parse_ber_tlv(body)
                    parsed["tlv_tags"] = [n.tag for n in nodes]
                    if errs:
                        parsed["tlv_errors"] = errs
                except Exception as exc:
                    parsed["tlv_error"] = str(exc)
        except Exception as exc:
            parsed["protocol_error"] = str(exc)
            body = apdu[:-2] if len(apdu) >= 2 else apdu

        if sw != constants.SW_9000:
            self.state = "ERROR"
            self.expected = "STOP"
            detail = f"kernel/reader simulator received SW={_status_name(sw)}; stopping"
            self._emit(
                "APDU",
                "RX",
                exchange_id=exchange_id,
                apdu=apdu,
                status=sw,
                state_before=before,
                state_after=self.state,
                detail=detail,
                parsed=parsed,
            )
            return

        # A real kernel-like state progression driven by what was actually
        # received, not by hard-coded success output.
        if self.expected == "PPSE_RAPDU":
            self.state = "PPSE_SELECTED"
            self.expected = "SEND_AID"
            self._emit("APDU", "RX", exchange_id=exchange_id, apdu=apdu,
                       status=sw, state_before=before, state_after=self.state,
                       detail="PPSE response accepted; proceeding to AID SELECT", parsed=parsed)
            self._send_select_aid()
            return

        if self.expected == "AID_RAPDU":
            self.state = "AID_SELECTED"
            self.expected = "SEND_GPO"
            self._emit("APDU", "RX", exchange_id=exchange_id, apdu=apdu,
                       status=sw, state_before=before, state_after=self.state,
                       detail="AID response accepted; proceeding to GPO", parsed=parsed)
            self._send_gpo()
            return

        if self.expected == "GPO_RAPDU":
            self.state = "GPO_RESPONDED"
            afl = tlv.find_tlv(body, 0x94) if body else None
            self._emit(
                "APDU",
                "RX",
                exchange_id=exchange_id,
                apdu=apdu,
                status=sw,
                state_before=before,
                state_after=self.state,
                detail=f"GPO accepted; AFL={_hex(afl) if afl else 'NONE'}",
                parsed={**parsed, "afl_hex": _hex(afl) if afl else None},
            )
            # Build the complete READ RECORD queue from the AFL.
            self._read_queue = []
            if afl and len(afl) >= 4:
                for off in range(0, len(afl) - 3, 4):
                    sfi = (afl[off] >> 3) & 0x1F
                    first_record = afl[off + 1]
                    last_record = afl[off + 2]
                    if first_record == 0 or last_record < first_record:
                        continue
                    for record_no in range(first_record, last_record + 1):
                        p2 = (sfi << 3) | 0x04
                        self._read_queue.append((p2, record_no))

            if self._read_queue:
                p2, record_no = self._read_queue.pop(0)
                self.expected = "READ_RECORD_RAPDU"
                self._send_read_record(p2, record_no)
            else:
                self.state = "ERROR"
                self.expected = "STOP"
            return

        if self.expected == "READ_RECORD_RAPDU":
            self.state = "READ_RECORD_DONE"
            cvm = tlv.find_tlv(body, 0x8E) if body else None
            remaining = len(self._read_queue)
            self._emit(
                "APDU",
                "RX",
                exchange_id=exchange_id,
                apdu=apdu,
                status=sw,
                state_before=before,
                state_after=self.state,
                detail=(
                    f"READ RECORD accepted; CVM={_hex(cvm) if cvm else 'NONE'}; "
                    f"remaining_reads={remaining}"
                ),
                parsed={
                    **parsed,
                    "cvm_hex": _hex(cvm) if cvm else None,
                    "remaining_read_count": remaining,
                },
            )

            if self._read_queue:
                p2, record_no = self._read_queue.pop(0)
                self._send_read_record(p2, record_no)
            else:
                # Only after the complete AFL read list has been consumed do
                # we issue the first GENERATE AC.
                self._send_gac1()
            return

        if self.expected == "GAC1_RAPDU":
            cid = tlv.find_tlv(body, 0x9F27) if body else None
            atc = tlv.find_tlv(body, 0x9F36) if body else None
            ac = tlv.find_tlv(body, 0x9F26) if body else None
            self.state = "ARQC_RECEIVED" if cid == bytes([constants.CID_ARQC]) else "GAC1_RECEIVED"
            self._emit(
                "APDU",
                "RX",
                exchange_id=exchange_id,
                apdu=apdu,
                status=sw,
                state_before=before,
                state_after=self.state,
                detail=f"first GAC received; CID={_hex(cid) if cid else 'NONE'}",
                parsed={**parsed, "cid_hex": _hex(cid) if cid else None,
                        "atc_hex": _hex(atc) if atc else None,
                        "ac_hex": _hex(ac) if ac else None},
            )
            if cid == bytes([constants.CID_ARQC]):
                # 05:40:22 capture proceeds directly to the second GAC.
                self._send_gac2()
            else:
                self.expected = "STOP"
            return

        if self.expected == "EXT_AUTH_RAPDU":
            self.state = "EXTERNAL_AUTH_DONE"
            self._emit(
                "APDU",
                "RX",
                exchange_id=exchange_id,
                apdu=apdu,
                status=sw,
                state_before=before,
                state_after=self.state,
                detail="External Authentication accepted in synthetic lab",
                parsed=parsed,
            )
            self._send_gac2()
            return

        if self.expected == "GAC2_RAPDU":
            cid = tlv.find_tlv(body, 0x9F27) if body else None
            self.state = "COMPLETE"
            self.expected = "STOP"
            self._emit(
                "APDU",
                "RX",
                exchange_id=exchange_id,
                apdu=apdu,
                status=sw,
                state_before=before,
                state_after=self.state,
                detail=f"second GAC response received; CID={_hex(cid) if cid else 'NONE'}",
                parsed={**parsed, "cid_hex": _hex(cid) if cid else None},
            )
            return

        self._emit(
            "APDU",
            "RX",
            exchange_id=exchange_id,
            apdu=apdu,
            status=sw,
            state_before=before,
            state_after=self.state,
            detail=f"unexpected response while expected={self.expected}",
            parsed=parsed,
        )

    def status(self) -> Dict[str, Any]:
        out = super().status()
        out.update({
            "state": self.state,
            "expected": self.expected,
            "running_transaction": self.running_transaction,
            "last_capdu_hex": _hex(self.last_capdu),
            "last_response_hex": _hex(self.last_response),
            "profile": self.profile.name,
        })
        return out


class EmvLabSession:
    """Owns zero, one, or two local endpoint simulators."""

    def __init__(
        self,
        *,
        mode: str = "closed_loop",
        relay_host: str = "127.0.0.1",
        relay_port: int = 5566,
        profile: Optional[LabCardProfile] = None,
        session_id: Optional[str] = None,
    ) -> None:
        self.mode = mode.strip().lower()
        if self.mode not in {"closed_loop", "reader", "tag"}:
            raise ValueError("mode must be closed_loop, reader, or tag")
        self.relay_host = relay_host
        self.relay_port = int(relay_port)
        self.profile = profile or LabCardProfile()
        self.session_id = session_id or time.strftime("lab-%Y%m%d-%H%M%S")
        self.events: Deque[LabEvent] = deque(maxlen=2000)
        self.reader: Optional[LabReader] = None
        self.tag: Optional[LabTag] = None
        self.started_at: Optional[float] = None

        # Prevent accidental parallel lab sessions in one process.
        self._lock = threading.RLock()

    def _sink(self, event: LabEvent) -> None:
        with self._lock:
            self.events.append(event)

    def start(self) -> Dict[str, Any]:
        with self._lock:
            if self.started_at is not None:
                return self.status()

            self.started_at = time.time()

            if self.mode in {"closed_loop", "reader"}:
                self.reader = LabReader(
                    profile=self.profile,
                    relay_host=self.relay_host,
                    relay_port=self.relay_port,
                    client_id=f"REL8-LAB-PCD-{self.session_id}",
                    event_sink=self._sink,
                )
                self.reader.start()

            if self.mode in {"closed_loop", "tag"}:
                self.tag = LabTag(
                    profile=self.profile,
                    relay_host=self.relay_host,
                    relay_port=self.relay_port,
                    client_id=f"REL8-LAB-PICC-{self.session_id}",
                    event_sink=self._sink,
                )
                self.tag.start()

            return self.status()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if self.reader:
                self.reader.stop()
            if self.tag:
                self.tag.stop()
            return self.status()

    def wait(self, timeout_s: float = 30.0) -> Dict[str, Any]:
        deadline = time.time() + float(timeout_s)
        while time.time() < deadline:
            st = self.status()
            if st.get("state") in {"COMPLETE", "ERROR", "STOPPED"}:
                return st
            time.sleep(0.1)
        return self.status()

    def status(self) -> Dict[str, Any]:
        reader_state = self.reader.state if self.reader else None
        tag_state = self.tag.state if self.tag else None
        state = "STOPPED"
        if self.started_at is not None and (
            (self.reader and self.reader.running) or (self.tag and self.tag.running)
        ):
            if self.mode == "tag" and self.tag and self.tag.running:
                if self.tag.registration_error:
                    state = "REGISTER_REJECTED"
                elif not self.tag.registered.is_set():
                    state = "REGISTERING"
                else:
                    state = "READY" if self.tag.ready else (tag_state or "REGISTERED")
            else:
                state = reader_state or tag_state or "RUNNING"
                if reader_state == "COMPLETE":
                    state = "COMPLETE"
                elif reader_state == "ERROR" or tag_state == "ERROR":
                    state = "ERROR"

        return {
            "session_id": self.session_id,
            "mode": self.mode,
            "relay": {"host": self.relay_host, "port": self.relay_port},
            "profile": self.profile.name,
            "state": state,
            "started_at": self.started_at,
            "elapsed_s": round(time.time() - self.started_at, 3) if self.started_at else 0.0,
            "event_count": len(self.events),
            "reader": self.reader.status() if self.reader else None,
            "tag": self.tag.status() if self.tag else None,
            "last_events": [
                {
                    "ts": e.ts,
                    "actor": e.actor,
                    "direction": e.direction,
                    "kind": e.kind,
                    "exchange_id": e.exchange_id,
                    "apdu_hex": e.apdu_hex,
                    "status": e.status,
                    "state_before": e.state_before,
                    "state_after": e.state_after,
                    "detail": e.detail,
                    "parsed": e.parsed,
                }
                for e in list(self.events)[-20:]
            ],
        }

    def transcript(self) -> Dict[str, Any]:
        return {
            "harness": "REL8HF EMV Lab",
            "provenance": "synthetic-lab-runtime",
            "session_id": self.session_id,
            "mode": self.mode,
            "relay": {"host": self.relay_host, "port": self.relay_port},
            "profile": self.profile.name,
            "note": (
                "The endpoints are deterministic lab peers. The relay under test "
                "is the production rel8hf implementation. Cryptographic card values "
                "are synthetic unless a separate lab crypto provider is supplied."
            ),
            "events": [
                {
                    "ts": e.ts,
                    "actor": e.actor,
                    "direction": e.direction,
                    "kind": e.kind,
                    "exchange_id": e.exchange_id,
                    "apdu_hex": e.apdu_hex,
                    "status": e.status,
                    "state_before": e.state_before,
                    "state_after": e.state_after,
                    "detail": e.detail,
                    "parsed": e.parsed,
                }
                for e in self.events
            ],
            "status": self.status(),
        }

    def export_json(self, path: Path) -> Path:
        path = Path(path)
        path.write_text(
            json.dumps(self.transcript(), indent=2, default=str),
            encoding="utf-8",
        )
        return path


class EmvLabManager:
    """Process-local manager used by ai_tools.py."""

    def __init__(self) -> None:
        self.session: Optional[EmvLabSession] = None
        self._lock = threading.RLock()

    def start(
        self,
        *,
        mode: str = "closed_loop",
        relay_host: str = "127.0.0.1",
        relay_port: int = 5566,
        wait_s: float = 0.5,
    ) -> Dict[str, Any]:
        with self._lock:
            if self.session is not None:
                self.session.stop()
            self.session = EmvLabSession(
                mode=mode,
                relay_host=relay_host,
                relay_port=int(relay_port),
            )
            result = self.session.start()
        if wait_s > 0:
            time.sleep(float(wait_s))
        return self.status()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if self.session is None:
                return {"state": "STOPPED", "message": "No EMV lab session is active."}
            result = self.session.stop()
            self.session = None
            return result

    def status(self) -> Dict[str, Any]:
        with self._lock:
            if self.session is None:
                return {"state": "STOPPED", "message": "No EMV lab session is active."}
            return self.session.status()

    def wait(self, timeout_s: float = 30.0) -> Dict[str, Any]:
        with self._lock:
            session = self.session
        if session is None:
            return {"state": "STOPPED", "message": "No EMV lab session is active."}
        return session.wait(timeout_s)

    def transcript(self) -> Dict[str, Any]:
        with self._lock:
            if self.session is None:
                return {"state": "STOPPED", "events": []}
            return self.session.transcript()

    def export_json(self, path: Path) -> str:
        with self._lock:
            if self.session is None:
                raise RuntimeError("No EMV lab session is active.")
            return str(self.session.export_json(path))


def run_self_test() -> int:
    """Local construction/serialization smoke test; does not contact UDP."""
    profile = LabCardProfile()
    cases = {
        "ppse": profile.ppse_response(),
        "aid": profile.aid_response(),
        "gpo": profile.gpo_response(),
        "record_2_1": profile.record_response(),
        "record_4_1": profile.record_4_1_response(),
        "record_4_2": profile.record_4_2_response(),
        "record_4_3": profile.record_4_3_response(),
        "gac_arqc": profile.gac_arqc_response(),
        "gac_tc": profile.gac_tc_response(atc=bytes.fromhex("000D")),
        "ext_auth": profile.ext_auth_response(),
    }

    expected_captured = {
        "ppse": bytes.fromhex(
            "6F50840E325041592E5359532E4444463031"
            "A53EBF0C3B"
            "611E4F07A0000000041010"
            "50104465626974204D617374657263617264870101"
            "61194F07A0000000031010"
            "500B56697361204372656469748701019000"
        ),
        "aid": bytes.fromhex(
            "6F658407A0000000041010A55A50104465626974204D617374657263617264870101"
            "9F38039F5C085F2D02656E9F1101019F12104465626974204D617374657263617264"
            "BF0C209F4D020B0A9F6E07082600003030009F5D030100069F0A0800010501000000009000"
        ),
        "gpo": bytes.fromhex(
            "770E82020980940810010101200103009000"
        ),
        "gac_arqc": bytes.fromhex(
            "77339F2701809F3602000D9F26084FFA29CF6FD34076"
            "9F101C3014A04303A40004AE74E26D0A8185D4B460E545E9F534369037000E9000"
        ),
        "record_2_1": bytes.fromhex(
            "7081BE9F420208265F25032512015F24033012315A085355222091779157"
            "5F3401009F0702FFC09F080200028C279F02069F03069F1A0295055F2A029A"
            "039C019F37049F35019F45029F4C089F34039F21039F7C148D12910A8A029505"
            "9F37049F4C089F02069F03068E10000000000000000000001F031E030000"
            "9F51039F37049F5B0CDF6008DF6108DF6201DF63A09F0D050000000000"
            "9F0E0500000000009F0F0500000000005F28020826570E5355222091779157"
            "D301222106109F4A01829000"
        ),
        "record_4_1": bytes.fromhex(
            "7081C59F4681B02945DCF8866BFE7D91990DE7D55370D79EFCA75F58B183E07F0053183955853AA0513A5E12320C01404D17ADF58D2ED6F80C155F0C887B4AA17F15AC928DAAA688E96B0C5DA2760FDE6A3FE3D4FA80677DD29FE637B13E8C4FB7DEC287E6DF27DA04545A964DAA49F4624B0EDBDA68897A6BB5886D6D7A671584772B54054062B34B6F8E8DB8EA6658E092CAA0B993323FB19A5D14DED37CE10503A2C782AFE989D76B0023DD62BDCEC61CE33825C5C69F4701039F480AEE122B67AA85775FA6CD9000"
        ),
        "record_4_2": bytes.fromhex("70078F01069F3201039000"),
        "record_4_3": bytes.fromhex(
            "7081FB9081F888A05F6427BE068DF350CC9DBDBD91EBBCF0D1BE8B6464FFA67818D2B82154CF43BFDB82C1500E8936EED9C6C3BEC13B2E07C848B14C7B9120C2ED99B8904DCDEF89B3AC3D0C6FA1E4BA044FCE39F5DEC94E35A26038B1DD44AF5737A2CCC811D02B1ADFD8EE2D75F6E032EFAE3042E742406409E64F804247E7BEC8D3117DBFBAA178EE72B23AF25E72D99BEC2AA78C51F23FEB343E34C854DA2FD19521E6451EC23D1E19D4D4C2D5D91ADD540A1B3DDAB0A28E1EF190994A01A8C08DD151DDF090AC627B79CAEEC373C99507CED18C211A1DB48F2067C1FD3B37DBE4DAB82E44D036C4D4FCE3853C795493C65D1452F0C0E4DEA6C455769000"
        ),
    }

    for name, expected in expected_captured.items():
        if cases[name] != expected:
            raise AssertionError(
                f"{name} captured replay mismatch: "
                f"{cases[name].hex().upper()} != {expected.hex().upper()}"
            )

    # Explicitly verify the intentionally malformed PPSE test condition.
    ppse = cases["ppse"]
    if len(ppse) != 84:
        raise AssertionError(f"PPSE fixture must be exactly 84 bytes, got {len(ppse)}")
    if ppse[:2] != bytes.fromhex("6F50"):
        raise AssertionError("PPSE fixture must begin with 6F50")
    if not ppse.endswith(constants.SW_9000):
        raise AssertionError("PPSE fixture must end with SW=9000")

    # Structural check for the READ RECORD fixture that will be handed to the
    # real mutation/TLV path.
    rr = cases["record_2_1"]
    if not rr.endswith(constants.SW_9000):
        raise AssertionError("READ RECORD fixture must end in SW=9000")
    if rr[:2] != b"\x70\x81":
        raise AssertionError("READ RECORD fixture must use 70 81 long-form")
    declared_len = rr[2]
    actual_body_len = len(rr) - 2 - 1 - 2
    if declared_len != actual_body_len:
        raise AssertionError(
            f"READ RECORD length mismatch: declared={declared_len} "
            f"actual={actual_body_len}"
        )
    if b"\x5F\x34\x01\x00" not in rr:
        raise AssertionError("READ RECORD fixture lost PSN tag 5F34")
    if b"\x8C\x27" not in rr:
        raise AssertionError("READ RECORD fixture lost CDOL1 tag 8C")
    for name, response in cases.items():
        if len(response) < 2 or _sw(response) != constants.SW_9000:
            raise AssertionError(f"{name}: missing SW=9000")
        body = response[:-2]
        if body:
            emv_parser.parse_ber_tlv(body)

    # Verify the exact 05:40:22 first-GAC command shape.
    gac_fixture = profile.gac1_capdu
    if len(gac_fixture) != 72:
        raise AssertionError(f"GAC #1 length mismatch: expected 72, got {len(gac_fixture)}")
    if gac_fixture[0:5] != bytes.fromhex("80AE800042"):
        raise AssertionError("GAC #1 header/Lc mismatch")
    cmd = protocol.CommandAPDU.from_bytes(gac_fixture)
    if cmd is None or cmd.ins != constants.INS_GENERATE_AC:
        raise AssertionError("GAC #1 did not parse as GENERATE AC")

    if len(profile.gac2_capdu) != 49 or profile.gac2_capdu[:5] != bytes.fromhex("80AE40002B"):
        raise AssertionError("GAC #2 captured command shape mismatch")

    gac2_fixture = profile.gac2_capdu
    if len(gac2_fixture) != 49:
        raise AssertionError(f"GAC #2 length mismatch: expected 49, got {len(gac2_fixture)}")
    if gac2_fixture[0:5] != bytes.fromhex("80AE40002B"):
        raise AssertionError("GAC #2 header/Lc mismatch")

    # Verify the relay wire-frame helpers with the real constants module.
    wire = constants.build_frame(
        constants.SID_CAPDU,
        profile.gac1_capdu,
        seq=7,
        epoch=123,
    )
    parsed = constants.parse_frame(wire)
    if parsed is None:
        raise AssertionError("wire frame did not parse")
    sid, epoch, seq, payload = parsed
    if sid != constants.SID_CAPDU or epoch != 123 or seq != 7:
        raise AssertionError(f"wire header mismatch: {parsed[:3]}")
    if payload != profile.gac1_capdu:
        raise AssertionError("wire payload is not the raw APDU")
    inner_id, inner_payload = constants.parse_exchange_payload(payload)
    if inner_id is not None or inner_payload != profile.gac1_capdu:
        raise AssertionError("lab unexpectedly wrapped the APDU with EXCHANGE_MAGIC")

    print("REL8HF EMV LAB SELF-TEST")
    print("=" * 60)
    print("profile:", profile.name)
    print("PPSE:", _hex(profile.ppse_response()), "(captured)")
    print("GPO :", _hex(profile.gpo_response()), "(captured)")
    print("RR 2/1:", len(profile.record_response()), "bytes (captured)")
    print("RR 4/1:", len(profile.record_4_1_response()), "bytes (captured)")
    print("RR 4/2:", len(profile.record_4_2_response()), "bytes (captured)")
    print("RR 4/3:", len(profile.record_4_3_response()), "bytes (captured)")
    print("GAC :", _hex(profile.gac_arqc_response()), "(captured ARQC)")
    print(
        "GAC fixture:",
        f"len={len(gac_fixture)} Lc={gac_fixture[4]} INS=0x{gac_fixture[1]:02X}",
    )
    print("wire header:", _hex(wire[:11]))
    print("wire payload:", _hex(wire[11:19]), "...")
    print("wire contract: 11-byte header + raw APDU, outer Seq correlation")
    print("STATUS: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="REL8HF state-aware EMV lab peers")
    parser.add_argument("--mode", choices=["closed_loop", "reader", "tag"], default="closed_loop")
    parser.add_argument("--relay-host", default="127.0.0.1")
    parser.add_argument("--relay-port", type=int, default=5566)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--export", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.self_test:
        return run_self_test()

    session = EmvLabSession(
        mode=args.mode,
        relay_host=args.relay_host,
        relay_port=args.relay_port,
    )
    session.start()
    print(json.dumps(session.status(), indent=2, default=str))
    if args.mode == "closed_loop":
        time.sleep(0.5)
        result = session.wait(args.timeout)
        print(json.dumps(result, indent=2, default=str))
    elif args.mode == "tag":
        print("TAG MODE: passive/armed; waiting for real EMULATOR CAPDU traffic.")
        print("Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            pass

    if args.export:
        path = session.export_json(args.export)
        print(f"TRANSCRIPT: {path}")

    session.stop()
    return 0 if session.status().get("state") != "ERROR" else 1


if __name__ == "__main__":
    raise SystemExit(main())
