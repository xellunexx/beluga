# -*- coding: utf-8 -*-
"""EMV APDU protocol classes, TLV helpers, and byte-level operations."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, NamedTuple, Dict, Any
import struct

@dataclass
class CommandAPDU:
    cla: int = 0x00
    ins: int = 0x00
    p1: int = 0x00
    p2: int = 0x00
    data: bytes = b""
    le: Optional[int] = None
    extended: bool = False

    @staticmethod
    def parse_tlv_list(data: bytes) -> List[Tuple[bytes, bytes]]:
        """
        Robust BER-TLV parser that supports:
        - multi-byte tags (constructed and primitive)
        - short-form (0x00-0x7F) and long-form (0x81-0x84) lengths
        Returns a list of (tag_bytes, value_bytes).
        """
        tlvs: List[Tuple[bytes, bytes]] = []
        i = 0
        n = len(data)
        while i < n:
            tag_start = i
            first = data[i]
            i += 1
            if (first & 0x1F) == 0x1F:
                while i < n:
                    b = data[i]
                    i += 1
                    if not (b & 0x80):
                        break
            tag_bytes = data[tag_start:i]

            if i >= n:
                break
            length_byte = data[i]
            i += 1
            if length_byte & 0x80:
                num_bytes = length_byte & 0x7F
                if num_bytes == 0 or i + num_bytes > n:
                    break
                length = int.from_bytes(data[i:i + num_bytes], "big")
                i += num_bytes
            else:
                length = length_byte

            if i + length > n:
                value_bytes = data[i:]
                tlvs.append((tag_bytes, value_bytes))
                break
            value_bytes = data[i:i + length]
            i += length
            tlvs.append((tag_bytes, value_bytes))
        return tlvs

    @classmethod
    def from_bytes(cls, raw: bytes) -> Optional["CommandAPDU"]:
        if len(raw) < 4:
            return None
        head = dict(cla=raw[0], ins=raw[1], p1=raw[2], p2=raw[3])
        if len(raw) == 4:
            return cls(**head)
        if len(raw) == 5:
            le = raw[4] or 256
            return cls(**head, le=le)

        first_length = raw[4]
        if first_length != 0:
            lc = first_length
            data_end = 5 + lc
            if len(raw) == data_end:
                return cls(**head, data=raw[5:data_end])
            if len(raw) == data_end + 1:
                return cls(**head, data=raw[5:data_end], le=raw[data_end] or 256)
            return None

        if len(raw) < 7:
            return None
        value = int.from_bytes(raw[5:7], "big")
        if len(raw) == 7:
            return cls(**head, le=value or 65536, extended=True)
        if value == 0:
            return None
        data_end = 7 + value
        if len(raw) == data_end:
            return cls(**head, data=raw[7:data_end], extended=True)
        if len(raw) == data_end + 2:
            le = int.from_bytes(raw[data_end:data_end + 2], "big") or 65536
            return cls(**head, data=raw[7:data_end], le=le, extended=True)
        return None

    def to_bytes(self) -> bytes:
        header = bytes([self.cla, self.ins, self.p1, self.p2])
        use_extended = self.extended or len(self.data) > 255 or (self.le or 0) > 256
        if use_extended:
            if self.data:
                if len(self.data) > 65535:
                    raise ValueError("Extended APDU data exceeds 65535 bytes")
                out = header + b"\x00" + len(self.data).to_bytes(2, "big") + self.data
                if self.le is not None:
                    encoded_le = 0 if self.le == 65536 else self.le
                    if not 0 <= encoded_le <= 65535:
                        raise ValueError("Extended Le is out of range")
                    out += encoded_le.to_bytes(2, "big")
                return out
            if self.le is None:
                return header
            encoded_le = 0 if self.le == 65536 else self.le
            if not 0 <= encoded_le <= 65535:
                raise ValueError("Extended Le is out of range")
            return header + b"\x00" + encoded_le.to_bytes(2, "big")

        if self.data:
            out = header + bytes([len(self.data)]) + self.data
            if self.le is not None:
                if not 1 <= self.le <= 256:
                    raise ValueError("Short Le is out of range")
                out += bytes([0 if self.le == 256 else self.le])
            return out
        if self.le is None:
            return header
        if not 1 <= self.le <= 256:
            raise ValueError("Short Le is out of range")
        return header + bytes([0 if self.le == 256 else self.le])

    @property
    def ins_name(self) -> str:
        names = {
            0xA4: "SELECT", 0xA8: "GPO", 0xB2: "READ RECORD",
            0x20: "VERIFY", 0xAE: "GENERATE AC", 0xCA: "GET DATA",
            0x82: "EXTERNAL AUTH",
        }
        return names.get(self.ins, f"0x{self.ins:02X}")

    @property
    def is_select(self) -> bool:
        return self.ins == 0xA4

    @property
    def is_gpo(self) -> bool:
        return self.ins == 0xA8

    @property
    def is_read_record(self) -> bool:
        return self.ins == 0xB2

    @property
    def is_generate_ac(self) -> bool:
        return self.ins == 0xAE

    @property
    def is_verify(self) -> bool:
        return self.cla == 0x00 and self.ins == 0x20 and self.p1 == 0x00 and self.p2 == 0x80

    @property
    def select_aid(self) -> Optional[bytes]:
        if not self.is_select or self.p1 != 0x04:
            return None
        return self.data

@dataclass
class ResponseAPDU:
    data: bytes = b""
    sw1: int = 0x90
    sw2: int = 0x00

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ResponseAPDU":
        if len(raw) < 2:
            return cls(sw1=0x6F, sw2=0x00)
        return cls(data=raw[:-2], sw1=raw[-2], sw2=raw[-1])

    def parse_tlv_list(self, data: Optional[bytes] = None) -> List[Tuple[bytes, bytes]]:
        """Parse TLVs from response data (or passed data bytes)."""
        target_data = self.data if data is None else data
        return CommandAPDU.parse_tlv_list(target_data)

    def to_bytes(self) -> bytes:
        return self.data + bytes([self.sw1, self.sw2])

    @property
    def sw(self) -> bytes:
        return bytes([self.sw1, self.sw2])

    @property
    def is_ok(self) -> bool:
        return self.sw1 == 0x90 and self.sw2 == 0x00

def craft_verify_success() -> ResponseAPDU:
    """Return SW=9000 for VERIFY bypass."""
    return ResponseAPDU(sw1=0x90, sw2=0x00)

def sw(status: bytes) -> ResponseAPDU:
    return ResponseAPDU(sw1=status[0], sw2=status[1])

SW9000 = b"\x90\x00"
SW6F00 = b"\x6F\x00"

# --- TLV helpers -----------------------------------------------------------

class TLV(NamedTuple):
    tag: int
    length: int
    value: bytes
    rest: bytes


class TlvValue(bytes):
    @property
    def length(self) -> int:
        return len(self)


class TlvTree(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sw: bytes = b""

    def __contains__(self, key: Any) -> bool:
        if super().__contains__(key):
            return True
        for val in self.values():
            if isinstance(val, TlvTree) and key in val:
                return True
        return False

    def __getitem__(self, key: Any) -> Any:
        if super().__contains__(key):
            return super().__getitem__(key)
        for val in self.values():
            if isinstance(val, TlvTree) and key in val:
                return val[key]
        raise KeyError(key)

    def __setitem__(self, key: Any, value: Any) -> None:
        if super().__contains__(key) or not any(isinstance(v, TlvTree) and key in v for v in self.values()):
            if isinstance(value, (bytes, bytearray)) and not isinstance(value, TlvValue):
                super().__setitem__(key, TlvValue(value))
            else:
                super().__setitem__(key, value)
            return
        for val in self.values():
            if isinstance(val, TlvTree) and key in val:
                val[key] = value
                return

    def get(self, key: Any, default: Any = None) -> Any:
        if key in self:
            return self[key]
        return default


def is_constructed_tag(tag: int) -> bool:
    top = tag
    while top > 0xFF:
        top >>= 8
    return bool(top & 0x20)


def parse_tlv(data: bytes, offset: int = 0) -> TLV:
    """
    Parse a single BER-TLV, supporting extended lengths.
    Returns (tag, length, value, rest_of_data).
    """
    if offset >= len(data):
        return TLV(0, 0, b"", b"")
    first = data[offset]
    offset += 1
    tag = first
    if (first & 0x1F) == 0x1F:
        while offset < len(data):
            b = data[offset]
            tag = (tag << 8) | b
            offset += 1
            if not (b & 0x80):
                break

    if offset >= len(data):
        return TLV(tag, 0, b"", b"")

    if data[offset] & 0x80:
        num_len_bytes = data[offset] & 0x7F
        offset += 1
        if num_len_bytes == 0 or offset + num_len_bytes > len(data):
            return TLV(tag, 0, b"", b"")
        length = int.from_bytes(data[offset:offset + num_len_bytes], "big")
        offset += num_len_bytes
    else:
        length = data[offset]
        offset += 1

    value = data[offset:offset + length]
    rest = data[offset + length:]
    return TLV(tag, length, value, rest)


def parse_ber_tlv(data: bytes) -> TlvTree:
    """
    Walk the TLV tree of a BER-TLV byte stream into a recursive TlvTree.
    """
    tree = TlvTree()
    if not data:
        return tree

    offset = 0
    n = len(data)
    while offset < n:
        if offset == n - 2 and (data[offset] in (0x90, 0x6F, 0x6A, 0x67, 0x69, 0x63, 0x62) or len(tree) > 0):
            tree.sw = data[offset:]
            break

        tag_item = parse_tlv(data, offset)
        tag = tag_item.tag
        val_bytes = tag_item.value
        consumed = n - len(tag_item.rest) - offset
        if consumed <= 0:
            if offset + 2 == n:
                tree.sw = data[offset:]
            break
        offset += consumed

        if is_constructed_tag(tag):
            child_tree = parse_ber_tlv(val_bytes)
            tree[tag] = child_tree
        else:
            tree[tag] = TlvValue(val_bytes)

    return tree


def build_ber_tlv(tree: dict | TlvTree) -> bytes:
    """
    Rebuild BER-TLV byte stream from a dictionary or TlvTree.
    """
    out = bytearray()
    for tag, val in tree.items():
        if isinstance(val, dict):
            child_bytes = build_ber_tlv(val)
            out.extend(build_tlv(tag, child_bytes))
        elif isinstance(val, (bytes, bytearray)):
            out.extend(build_tlv(tag, bytes(val)))
    if isinstance(tree, TlvTree) and tree.sw:
        out.extend(tree.sw)
    return bytes(out)


def find_tlv(data: bytes, target_tag: int) -> Optional[bytes]:
    i, n = 0, len(data)
    while i < n:
        tag_first = data[i]; i += 1
        if (tag_first & 0x1F) == 0x1F:
            if i >= n: return None
            tag = (tag_first << 8) | data[i]; i += 1
        else:
            tag = tag_first
        if i >= n: return None
        lf = data[i]; i += 1
        if lf & 0x80:
            nb = lf & 0x7F
            if nb == 0 or nb > 2 or i + nb > n: return None
            length = 0
            for _ in range(nb):
                length = (length << 8) | data[i]; i += 1
        else:
            length = lf
        if i + length > n: return None
        value = data[i:i + length]
        if tag == target_tag: return value
        if tag_first & 0x20:
            inner = find_tlv(value, target_tag)
            if inner is not None: return inner
        i += length
    return None

def build_tlv(tag: int, value: bytes) -> bytes:
    if tag <= 0xFF:
        tag_bytes = bytes([tag])
    elif tag <= 0xFFFF:
        tag_bytes = struct.pack(">H", tag)
    elif tag <= 0xFFFFFF:
        tag_bytes = tag.to_bytes(3, "big")
    else:
        raise ValueError(f"tag out of supported range (<= 0xFFFFFF): 0x{tag:X}")
    length = len(value)
    if length < 0x80:
        length_bytes = bytes([length])
    elif length < 0x100:
        length_bytes = bytes([0x81, length])
    else:
        length_bytes = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    return tag_bytes + length_bytes + value

def parse_tlv_list(data: bytes) -> List[Tuple[int, bytes]]:
    """Parse all top-level TLV entries into a list of (tag, value)."""
    result = []
    i, n = 0, len(data)
    while i < n:
        tag_first = data[i]; i += 1
        if (tag_first & 0x1F) == 0x1F:
            if i >= n: break
            tag = (tag_first << 8) | data[i]; i += 1
        else:
            tag = tag_first
        if i >= n: break
        lf = data[i]; i += 1
        if lf & 0x80:
            nb = lf & 0x7F
            if nb == 0 or nb > 2 or i + nb > n: break
            length = 0
            for _ in range(nb):
                length = (length << 8) | data[i]; i += 1
        else:
            length = lf
        if i + length > n: break
        result.append((tag, data[i:i + length]))
        i += length
    return result

def replace_tlv(data: bytes, target_tag: int, new_value: bytes) -> bytes:
    """
    Replace every occurrence of target_tag without losing unrelated bytes.

    Core contract:
    - Validate the complete BER-TLV sequence before modifying anything.
    - Replace the exact target TLV span.
    - Preserve every byte outside the target TLV.
    - Recalculate only lengths of containing constructed TLVs.
    - Never silently truncate malformed input.
    - Return the original bytes unchanged when target_tag is absent.

    This deliberately does NOT use parse_tlv_list(), because that function
    historically stopped on malformed/truncated input and replace_tlv() then
    rebuilt only the successfully parsed prefix.
    """

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"data must be bytes-like, got {type(data).__name__}"
        )
    if not isinstance(new_value, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"new_value must be bytes-like, got {type(new_value).__name__}"
        )
    if not isinstance(target_tag, int):
        raise TypeError(
            f"target_tag must be int, got {type(target_tag).__name__}"
        )
    if target_tag < 0 or target_tag > 0xFFFFFF:
        raise ValueError(
            f"target_tag out of supported range: 0x{target_tag:X}"
        )

    data = bytes(data)
    new_value = bytes(new_value)

    def _parse_tag(buf: bytes, offset: int):
        if offset >= len(buf):
            raise ValueError("truncated TLV tag")

        start = offset
        first = buf[offset]
        offset += 1

        if (first & 0x1F) != 0x1F:
            return first, start, offset

        # BER high-tag-number form.
        while True:
            if offset >= len(buf):
                raise ValueError(
                    "truncated multi-byte BER tag"
                )

            octet = buf[offset]
            offset += 1

            # A BER tag can continue until a terminating octet is seen.
            if not (octet & 0x80):
                break

        tag_value = int.from_bytes(
            buf[start:offset],
            "big",
        )
        return tag_value, start, offset

    def _parse_length(buf: bytes, offset: int):
        if offset >= len(buf):
            raise ValueError("truncated TLV length")

        first = buf[offset]
        offset += 1

        if not (first & 0x80):
            return first, offset

        count = first & 0x7F

        # BER indefinite form is not supported by this stack.
        if count == 0:
            raise ValueError(
                "indefinite-length BER TLV is unsupported"
            )

        # Keep this bounded and explicit.
        if count > 4:
            raise ValueError(
                "BER length exceeds supported 4-byte form"
            )

        if offset + count > len(buf):
            raise ValueError(
                "truncated BER length field"
            )

        length = int.from_bytes(
            buf[offset:offset + count],
            "big",
        )
        offset += count

        return length, offset

    def _encode_length(length: int) -> bytes:
        if length < 0:
            raise ValueError(
                "TLV length cannot be negative"
            )

        if length < 0x80:
            return bytes([length])

        if length <= 0xFF:
            return b"\x81" + bytes([length])

        if length <= 0xFFFF:
            return b"\x82" + length.to_bytes(2, "big")

        if length <= 0xFFFFFF:
            return b"\x83" + length.to_bytes(3, "big")

        if length <= 0xFFFFFFFF:
            return b"\x84" + length.to_bytes(4, "big")

        raise ValueError(
            "TLV value exceeds supported 4-byte length"
        )

    def _scan_one(buf: bytes, offset: int):
        tag, tag_start, tag_end = _parse_tag(
            buf,
            offset,
        )

        value_length, value_start = _parse_length(
            buf,
            tag_end,
        )

        value_end = value_start + value_length

        if value_end > len(buf):
            raise ValueError(
                f"TLV 0x{tag:X} declares "
                f"{value_length} value bytes, "
                f"but only {len(buf) - value_start} remain"
            )

        return {
            "tag": tag,
            "tag_start": tag_start,
            "tag_end": tag_end,
            "value_start": value_start,
            "value_end": value_end,
            "end": value_end,
            "constructed": bool(
                buf[tag_start] & 0x20
            ),
        }

    def _replace_sequence(
        buf: bytes,
    ):
        """
        Parse a COMPLETE TLV sequence and rebuild only paths containing
        target_tag.

        Returns:
            (new_bytes, replacement_count)
        """

        spans = []
        offset = 0

        # IMPORTANT:
        # Scan the ENTIRE sequence before rebuilding anything.
        # A malformed trailing TLV therefore causes safe failure rather than
        # accidental prefix truncation.
        while offset < len(buf):
            span = _scan_one(buf, offset)
            spans.append(span)
            offset = span["end"]

        output_parts = []
        cursor = 0
        replacement_count = 0

        for span in spans:
            start = span["tag_start"]
            end = span["end"]

            # Preserve bytes preceding this TLV exactly.
            output_parts.append(buf[cursor:start])

            if span["tag"] == target_tag:
                # Preserve the original encoded tag bytes exactly.
                original_tag_bytes = buf[
                    span["tag_start"]:span["tag_end"]
                ]

                replacement = (
                    original_tag_bytes
                    + _encode_length(len(new_value))
                    + new_value
                )

                output_parts.append(replacement)
                replacement_count += 1

            elif span["constructed"]:
                # Recursively inspect constructed TLVs.
                inner = buf[
                    span["value_start"]:span["value_end"]
                ]

                new_inner, nested_count = _replace_sequence(
                    inner
                )

                if nested_count:
                    # Rebuild ONLY the containing TLV:
                    # original tag + new length + changed inner value.
                    original_tag_bytes = buf[
                        span["tag_start"]:span["tag_end"]
                    ]

                    replacement = (
                        original_tag_bytes
                        + _encode_length(len(new_inner))
                        + new_inner
                    )

                    output_parts.append(replacement)
                    replacement_count += nested_count

                else:
                    # No target beneath this container.
                    output_parts.append(
                        buf[start:end]
                    )

            else:
                # Primitive non-target TLV: preserve byte-for-byte.
                output_parts.append(
                    buf[start:end]
                )

            cursor = end

        # CRITICAL: preserve everything after the last TLV.
        output_parts.append(buf[cursor:])

        return (
            b"".join(output_parts),
            replacement_count,
        )

    result, replacement_count = _replace_sequence(
        data
    )

    # Preserve the original function's useful no-op behavior.
    if replacement_count == 0:
        return data

    return result
