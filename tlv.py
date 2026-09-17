# -*- coding: utf-8 -*-
"""Core-compatible BER-TLV helpers.

Existing protocol.py functions remain authoritative where available.
replace_tlv() is implemented locally because the previous delegation could
silently discard unrelated suffix bytes during replacement.

Strict replacement contract:
- validate the full input TLV sequence;
- replace matching target TLVs only;
- preserve all non-target bytes;
- rebuild only affected enclosing constructed lengths;
- reject malformed/truncated TLV data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

BytesLike = Union[bytes, bytearray, memoryview]


try:
    from protocol import (
        find_tlv as _proto_find_tlv,
        build_tlv as _proto_build_tlv,
        parse_tlv_list as _proto_parse_tlv_list,
        parse_tlv as _proto_parse_tlv,
        parse_ber_tlv as _proto_parse_ber_tlv,
        build_ber_tlv as _proto_build_ber_tlv,
        TLV as _ProtoTLV,
        TlvValue as _ProtoTlvValue,
        TlvTree as _ProtoTlvTree,
    )
    _HAS_PROTOCOL = True
except Exception:
    _HAS_PROTOCOL = False
    _proto_find_tlv = None
    _proto_build_tlv = None
    _proto_parse_tlv_list = None
    _proto_parse_tlv = None
    _proto_parse_ber_tlv = None
    _proto_build_ber_tlv = None
    _ProtoTLV = None
    _ProtoTlvValue = None
    _ProtoTlvTree = None


def _as_bytes(data: BytesLike, *, name: str = "data") -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like, got {type(data).__name__}")
    return bytes(data)


def _validate_tag(tag: int) -> None:
    if not isinstance(tag, int):
        raise TypeError(f"tag must be int, got {type(tag).__name__}")
    if tag < 0 or tag > 0xFFFFFFFF:
        raise ValueError(f"tag out of range: 0x{tag:X}")


def _encode_tag(tag: int) -> bytes:
    _validate_tag(tag)
    if tag <= 0xFF:
        return bytes([tag])

    raw = tag.to_bytes((tag.bit_length() + 7) // 8, "big")
    if (raw[0] & 0x1F) != 0x1F:
        raise ValueError(f"invalid BER multi-byte tag: 0x{tag:X}")

    result = bytearray([raw[0]])
    for idx, octet in enumerate(raw[1:]):
        result.append(octet | 0x80 if idx < len(raw) - 2 else octet & 0x7F)
    return bytes(result)


def _encode_length(length: int) -> bytes:
    if not isinstance(length, int):
        raise TypeError("length must be int")
    if length < 0:
        raise ValueError("length cannot be negative")
    if length < 0x80:
        return bytes([length])

    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    if len(raw) > 4:
        raise ValueError("BER length exceeds supported 4-byte form")
    return bytes([0x80 | len(raw)]) + raw


def _parse_tag(data: bytes, offset: int) -> Tuple[int, int]:
    if offset < 0 or offset >= len(data):
        raise ValueError("tag offset out of range")

    first = data[offset]
    offset += 1

    if (first & 0x1F) != 0x1F:
        return first, offset

    tag = first
    continuation_count = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated multi-byte BER tag")
        octet = data[offset]
        offset += 1
        continuation_count += 1
        if continuation_count > 3:
            raise ValueError("BER tag exceeds supported 4-byte form")
        tag = (tag << 8) | octet
        if not (octet & 0x80):
            return tag, offset


def _parse_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset < 0 or offset >= len(data):
        raise ValueError("length offset out of range")

    first = data[offset]
    offset += 1

    if not (first & 0x80):
        return first, offset

    count = first & 0x7F
    if count == 0:
        raise ValueError("BER indefinite-length encoding is unsupported")
    if count > 4:
        raise ValueError("BER length exceeds supported 4-byte form")

    end = offset + count
    if end > len(data):
        raise ValueError("truncated BER length field")

    return int.from_bytes(data[offset:end], "big"), end


def _is_constructed(tag: int) -> bool:
    _validate_tag(tag)
    return bool(_encode_tag(tag)[0] & 0x20)


@dataclass(frozen=True)
class _TlvSpan:
    tag: int
    tag_start: int
    tag_end: int
    value_start: int
    value_end: int
    end: int

    @property
    def value_length(self) -> int:
        return self.value_end - self.value_start


def _scan_one(data: bytes, offset: int) -> _TlvSpan:
    tag_start = offset
    tag, tag_end = _parse_tag(data, offset)
    length, value_start = _parse_length(data, tag_end)
    value_end = value_start + length

    if value_end > len(data):
        raise ValueError(
            f"TLV 0x{tag:X} declares {length} value bytes, "
            f"but only {len(data) - value_start} remain"
        )

    return _TlvSpan(
        tag=tag,
        tag_start=tag_start,
        tag_end=tag_end,
        value_start=value_start,
        value_end=value_end,
        end=value_end,
    )


def _scan_sequence(data: bytes) -> List[_TlvSpan]:
    data = _as_bytes(data)
    spans: List[_TlvSpan] = []
    offset = 0
    while offset < len(data):
        span = _scan_one(data, offset)
        spans.append(span)
        offset = span.end
    return spans


def _replace_all(
    data: bytes,
    target_tag: int,
    new_value: bytes,
) -> Tuple[bytes, int]:
    spans = _scan_sequence(data)
    chunks: List[bytes] = []
    cursor = 0
    count = 0

    for span in spans:
        chunks.append(data[cursor:span.tag_start])

        if span.tag == target_tag:
            tag_bytes = data[span.tag_start:span.tag_end]
            chunks.append(
                tag_bytes
                + _encode_length(len(new_value))
                + new_value
            )
            count += 1

        elif _is_constructed(span.tag):
            inner = data[span.value_start:span.value_end]
            replaced_inner, inner_count = _replace_all(
                inner,
                target_tag,
                new_value,
            )

            if inner_count:
                container_tag = data[span.tag_start:span.tag_end]
                chunks.append(
                    container_tag
                    + _encode_length(len(replaced_inner))
                    + replaced_inner
                )
                count += inner_count
            else:
                chunks.append(data[span.tag_start:span.end])

        else:
            chunks.append(data[span.tag_start:span.end])

        cursor = span.end

    chunks.append(data[cursor:])
    return b"".join(chunks), count


def find_tlv(data: BytesLike, target_tag: int) -> Optional[bytes]:
    data = _as_bytes(data)
    _validate_tag(target_tag)

    if _HAS_PROTOCOL and _proto_find_tlv is not None:
        return _proto_find_tlv(data, target_tag)

    for span in _scan_sequence(data):
        if span.tag == target_tag:
            return data[span.value_start:span.value_end]
        if _is_constructed(span.tag):
            nested = find_tlv(
                data[span.value_start:span.value_end],
                target_tag,
            )
            if nested is not None:
                return nested

    return None


def build_tlv(tag: int, value: BytesLike) -> bytes:
    value = _as_bytes(value, name="value")
    _validate_tag(tag)

    if _HAS_PROTOCOL and _proto_build_tlv is not None:
        return _proto_build_tlv(tag, value)

    return _encode_tag(tag) + _encode_length(len(value)) + value


def parse_tlv_list(data: BytesLike) -> List[Tuple[int, bytes]]:
    data = _as_bytes(data)

    if _HAS_PROTOCOL and _proto_parse_tlv_list is not None:
        return _proto_parse_tlv_list(data)

    return [
        (span.tag, data[span.value_start:span.value_end])
        for span in _scan_sequence(data)
    ]


def replace_tlv(
    data: BytesLike,
    target_tag: int,
    new_value: BytesLike,
) -> bytes:
    """Strictly replace target TLVs and preserve unrelated surrounding bytes."""
    data = _as_bytes(data)
    new_value = _as_bytes(new_value, name="new_value")
    _validate_tag(target_tag)

    result, replacements = _replace_all(
        data,
        target_tag,
        new_value,
    )
    return result if replacements else data


def parse_tlv(data: BytesLike, *args: Any, **kwargs: Any) -> Any:
    if _HAS_PROTOCOL and _proto_parse_tlv is not None:
        return _proto_parse_tlv(_as_bytes(data), *args, **kwargs)
    return parse_tlv_list(data)


def parse_ber_tlv(data: BytesLike, *args: Any, **kwargs: Any) -> Any:
    if _HAS_PROTOCOL and _proto_parse_ber_tlv is not None:
        return _proto_parse_ber_tlv(_as_bytes(data), *args, **kwargs)
    return parse_tlv_list(data), []


def build_ber_tlv(tree: Any, *args: Any, **kwargs: Any) -> bytes:
    if _HAS_PROTOCOL and _proto_build_ber_tlv is not None:
        return _proto_build_ber_tlv(tree, *args, **kwargs)

    if not isinstance(tree, dict):
        raise TypeError("fallback build_ber_tlv expects a dict")

    return b"".join(build_tlv(int(tag), value) for tag, value in tree.items())


TLV = _ProtoTLV if _ProtoTLV is not None else Dict[str, Any]
TlvValue = _ProtoTlvValue if _ProtoTlvValue is not None else bytes
TlvTree = _ProtoTlvTree if _ProtoTlvTree is not None else Dict[int, bytes]


def self_test() -> Dict[str, Any]:
    old = bytes(range(27))
    new = bytes.fromhex("000000000000000000001F031E030000")

    sample = (
        build_tlv(0x5A, bytes.fromhex("12345678"))
        + build_tlv(0x8E, old)
        + build_tlv(0x9F51, bytes.fromhex("010203"))
        + build_tlv(0x5F28, bytes.fromhex("0840"))
        + build_tlv(0x57, bytes.fromhex("1234567890123456"))
    )

    result = replace_tlv(sample, 0x8E, new)
    checks = {
        "exact_length_delta": len(result) - len(sample) == len(new) - len(old),
        "target_replaced": find_tlv(result, 0x8E) == new,
        "suffix_9f51_preserved": find_tlv(result, 0x9F51) == bytes.fromhex("010203"),
        "suffix_5f28_preserved": find_tlv(result, 0x5F28) == bytes.fromhex("0840"),
        "suffix_57_preserved": find_tlv(result, 0x57) == bytes.fromhex("1234567890123456"),
    }

    nested = build_tlv(
        0x70,
        build_tlv(0x5A, b"ABCD")
        + build_tlv(0x8E, b"OLDVALUE")
        + build_tlv(0x5F34, b"\x01"),
    )
    nested_out = replace_tlv(nested, 0x8E, b"NEW")
    checks["nested_replacement"] = (
        find_tlv(nested_out, 0x8E) == b"NEW"
        and find_tlv(nested_out, 0x5A) == b"ABCD"
        and find_tlv(nested_out, 0x5F34) == b"\x01"
    )

    malformed = b"\x8E\x05\x01\x02"
    try:
        replace_tlv(malformed, 0x8E, b"\x00")
        checks["malformed_rejected"] = False
    except ValueError:
        checks["malformed_rejected"] = True

    untouched = build_tlv(0x5A, b"AB")
    checks["target_absent_noop"] = replace_tlv(untouched, 0x8E, b"X") == untouched

    checks["status"] = (
        "PASS"
        if all(v is True for k, v in checks.items() if k != "status")
        else "FAIL"
    )
    return checks


__all__ = [
    "find_tlv",
    "build_tlv",
    "parse_tlv_list",
    "replace_tlv",
    "parse_tlv",
    "parse_ber_tlv",
    "build_ber_tlv",
    "TLV",
    "TlvValue",
    "TlvTree",
    "self_test",
]
