from __future__ import annotations

from typing import Any, Dict, List, Tuple


INS_NAMES = {
    0xA4: "SELECT",
    0xA8: "GET PROCESSING OPTIONS",
    0xB2: "READ RECORD",
    0xAE: "GENERATE AC",
    0x82: "EXTERNAL AUTHENTICATE",
    0x20: "VERIFY",
}

TAG_NAMES = {
    "82": "AIP",
    "84": "DF Name",
    "8E": "CVM List",
    "94": "AFL",
    "95": "TVR",
    "9A": "Transaction Date",
    "9C": "Transaction Type",
    "9F02": "Amount, Authorised",
    "9F03": "Amount, Other",
    "9F10": "Issuer Application Data",
    "9F1A": "Terminal Country Code",
    "9F26": "Application Cryptogram",
    "9F27": "Cryptogram Information Data",
    "9F34": "CVM Results",
    "9F35": "Terminal Type",
    "9F36": "Application Transaction Counter",
    "9F37": "Unpredictable Number",
    "9F6C": "Card Transaction Qualifiers",
}


def _clean_hex(value: str) -> str:
    return "".join(value.split()).upper()


def decode_apdu(hex_apdu: str) -> Dict[str, Any]:
    raw = bytes.fromhex(_clean_hex(hex_apdu))
    if len(raw) < 4:
        raise ValueError("APDU must contain at least CLA/INS/P1/P2.")

    result: Dict[str, Any] = {
        "cla": f"{raw[0]:02X}",
        "ins": f"{raw[1]:02X}",
        "p1": f"{raw[2]:02X}",
        "p2": f"{raw[3]:02X}",
        "instruction": INS_NAMES.get(raw[1], f"INS 0x{raw[1]:02X}"),
        "length": len(raw),
        "raw": raw.hex().upper(),
    }
    if len(raw) >= 5:
        result["p3_or_lc"] = f"{raw[4]:02X}"
    return result


def _read_len(raw: bytes, offset: int) -> Tuple[int, int]:
    first = raw[offset]
    if first < 0x80:
        return first, 1
    if first == 0x81 and offset + 1 < len(raw):
        return raw[offset + 1], 2
    if first == 0x82 and offset + 2 < len(raw):
        return int.from_bytes(raw[offset + 1:offset + 3], "big"), 3
    raise ValueError("Unsupported TLV length encoding")


def decode_tag_value(raw_hex: str, depth: int = 0) -> List[Dict[str, Any]]:
    raw = bytes.fromhex(_clean_hex(raw_hex))
    items: List[Dict[str, Any]] = []
    i = 0
    while i < len(raw):
        tag_start = i
        first = raw[i]
        i += 1
        if first & 0x1F == 0x1F:
            while i < len(raw):
                b = raw[i]
                i += 1
                if not (b & 0x80):
                    break
        tag_hex = raw[tag_start:i].hex().upper()
        length, n_len = _read_len(raw, i)
        i += n_len
        if i + length > len(raw):
            raise ValueError(f"TLV {tag_hex}: value overruns buffer")
        value = raw[i:i + length]
        i += length
        item = {
            "tag": tag_hex,
            "name": TAG_NAMES.get(tag_hex, "Unknown / Proprietary"),
            "length": length,
            "value_hex": value.hex().upper(),
            "constructed": bool(int(tag_hex, 16) & 0x20),
            "depth": depth,
        }
        if item["constructed"]:
            try:
                item["children"] = decode_tag_value(value.hex(), depth + 1)
            except Exception:
                item["children"] = []
        items.append(item)
    return items


def summarize_tlv(raw_hex: str) -> Dict[str, Any]:
    nodes = decode_tag_value(raw_hex)
    tags: Dict[str, str] = {}
    flat: List[str] = []

    def walk(items: List[Dict[str, Any]]) -> None:
        for item in items:
            tags[item["tag"]] = item["value_hex"]
            flat.append(
                f'{item["tag"]} ({item["name"]}) = {item["value_hex"]}'
            )
            walk(item.get("children", []))

    walk(nodes)
    return {
        "tags": tags,
        "items": nodes,
        "summary": flat,
    }
