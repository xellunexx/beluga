# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


PPSE_SELECT = "00A404000E325041592E5359532E444446303100"
_EPOCH_RE = re.compile(r"^(?P<ts>\d{2}:\d{2}:\d{2}\.\d{3}).*Session epoch opened:\s*(?P<epoch>\d+)(?:\s+token=(?P<token>\S+))?")
_CAPDU_RE = re.compile(r"CAPDU\s+\S+\s+len=\d+:\s*([0-9A-Fa-f]+)")


@dataclass
class Exchange:
    transaction: int
    epoch: Optional[int]
    capdu_hex: str = ""


@dataclass
class TlvNode:
    tag: str
    value: bytes
    children: List["TlvNode"] = field(default_factory=list)


class RelayAnalyzer:
    def __init__(self, source: Path) -> None:
        self.source = Path(source)
        self.epochs: List[Tuple[int, str, str]] = []
        self.exchanges: List[Exchange] = []

    def analyze(self) -> None:
        lines = self.source.read_text(encoding="utf-8", errors="replace").splitlines()
        current_epoch: Optional[int] = None
        transaction = 0

        for line in lines:
            epoch_match = _EPOCH_RE.search(line)
            if epoch_match:
                epoch = int(epoch_match.group("epoch"))
                token = epoch_match.group("token") or "not-logged"
                ts = epoch_match.group("ts")
                self.epochs.append((epoch, token, ts))
                current_epoch = epoch
                continue

            capdu_match = _CAPDU_RE.search(line)
            if not capdu_match:
                continue
            capdu_hex = capdu_match.group(1).upper()
            if capdu_hex == PPSE_SELECT or transaction == 0:
                transaction += 1
            self.exchanges.append(Exchange(transaction=transaction, epoch=current_epoch, capdu_hex=capdu_hex))


def parsed_path(path: Path) -> Path:
    path = Path(path)
    if path.suffix.lower() != ".log":
        return path.with_name(path.name + "_parsed")
    return path.with_name(f"{path.stem}_parsed{path.suffix}")


def transaction_logs(root: Path) -> List[Path]:
    root = Path(root)
    candidates = []
    for p in root.glob("tx_*.log"):
        if p.name.endswith("_parsed.log"):
            continue
        candidates.append(p)
    return sorted(candidates)


def parse_ber_tlv(data: bytes) -> Tuple[List[TlvNode], List[str]]:
    i = 0
    nodes: List[TlvNode] = []
    errors: List[str] = []
    dol_like_tags = {"8C", "8D", "8E", "9F38", "9F49"}

    while i < len(data):
        start = i
        first = data[i]
        i += 1

        tag_bytes = bytes([first])
        if (first & 0x1F) == 0x1F:
            while i < len(data):
                b = data[i]
                tag_bytes += bytes([b])
                i += 1
                if not (b & 0x80):
                    break

        if i >= len(data):
            errors.append("missing_length")
            break

        length_first = data[i]
        i += 1
        if length_first & 0x80:
            n_len = length_first & 0x7F
            if i + n_len > len(data):
                errors.append("length_overflow")
                break
            length = int.from_bytes(data[i:i + n_len], "big")
            i += n_len
        else:
            length = length_first

        if i + length > len(data):
            errors.append("value_overflow")
            break

        value = data[i:i + length]
        i += length
        tag_hex = tag_bytes.hex().upper()

        is_constructed = bool(tag_bytes[0] & 0x20)
        if is_constructed and tag_hex not in dol_like_tags:
            children, child_errors = parse_ber_tlv(value)
            nodes.append(TlvNode(tag=tag_hex, value=value, children=children))
            errors.extend(child_errors)
        else:
            nodes.append(TlvNode(tag=tag_hex, value=value, children=[]))

        if i <= start:
            errors.append("parser_stall")
            break

    return nodes, errors
