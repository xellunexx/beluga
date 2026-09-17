# -*- coding: utf-8 -*-

from __future__ import annotations

import dataclasses
import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict, Any


TEST_PAN = "5555444433332222"
_ISSUER_KEY = b"rel8stack-synthetic-issuer-key"


@dataclass(frozen=True)
class AuthorizationRequest:
    pan: str
    amount_minor: int
    currency_numeric: int
    atc: int
    ttq: bytes
    ctq: bytes
    arqc: bytes
    cdcvm_performed: bool = False
    signature: bytes = b""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pan": self.pan,
            "amount_minor": int(self.amount_minor),
            "currency_numeric": int(self.currency_numeric),
            "atc": int(self.atc),
            "ttq": self.ttq.hex().upper(),
            "ctq": self.ctq.hex().upper(),
            "arqc": self.arqc.hex().upper(),
            "cdcvm_performed": bool(self.cdcvm_performed),
            "signature": self.signature.hex().upper(),
        }

    @staticmethod
    def from_dict(payload: Dict[str, Any]) -> "AuthorizationRequest":
        def _hex(name: str) -> bytes:
            value = str(payload.get(name, "")).strip()
            return bytes.fromhex(value) if value else b""

        return AuthorizationRequest(
            pan=str(payload.get("pan", "")),
            amount_minor=int(payload.get("amount_minor", 0)),
            currency_numeric=int(payload.get("currency_numeric", 0)),
            atc=int(payload.get("atc", 0)),
            ttq=_hex("ttq"),
            ctq=_hex("ctq"),
            arqc=_hex("arqc"),
            cdcvm_performed=bool(payload.get("cdcvm_performed", False)),
            signature=_hex("signature"),
        )


@dataclass(frozen=True)
class AuthorizationResponse:
    approved: bool
    response_code: str
    arqc_valid: bool
    cvm_consistent: bool

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class SyntheticIssuer:
    def __init__(self, *, bind_ctq: bool = True, require_cvm_consistency: bool = True) -> None:
        self.bind_ctq = bool(bind_ctq)
        self.require_cvm_consistency = bool(require_cvm_consistency)

    @staticmethod
    def _ctq_requires_cdcvm(ctq: bytes) -> bool:
        return bool(len(ctq) >= 2 and (ctq[1] & 0x80))

    def _signature_material(self, request: AuthorizationRequest) -> bytes:
        pieces = [
            request.pan.encode("utf-8"),
            f"{int(request.amount_minor)}".encode("utf-8"),
            f"{int(request.currency_numeric)}".encode("utf-8"),
            f"{int(request.atc)}".encode("utf-8"),
            request.ttq,
            request.arqc,
            b"1" if request.cdcvm_performed else b"0",
        ]
        if self.bind_ctq:
            pieces.append(request.ctq)
        return b"|".join(pieces)

    def _sign_bytes(self, request: AuthorizationRequest) -> bytes:
        material = self._signature_material(request)
        return hmac.new(_ISSUER_KEY, material, hashlib.sha256).digest()

    def sign(self, request: AuthorizationRequest) -> AuthorizationRequest:
        return dataclasses.replace(request, signature=self._sign_bytes(request))

    def authorize(self, request: AuthorizationRequest) -> AuthorizationResponse:
        expected = self._sign_bytes(request)
        arqc_valid = hmac.compare_digest(expected, request.signature)
        if not arqc_valid:
            return AuthorizationResponse(
                approved=False,
                response_code="N7",
                arqc_valid=False,
                cvm_consistent=False,
            )

        cvm_consistent = True
        if self.require_cvm_consistency and self._ctq_requires_cdcvm(request.ctq):
            cvm_consistent = bool(request.cdcvm_performed)

        if not cvm_consistent:
            return AuthorizationResponse(
                approved=False,
                response_code="55",
                arqc_valid=True,
                cvm_consistent=False,
            )

        return AuthorizationResponse(
            approved=True,
            response_code="00",
            arqc_valid=True,
            cvm_consistent=True,
        )


class InteractiveIssuer:
    def __init__(self, issuer: SyntheticIssuer) -> None:
        self.issuer = issuer
        self._requests = 0

    def evaluate(self, request_payload: Dict[str, Any]) -> Dict[str, Any]:
        request = AuthorizationRequest.from_dict(request_payload)
        self._requests += 1
        return self.issuer.authorize(request).to_dict()

    def status(self) -> str:
        return f"InteractiveIssuer(requests={self._requests})"
