# -*- coding: utf-8 -*-
"""Real guard-flow regression checks for the EMV transaction state machine.

This file used to be a print-only demo. It is now an executable pytest regression test
that asserts the legal flow progression, retry after failure, and the guarded second-GAC
forge decision path.
"""

import pytest

from constants import CID_ARQC
from guard import Guard, Phase, SessionState, SW_9000


def _make_session() -> SessionState:
    session = SessionState(
        arpc_forge_enabled=True,
        second_ae_pending=True,
        verify_bypass_enabled=True,
        arpc_rewrite_enabled=True,
    )
    session.arqc_cache.cid = CID_ARQC
    session.arqc_cache.atc = b"\x00\x01"
    session.arqc_cache.ac = b"\x12\x34\x56\x78"
    session.arqc_cache.iad = b"iad"
    return session


def test_guard_allows_expected_emv_progression() -> None:
    guard = Guard()
    session = _make_session()

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.PPSE_SELECTED)
    assert ok and "Phase advanced to PPSE_SELECTED" in reason

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.AID_SELECTED)
    assert ok and "Phase advanced to AID_SELECTED" in reason

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.GPO_RESPONDED)
    assert ok and "Phase advanced to GPO_RESPONDED" in reason

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.READ_RECORD_DONE)
    assert ok and "Phase advanced to READ_RECORD_DONE" in reason

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.FIRST_GAC_SENT)
    assert ok and "Phase advanced to FIRST_GAC_SENT" in reason

    ok, reason = guard.advance(Phase.ARQC_RECEIVED)
    assert ok and "Phase advanced to ARQC_RECEIVED" in reason

    ok, reason = guard.check_forge(session)
    assert ok and "forge allowed" in reason.lower()

    ok, reason = guard.advance(Phase.SECOND_GAC_FORGED)
    assert ok and "Phase advanced to SECOND_GAC_FORGED" in reason

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.EXTERNAL_AUTH_DONE)
    assert ok and "Phase advanced to EXTERNAL_AUTH_DONE" in reason

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.COMPLETE)
    assert ok and "Phase advanced to COMPLETE" in reason

    ok, reason = guard.advance(Phase.IDLE)
    assert not ok and "denied" in reason.lower()


def test_guard_retries_after_non_9000_response() -> None:
    guard = Guard()

    guard.record_sw(SW_9000)
    ok, reason = guard.advance(Phase.PPSE_SELECTED)
    assert ok and "Phase advanced to PPSE_SELECTED" in reason

    guard.record_sw(b"\x6A\x82")
    assert guard._last_sw == b"\x6A\x82"
    ok, reason = guard.advance(Phase.AID_SELECTED)
    assert not ok and "expected sw=9000" in reason.lower()

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.AID_SELECTED)
    assert ok and "Phase advanced to AID_SELECTED" in reason

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.GPO_RESPONDED)
    assert ok and "Phase advanced to GPO_RESPONDED" in reason

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.READ_RECORD_DONE)
    assert ok and "Phase advanced to READ_RECORD_DONE" in reason

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.FIRST_GAC_SENT)
    assert ok and "Phase advanced to FIRST_GAC_SENT" in reason

    ok, reason = guard.advance(Phase.ARQC_RECEIVED)
    assert ok and "Phase advanced to ARQC_RECEIVED" in reason

    ok, reason = guard.check_forge(_make_session())
    assert ok

    ok, reason = guard.advance(Phase.SECOND_GAC_FORGED)
    assert ok and "Phase advanced to SECOND_GAC_FORGED" in reason

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.EXTERNAL_AUTH_DONE)
    assert ok and "Phase advanced to EXTERNAL_AUTH_DONE" in reason

    guard.record_sw(SW_9000)
    assert guard._last_sw == SW_9000
    ok, reason = guard.advance(Phase.COMPLETE)
    assert ok and "Phase advanced to COMPLETE" in reason


if __name__ == "__main__":
    raise SystemExit(pytest.main(["-q", __file__]))
