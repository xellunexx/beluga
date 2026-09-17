# -*- coding: utf-8 -*-
import pytest
import time
from protocol import CommandAPDU, ResponseAPDU
from guard import Guard, Phase
from logger import mask_pan, set_current_transaction_id, get_current_transaction_id, _record_apdu


def test_parse_tlv_long_form():
    data = b'\x9F\x1A\x02\x01\x23\x9F\x33\x81\x01\x45'
    tlvs = CommandAPDU.parse_tlv_list(data)
    assert tlvs == [(b'\x9F\x1A', b'\x01\x23'), (b'\x9F\x33', b'\x45')]


def test_parse_tlv_multi_byte_and_single_byte():
    # Tag 0x82 (AIP) is single byte with MSB set. Tag 0x5F24 is 2-byte tag with MSB unset.
    data = b'\x82\x02\x08\x00\x5F\x24\x03\x25\x12\x31'
    tlvs = CommandAPDU.parse_tlv_list(data)
    assert tlvs == [(b'\x82', b'\x08\x00'), (b'\x5F\x24', b'\x25\x12\x31')]


def test_response_apdu_parse_tlv():
    resp = ResponseAPDU(data=b'\x82\x02\x08\x00', sw1=0x90, sw2=0x00)
    tlvs = resp.parse_tlv_list()
    assert tlvs == [(b'\x82', b'\x08\x00')]


def test_guard_timeout_tick():
    g = Guard(timeout=0.05)
    g.record_sw(b"\x90\x00")
    allowed, _ = g.advance(Phase.PPSE_SELECTED)
    assert allowed
    assert g.phase == Phase.PPSE_SELECTED
    time.sleep(0.08)
    g.tick()
    assert g.phase == Phase.ERROR


def test_guard_apply_ctq_modifier():
    class DummyProfile:
        def get_cvm_for_card(self, card):
            return [0x1F, 0x03] # CDCVM

    class DummyProfileNoCDCVM:
        def get_cvm_for_card(self, card):
            return [0x02, 0x03] # Enciphered PIN

    g = Guard()
    assert g.apply_ctq_modifier("card", DummyProfile()) is True
    assert g.apply_ctq_modifier("card", DummyProfileNoCDCVM()) is False


def test_logger_pan_masking_and_correlation():
    masked = mask_pan("4111222233334444")
    assert masked == "411122******4444"

    tx_id = set_current_transaction_id("tx-test-1234")
    assert get_current_transaction_id() == "tx-test-1234"
    _record_apdu("C->S", "CAPDU", "SELECT", b"\x00\xA4\x04\x00")
