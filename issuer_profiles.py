# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
F.R.A.N.K. ISSUER PROFILE TABLE v2.0
Threshold-aware CVM selection keyed to 5F28 country code.

cvm_threshold: integer in minor currency units (same encoding as 9F02).
               0 = no threshold (base cvm_* applies at all amounts).
               >0 = below threshold -> cvm_debit/credit/etc,
                    at or above threshold -> SIG override.

9F02 BCD parse: int('000000010000') = 10000 minor units = e.g. £100.00
                Works because BCD amount nibbles are always 0-9.
"""

import logging
import json
from pathlib import Path
from typing import Optional

logger = logging.getLogger("bypass_engine")

# ─────────────────────────────────────────────────────────────
# 9F34 CONSTANTS
# ─────────────────────────────────────────────────────────────
SIG   = '1E0002'   # Signature / always / successful
NOCVM = '1F0002'   # No CVM required / always / successful
OPIN  = '010002'   # Offline plaintext PIN / always / successful

# ─────────────────────────────────────────────────────────────
# ISSUER PROFILE TABLE
# cvm_threshold: minor currency units above which SIG replaces NoCVM
# 0 means threshold check is disabled (SIG-only countries set 0)
# ─────────────────────────────────────────────────────────────
ISSUER_PROFILES = {

    # ── UNITED KINGDOM ───────────────────────────────────────
    '0826': {
        'country':      'United Kingdom',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 10000,   # £100.00 -- Oct 2023 limit
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'UK: NoCVM below £100, Sig at/above.',
    },

    # ── IRELAND ───────────────────────────────────────────────
    '0372': {
        'country':      'Ireland',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 5000,    # €50.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'IE: NoCVM below €50, Sig at/above.',
    },

    # ── NETHERLANDS ───────────────────────────────────────────
    '0528': {
        'country':      'Netherlands',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 5000,    # €50.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'NL: NoCVM below €50.',
    },

    # ── BELGIUM ───────────────────────────────────────────────
    '0056': {
        'country':      'Belgium',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 5000,    # €50.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'BE: Bancontact NoCVM below €50.',
    },

    # ── LUXEMBOURG ────────────────────────────────────────────
    '0442': {
        'country':      'Luxembourg',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 5000,    # €50.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'LU: Benelux NoCVM model below €50.',
    },

    # ── FRANCE ────────────────────────────────────────────────
    '0250': {
        'country':      'France',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,       # SIG always -- threshold N/A
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'FR: Cartes Bancaires SIG always. IAD skip.',
    },

    # ── GERMANY ───────────────────────────────────────────────
    '0276': {
        'country':      'Germany',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'DE: Girocard SIG always.',
    },

    # ── AUSTRIA ───────────────────────────────────────────────
    '0040': {
        'country':      'Austria',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'AT: DEfollows DE model. SIG always.',
    },

    # ── SWITZERLAND ───────────────────────────────────────────
    '0756': {
        'country':      'Switzerland',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'CH: PostFinance, UBS offline PIN. SIG always.',
    },

    # ── SPAIN ─────────────────────────────────────────────────
    '0724': {
        'country':      'Spain',
        'cvm_debit':    SIG,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 5000,    # €50.00 -- credit NoCVM below, SIG above
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'ES: Credit NoCVM below €50, SIG at/above. Debit SIG always.',
    },

    # ── PORTUGAL ──────────────────────────────────────────────
    '0620': {
        'country':      'Portugal',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'PT: MB WAY. SIG always.',
    },

    # ── ITALY ─────────────────────────────────────────────────
    '0380': {
        'country':      'Italy',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'IT: Bancomat PIN enforced contact. SIG always relay.',
    },

    # ── GREECE ────────────────────────────────────────────────
    '0300': {
        'country':      'Greece',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'GR: Alpha, Eurobank. SIG always.',
    },

    # ── POLAND ────────────────────────────────────────────────
    '0616': {
        'country':      'Poland',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'PL: BLIK PIN dominant. SIG always relay.',
    },

    # ── CZECH REPUBLIC ────────────────────────────────────────
    '0203': {
        'country':      'Czech Republic',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'CZ: Ceska sporitelna, CSOB. SIG always.',
    },

    # ── SLOVAKIA ──────────────────────────────────────────────
    '0703': {
        'country':      'Slovakia',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'SK: Follows CZ model. SIG always.',
    },

    # ── HUNGARY ───────────────────────────────────────────────
    '0348': {
        'country':      'Hungary',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'HU: OTP Bank PIN enforced. SIG always relay.',
    },

    # ── ROMANIA ───────────────────────────────────────────────
    '0642': {
        'country':      'Romania',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,   # ING Romania compressed IAD
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'RO: ING Romania SIG confirmed. IAD skip.',
    },

    # ── BULGARIA ──────────────────────────────────────────────
    '0100': {
        'country':      'Bulgaria',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'BG: DSK, UniCredit BG. SIG always.',
    },

    # ── CROATIA ───────────────────────────────────────────────
    '0191': {
        'country':      'Croatia',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'HR: Erste, Zaba. SIG always.',
    },

    # ── SERBIA ────────────────────────────────────────────────
    '0688': {
        'country':      'Serbia',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'RS: Banca Intesa, Komercijalna. SIG always.',
    },

    # ── UKRAINE ───────────────────────────────────────────────
    '0804': {
        'country':      'Ukraine',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'UA: PrivatBank, Monobank. SIG always.',
    },

    # ── RUSSIA ────────────────────────────────────────────────
    '0643': {
        'country':      'Russia',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'RU: Sberbank, Tinkoff. SIG always. Mir skip.',
    },

    # ── SWEDEN ────────────────────────────────────────────────
    '0752': {
        'country':      'Sweden',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 40000,   # 400 SEK (minor unit = öre, 1/100 SEK)
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'SE: NoCVM below 400 SEK, SIG at/above.',
    },

    # ── NORWAY ────────────────────────────────────────────────
    '0578': {
        'country':      'Norway',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 50000,   # 500 NOK
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'NO: DNB, SpareBank. NoCVM below 500 NOK.',
    },

    # ── DENMARK ───────────────────────────────────────────────
    '0208': {
        'country':      'Denmark',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 35000,   # 350 DKK
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'DK: Dankort NoCVM below 350 DKK.',
    },

    # ── FINLAND ───────────────────────────────────────────────
    '0246': {
        'country':      'Finland',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 5000,    # €50.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'FI: OP, Nordea. NoCVM below €50.',
    },

    # ── ESTONIA ───────────────────────────────────────────────
    '0233': {
        'country':      'Estonia',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 5000,    # €50.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'EE: LHV, SEB Estonia. NoCVM below €50.',
    },

    # ── LATVIA ────────────────────────────────────────────────
    '0428': {
        'country':      'Latvia',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 5000,    # €50.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'LV: Citadele, SEB Latvia. NoCVM below €50.',
    },

    # ── LITHUANIA ─────────────────────────────────────────────
    '0440': {
        'country':      'Lithuania',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 5000,    # €50.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'LT: Luminor, SEB Lithuania. NoCVM below €50.',
    },

    # ── UNITED STATES ─────────────────────────────────────────
    '0840': {
        'country':      'United States',
        'cvm_debit':    SIG,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 10000,   # $100.00 -- credit NoCVM below, SIG at/above
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'US: Credit NoCVM below $100, SIG at/above. Debit SIG always.',
    },

    # ── CANADA ────────────────────────────────────────────────
    '0124': {
        'country':      'Canada',
        'cvm_debit':    SIG,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 25000,   # CAD 250.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'CA: Credit NoCVM below CAD 250, SIG at/above.',
    },

    # ── AUSTRALIA ─────────────────────────────────────────────
    '0036': {
        'country':      'Australia',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 10000,   # AUD 100.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'AU: Tap-and-go NoCVM below AUD 100, SIG at/above.',
    },

    # ── NEW ZEALAND ───────────────────────────────────────────
    '0554': {
        'country':      'New Zealand',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 20000,   # NZD 200.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'NZ: ANZ NZ, BNZ. NoCVM below NZD 200.',
    },

    # ── SINGAPORE ─────────────────────────────────────────────
    '0702': {
        'country':      'Singapore',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 20000,   # SGD 200.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'SG: DBS, OCBC, UOB. NoCVM below SGD 200.',
    },

    # ── HONG KONG ─────────────────────────────────────────────
    '0344': {
        'country':      'Hong Kong',
        'cvm_debit':    NOCVM,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  NOCVM,
        'cvm_threshold': 100000,  # HKD 1000.00
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'HK: HSBC HK, Hang Seng. NoCVM below HKD 1000.',
    },

    # ── JAPAN ─────────────────────────────────────────────────
    '0392': {
        'country':      'Japan',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'JP: JCB, MUFG. SIG always. IAD skip.',
    },

    # ── SOUTH KOREA ───────────────────────────────────────────
    '0410': {
        'country':      'South Korea',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'KR: Shinhan, KB Kookmin. SIG always.',
    },

    # ── CHINA ─────────────────────────────────────────────────
    '0156': {
        'country':      'China',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'CN: UnionPay proprietary IAD. SIG always.',
    },

    # ── INDIA ─────────────────────────────────────────────────
    '0356': {
        'country':      'India',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'IN: SBI, HDFC, ICICI. SIG always.',
    },

    # ── UNITED ARAB EMIRATES ──────────────────────────────────
    '0784': {
        'country':      'United Arab Emirates',
        'cvm_debit':    SIG,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 30000,   # AED 300.00 -- credit NoCVM below
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'AE: Emirates NBD, FAB. Credit NoCVM below AED 300.',
    },

    # ── SOUTH AFRICA ──────────────────────────────────────────
    '0710': {
        'country':      'South Africa',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'ZA: ABSA, Standard Bank, FNB. SIG always.',
    },

    # ── BRAZIL ────────────────────────────────────────────────
    '0076': {
        'country':      'Brazil',
        'cvm_debit':    SIG,
        'cvm_credit':   SIG,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 0,
        'iad_patch':    False,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'BR: Itau, Bradesco, Nubank. SIG always.',
    },

    # ── MEXICO ────────────────────────────────────────────────
    '0484': {
        'country':      'Mexico',
        'cvm_debit':    SIG,
        'cvm_credit':   NOCVM,
        'cvm_business': SIG,
        'cvm_prepaid':  NOCVM,
        'cvm_default':  SIG,
        'cvm_threshold': 50000,   # MXN 500.00 -- credit NoCVM below
        'iad_patch':    True,
        'tvr_clear_b3': True,
        'floor_max':    True,
        'notes':        'MX: BBVA, Banamex. Credit NoCVM below MXN 500.',
    },
}

# ─────────────────────────────────────────────────────────────
# FALLBACK PROFILE
# ─────────────────────────────────────────────────────────────
_FALLBACK_PROFILE = {
    'country':       'Unknown',
    'cvm_debit':     SIG,
    'cvm_credit':    SIG,
    'cvm_business':  SIG,
    'cvm_prepaid':   NOCVM,
    'cvm_default':   SIG,
    'cvm_threshold': 0,
    'iad_patch':     False,
    'tvr_clear_b3':  True,
    'floor_max':     True,
    'notes':         'Fallback -- SIG always, IAD skipped.',
}

# ─────────────────────────────────────────────────────────────
# AMOUNT PARSER
# 9F02 is 6-byte BCD, e.g. b'\x00\x00\x00\x01\x00\x00' = 10000 minor units
# parse_tlv_flat() returns it as uppercase hex string '000000010000'
# ─────────────────────────────────────────────────────────────
def parse_amount_9f02(amount_hex: str) -> int:
    """
    Convert 9F02 BCD hex string to integer minor currency units.

    9F02 is a 6-byte BCD field. parse_tlv_flat() returns it as an
    uppercase hex string. BCD nibbles are always 0-9, so the hex
    string IS the decimal amount when interpreted as base 10.

      '000000005000' -> 5000   (£50.00 in pence)
      '000000010000' -> 10000  (£100.00 in pence)

    Returns 0 on any failure -- safe fallback that disables threshold
    check. Failure paths are logged at WARNING so silent neutralization
    of issuer threshold logic is visible in operations logs.

    Empty input returns 0 silently (normal pre-capture state, not a bug).
    """
    if not amount_hex:
        return 0
    if len(amount_hex) != 12:
        logger.warning(
            f"[ISSUER] 9F02 wrong length: got {len(amount_hex)} expected 12 "
            f"({amount_hex!r}) -- threshold check skipped"
        )
        return 0
    try:
        return int(amount_hex, 10)
    except ValueError:
        logger.warning(
            f"[ISSUER] 9F02 not valid BCD: {amount_hex} "
            f"-- threshold check skipped"
        )
        return 0

# ─────────────────────────────────────────────────────────────
# PUBLIC LOOKUP API
# ─────────────────────────────────────────────────────────────
class IssuerProfile:
    def __init__(self, data: dict):
        self.country = data.get('country', 'Unknown')
        self.brand = data.get('brand', 'UNKNOWN')
        # Kc is the 16 or 24 byte 3DES key for ARPC/Forge
        kc_hex = data.get('k_c', '00' * 24)
        try:
            self.k_c = bytes.fromhex(kc_hex)
            if len(self.k_c) not in (16, 24):
                raise ValueError("Invalid Kc length")
        except Exception:
            self.k_c = b'\x00' * 24
        
        self.cvm_threshold = data.get('cvm_threshold', 0)
        self.iad_patch = data.get('iad_patch', False)
        self.tvr_clear_b3 = data.get('tvr_clear_b3', True)
        self.floor_max = data.get('floor_max', True)
        self.raw_data = data

def get_issuer_profile(issuer_country_hex: str) -> IssuerProfile:
    """
    Look up profile by 5F28 raw hex from parse_tlv_flat().
    Never raises -- returns a profile object based on _FALLBACK_PROFILE on miss.
    """
    if not issuer_country_hex:
        return IssuerProfile(_FALLBACK_PROFILE)
    key = issuer_country_hex.strip().upper().zfill(4)
    profile_data = ISSUER_PROFILES.get(key, _FALLBACK_PROFILE)
    if profile_data is _FALLBACK_PROFILE:
        logger.debug(f"[ISSUER] 5F28={key} not in table -- fallback")
    else:
        logger.debug(f"[ISSUER] 5F28={key} -> {profile_data['country']}")
    return IssuerProfile(profile_data)

def load_external_profile(bin_str: str) -> Optional[IssuerProfile]:
    """
    Attempts to load a profile from profiles/{bin_str}.json.
    Returns None if not found or malformed.
    """
    profile_path = Path(__file__).parent / "profiles" / f"{bin_str}.json"
    if not profile_path.exists():
        return None
    try:
        data = json.loads(profile_path.read_text(encoding="utf-8"))
        return IssuerProfile(data)
    except Exception as e:
        logger.error(f"[ISSUER] Failed to load external profile {bin_str}: {e}")
        return None

def get_cvm_for_card(issuer_country_hex: str, card_type: str,
                     amount_hex: str = '') -> str:
    """
    Return 9F34 hex for this issuer + card type + transaction amount.
    """
    profile_obj = get_issuer_profile(issuer_country_hex)
    profile = profile_obj.raw_data
    threshold = profile.get('cvm_threshold', 0)
    amount    = parse_amount_9f02(amount_hex) if amount_hex else 0

    # Threshold override: at/above threshold always claim Signature
    if threshold > 0 and amount > 0 and amount >= threshold:
        logger.info(
            f"[ISSUER] 5F28={issuer_country_hex} amount={amount} "
            f">= threshold={threshold} -> SIG override"
        )
        return SIG

    # Below threshold or threshold disabled: use base card-type mapping
    mapping = {
        'Debit Card':    profile['cvm_debit'],
        'Credit Card':   profile['cvm_credit'],
        'Business Card': profile['cvm_business'],
        'Prepaid Card':  profile['cvm_prepaid'],
    }
    result = mapping.get(card_type, profile['cvm_default'])
    logger.info(
        f"[ISSUER] 5F28={issuer_country_hex} card_type={card_type} "
        f"amount={amount} threshold={threshold} -> 9F34={result} "
        f"({profile['country']})"
    )
    return result

def should_patch_iad(issuer_country_hex: str) -> bool:
    return get_issuer_profile(issuer_country_hex).iad_patch

def should_clear_tvr_b3(issuer_country_hex: str) -> bool:
    return get_issuer_profile(issuer_country_hex).tvr_clear_b3

def should_max_floor(issuer_country_hex: str) -> bool:
    return get_issuer_profile(issuer_country_hex).floor_max

def list_countries() -> list:
    return sorted(
        [(k, v['country'], v['cvm_threshold'])
         for k, v in ISSUER_PROFILES.items()],
        key=lambda x: x[1]
    )
