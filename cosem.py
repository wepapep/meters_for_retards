"""
cosem.py — COSEM (Companion Specification for Energy Metering) layer.

Builds the xDLMS/COSEM PDUs that sit inside HDLC I-frame info fields.

Supports:
  - AARQ / AARE   — association setup
      * Logical Name (LN) referencing — modern meters
      * Short Name (SN) referencing   — older meters (incl. L+G ZMD)
      * Authentication: None / Low Level Security (password) / High Level Security
  - GET.request   — LN style (class_id + obis + attribute)
  - GET.response  — parsing for both LN and SN responses
  - SN GET-style read (READ.request, used by SN meters)
  - RLRQ          — graceful release

Reference: DLMS Green Book Edition 9, sections 9 & 10.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum


# ===========================================================================
# Constants
# ===========================================================================

# Referencing styles — what the application context OID encodes
class Referencing(IntEnum):
    LN = 0   # Logical Name (6-byte OBIS)
    SN = 1   # Short Name (2-byte object code)


# Authentication mechanisms (mechanism-id values)
class AuthMech(IntEnum):
    NONE = 0          # public client, no auth
    LOW  = 1          # LLS — password sent in plaintext
    HIGH = 2          # HLS — generic challenge-response (vendor-specific)
    HIGH_MD5  = 3
    HIGH_SHA1 = 4
    HIGH_GMAC = 5
    HIGH_SHA256 = 6
    HIGH_ECDSA  = 7


# Application context OIDs (last byte distinguishes them)
# Base: 2.16.756.5.8.1.X  →  06 07 60 85 74 05 08 01 XX
_OID_PREFIX = bytes([0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01])

_OID_SUFFIX = {
    (Referencing.LN, False): 0x01,   # LN, no ciphering
    (Referencing.LN, True):  0x03,   # LN, ciphered
    (Referencing.SN, False): 0x02,   # SN, no ciphering
    (Referencing.SN, True):  0x04,   # SN, ciphered
}


# Default conformance bitstrings — different services for LN vs SN
# Conformance is a BIT STRING; the wire format is "5F 04 LL <3 bytes>"
# where the 3 bytes encode the conformance bits.
_CONFORMANCE_LN = bytes([0x5F, 0x04, 0x00, 0x00, 0x60, 0x1D])  # get, set, action, selective-access, block-transfer
_CONFORMANCE_SN = bytes([0x5F, 0x04, 0x00, 0x1C, 0x13, 0x20])  # what L+G uses — matches our captures


# Default invoke-id-and-priority byte: priority-high, confirmed, invoke-id=1
DEFAULT_INVOKE_ID = 0xC1


# ===========================================================================
# AARQ — Association Request
# ===========================================================================

def build_aarq(
    referencing:   Referencing = Referencing.SN,
    auth:          AuthMech    = AuthMech.NONE,
    password:      bytes | None = None,
    max_pdu_size:  int = 0,
    dlms_version:  int = 6,
    conformance:   bytes | None = None,
) -> bytes:
    """
    Build an AARQ PDU.

    Args:
        referencing:  LN or SN (default SN, matches L+G ZMD)
        auth:         authentication mechanism (default NONE)
        password:     for LOW / HIGH auth — the password bytes (LLS) or
                      the client-to-server challenge (HLS)
        max_pdu_size: client-max-receive-pdu-size; 0 = "any"
        dlms_version: always 6 in practice
        conformance:  override the default conformance block bytes
                      (full TLV including 5F 04 LL ...)

    Returns:
        Raw AARQ bytes (tag 0x60 ...), ready to put after the LLC header.
    """
    if auth != AuthMech.NONE and password is None:
        raise ValueError(f"auth={auth.name} requires a password/challenge")

    # ---- xDLMS InitiateRequest (will be wrapped in OCTET STRING) ----
    if conformance is None:
        conformance = _CONFORMANCE_LN if referencing == Referencing.LN else _CONFORMANCE_SN

    initiate_request = (
        bytes([
            0x01,        # InitiateRequest tag
            0x00,        # dedicated-key absent
            0x00,        # response-allowed-used absent → default TRUE
            0x00,        # proposed-quality-of-service absent
            dlms_version,
        ])
        + conformance
        + struct.pack(">H", max_pdu_size)
    )

    user_info = (
        bytes([0xBE, len(initiate_request) + 2,  # [30] IMPLICIT
               0x04, len(initiate_request)])     # OCTET STRING tag + length
        + initiate_request
    )

    # ---- protocol-version [0] IMPLICIT BIT STRING ----
    protocol_version = bytes([0x80, 0x02, 0x07, 0x80])

    # ---- application-context-name [1] ----
    ciphered    = False  # ciphering not implemented
    oid         = _OID_PREFIX + bytes([_OID_SUFFIX[(referencing, ciphered)]])
    app_context = bytes([0xA1, len(oid)]) + oid

    # ---- Authentication fields (optional) ----
    auth_fields = b""
    if auth != AuthMech.NONE:
        # sender-acse-requirements [10] — "authentication required" bit
        auth_fields += bytes([0x8A, 0x02, 0x07, 0x80])

        # mechanism-name [11]
        mech_oid = bytes([0x60, 0x85, 0x74, 0x05, 0x08, 0x02]) + bytes([int(auth)])
        auth_fields += bytes([0x8B, len(mech_oid)]) + mech_oid

        # calling-authentication-value [12] — GraphicString tag 0x80
        auth_fields += bytes([0xAC, len(password) + 2, 0x80, len(password)]) + password

    # ---- Assemble ----
    body = protocol_version + app_context + auth_fields + user_info
    return bytes([0x60, len(body)]) + body


# ===========================================================================
# AARE — Association Response
# ===========================================================================

@dataclass
class AssociationResult:
    accepted:              bool
    result:                int
    result_source:         int
    result_diagnostic:     int
    server_max_pdu:        int | None
    negotiated_conformance: bytes | None
    server_challenge:      bytes | None   # for HLS, populated from auth value


def parse_aare(data: bytes) -> AssociationResult:
    """
    Parse an AARE PDU.

    Extracts: result code, server max PDU, negotiated conformance, and
    (for HLS) the server's challenge.

    Raises:
        ValueError: if data isn't an AARE.
    """
    if len(data) < 2 or data[0] != 0x61:
        raise ValueError(f"Not an AARE (expected 0x61, got {data[0]:#04x})")

    body = data[2:2 + data[1]]

    result = 0
    result_source = 0
    result_diagnostic = 0
    server_max_pdu = None
    negotiated_conformance = None
    server_challenge = None

    i = 0
    while i < len(body):
        tag = body[i]
        sub_len = body[i + 1]
        value = body[i + 2:i + 2 + sub_len]

        if tag == 0xA2:                          # [2] result
            if len(value) >= 4:
                result = value[3]

        elif tag == 0xA3:                        # [3] result-source-diagnostic
            if len(value) >= 5:
                result_source     = value[0] & 0x1F
                result_diagnostic = value[4]

        elif tag == 0xAA:                        # [10] responding-AP-title — HLS challenge
            # value usually: 80 LL <challenge bytes>
            if len(value) >= 2 and value[0] == 0x80:
                server_challenge = value[2:2 + value[1]]

        elif tag == 0xBE:                        # [30] user-information
            if len(value) >= 2 and value[0] == 0x04:
                inner = value[2:2 + value[1]]
                if inner and inner[0] == 0x08:  # InitiateResponse
                    j = 1
                    # optional negotiated-quality-of-service
                    if j < len(inner) and inner[j] != 0x06:
                        j += 1
                    j += 1  # dlms-version
                    if j + 6 <= len(inner) and inner[j] == 0x5F:
                        negotiated_conformance = inner[j:j + 6]
                        j += 6
                    if j + 2 <= len(inner):
                        server_max_pdu = int.from_bytes(inner[j:j + 2], "big")

        i += 2 + sub_len

    return AssociationResult(
        accepted=(result == 0),
        result=result,
        result_source=result_source,
        result_diagnostic=result_diagnostic,
        server_max_pdu=server_max_pdu,
        negotiated_conformance=negotiated_conformance,
        server_challenge=server_challenge,
    )


# ===========================================================================
# RLRQ — Release Request (graceful disconnect at COSEM level)
# ===========================================================================

def build_rlrq() -> bytes:
    """
    Build a minimal RLRQ PDU.

    Most meters tolerate not sending this — the HDLC DISC alone closes the
    session — but it's the polite way to release a COSEM association.
    """
    return bytes([0x62, 0x03, 0x80, 0x01, 0x00])


# ===========================================================================
# GET — Logical Name (LN) referencing
# ===========================================================================

def build_get_request_ln(
    class_id:   int,
    obis:       bytes,
    attribute:  int = 2,
    invoke_id:  int = DEFAULT_INVOKE_ID,
) -> bytes:
    """
    Build a GET-Request-Normal PDU (LN referencing).

        Layout: C0 01 IP CC CC OO OO OO OO OO OO AA SS
            C0           GET.request tag
            01           request-type = normal
            IP           invoke-id-and-priority
            CC CC        class-id (big-endian)
            OO * 6       OBIS code
            AA           attribute index (signed byte)
            SS           access-selection (00 = none)
    """
    if len(obis) != 6:
        raise ValueError(f"OBIS must be 6 bytes, got {len(obis)}")

    return (
        bytes([0xC0, 0x01, invoke_id])
        + struct.pack(">H", class_id)
        + obis
        + bytes([attribute & 0xFF, 0x00])
    )


# ===========================================================================
# GET — Short Name (SN) referencing
# ===========================================================================
#
# SN meters use a different service: READ.request (tag 0x05) carrying a
# variable-access-specification with a 2-byte short-name. This matches
# what the L+G ZMD captures showed.
#

def build_read_request_sn(short_name: int, parameter_count_index: int = 0) -> bytes:
    """
    Build a READ.request PDU using a single Short Name reference.

        Layout: 05 01 02 NN NN
            05       READ.request tag
            01       count of items (1)
            02       variable-access tag: "variable-name"
            NN NN    short-name (16-bit, big-endian)

    Note: this is equivalent to lg_short.build_read_request(); we keep
    a copy here so the function lives in the standards-aware layer rather
    than the vendor module. Vendors can still use this directly.
    """
    if not 0 <= short_name <= 0xFFFF:
        raise ValueError(f"short_name out of range: {short_name:#06x}")
    return bytes([0x05, 0x01, 0x02]) + short_name.to_bytes(2, "big")


# ===========================================================================
# GET.response parsing
# ===========================================================================

@dataclass
class GetResponse:
    invoke_id: int
    success:   bool
    data:      bytes        # raw value bytes if success
    error:     int | None   # data-access-error code if failure


def parse_get_response(data: bytes) -> GetResponse:
    """
    Parse a GET-Response-Normal PDU (LN reference).

        Layout: C4 01 IP CHOICE DATA...
            C4           GET.response tag
            01           response-type = normal
            IP           invoke-id-and-priority
            CHOICE:
              00 ...   → data (success)
              01 EE    → data-access-error (1-byte code)
    """
    if len(data) < 4:
        raise ValueError(f"GET.response too short: {data.hex()}")
    if data[0] != 0xC4:
        raise ValueError(f"Not a GET.response (expected 0xC4, got {data[0]:#04x})")
    if data[1] != 0x01:
        raise ValueError(f"Only GET-Response-Normal supported, got {data[1]:#04x}")

    invoke_id = data[2]
    choice    = data[3]

    if choice == 0x00:
        return GetResponse(invoke_id=invoke_id, success=True, data=data[4:], error=None)
    if choice == 0x01:
        if len(data) < 5:
            raise ValueError(f"Malformed error response: {data.hex()}")
        return GetResponse(invoke_id=invoke_id, success=False, data=b"", error=data[4])

    raise ValueError(f"Unknown GET.response choice: {choice:#04x}")


def parse_read_response_sn(data: bytes) -> list:
    """
    Parse a READ.response (SN reference) — used by L+G ZMD-style meters.

        Layout: 0C SC ST <data>...
            0C           READ.response tag
            SC           count of items
            ST           status for item (00 = success)
            <data>...    DLMS-tagged value(s)

    Returns a list of result dicts: [{ "success": bool, "status": int, "data": bytes }, ...]
    Vendors layer additional parsing on top (e.g. lg_short.parse_read_response).
    """
    if len(data) < 3 or data[0] != 0x0C:
        raise ValueError(f"Not a READ.response (expected 0x0C, got {data[:1].hex()})")

    count = data[1]
    # The exact framing for count > 1 varies by vendor — keep this generic and
    # return the body for further per-vendor parsing.
    return [{
        "count":  count,
        "body":   data[2:],
    }]
