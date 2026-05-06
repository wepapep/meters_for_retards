"""
cosem.py — COSEM (Companion Specification for Energy Metering) layer.

Builds the xDLMS/COSEM PDUs that sit inside HDLC I-frame info fields:
  - AARQ (association request)  / AARE (association response)
  - GET.request                  / GET.response
  - RLRQ (release request)       / RLRE (release response) — later

The public-client, no-auth profile is targeted, matching the observed
Landis+Gyr capture.
"""

import struct


# ---------------------------------------------------------------------------
# AARQ / AARE
# ---------------------------------------------------------------------------

# Application context OID: 2.16.756.5.8.1.2  →  BER-encoded
# = LN referencing, no ciphering
# Kept as raw bytes since only this one is used with the public client.
_APP_CONTEXT_OID_LN_NO_CIPHER = bytes([
    0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x02
])

# Conformance bitstring: which DLMS services the client advertises as supported.
# 00 1C 13 20 matches the observed L+G client — includes get, set, action,
# selective-access, and block-transfer-for-get.
_CONFORMANCE_BLOCK = bytes([0x5F, 0x04, 0x00, 0x1C, 0x13, 0x20])


def build_aarq(
    max_pdu_size: int = 0,
    dlms_version: int = 6,
) -> bytes:
    """
    Build an AARQ (Association Request) PDU for the public/no-auth client.

    Args:
        max_pdu_size: client-max-receive-pdu-size; 0 means "any size accepted".
        dlms_version: proposed DLMS version (always 6 in practice).

    Returns:
        Raw AARQ bytes, to be placed in the info field of an I-frame
        (after the LLC header).
    """
    # xDLMS InitiateRequest (will be wrapped in an OCTET STRING under
    # user-information)
    initiate_request = bytes([
        0x01,  # InitiateRequest tag
        0x00,  # dedicated-key absent
        0x00,  # response-allowed-used absent → default TRUE
        0x00,  # proposed-quality-of-service absent
        dlms_version,
    ]) + _CONFORMANCE_BLOCK + struct.pack(">H", max_pdu_size)

    # user-information [30] — wraps the InitiateRequest in an OCTET STRING
    user_info = (
        bytes([0xBE, len(initiate_request) + 2,  # [30] IMPLICIT
               0x04, len(initiate_request)])     # OCTET STRING tag
        + initiate_request
    )

    # protocol-version [0] IMPLICIT BIT STRING (version 1)
    protocol_version = bytes([0x80, 0x02, 0x07, 0x80])

    # application-context-name [1]
    app_context = bytes([0xA1, len(_APP_CONTEXT_OID_LN_NO_CIPHER)]) + _APP_CONTEXT_OID_LN_NO_CIPHER

    body = protocol_version + app_context + user_info

    # AARQ tag 0x60 + length
    return bytes([0x60, len(body)]) + body


def parse_aare(data: bytes) -> dict:
    """
    Parse an AARE (Association Response) PDU.

    Only the fields needed to confirm "association accepted" are extracted.
    Ciphering/auth fields are ignored since we don't use them.

    Args:
        data: AARE bytes (tag 0x61 onward).

    Returns:
        {
          "result":            int,   # 0 = accepted
          "result_source":     int,   # 0 = ACSE, 1 = xDLMS
          "result_diagnostic": int,
          "server_max_pdu":    int | None,
          "negotiated_conformance": bytes | None,
        }

    Raises:
        ValueError: if the data isn't an AARE or is malformed.
    """
    if len(data) < 2 or data[0] != 0x61:
        raise ValueError(f"Not an AARE (expected tag 0x61, got {data[0]:#04x})")

    length = data[1]
    body   = data[2:2 + length]

    result = 0
    result_source = 0
    result_diagnostic = 0
    server_max_pdu = None
    negotiated_conformance = None

    i = 0
    while i < len(body):
        tag = body[i]
        sub_len = body[i + 1]
        value = body[i + 2:i + 2 + sub_len]

        if tag == 0xA2:  # [2] result
            # value = 03 02 01 RR  (INTEGER, length 1, value RR)
            if len(value) >= 4:
                result = value[3]

        elif tag == 0xA3:  # [3] result-source-diagnostic
            # value = XX LL YY LL RR  — nested CHOICE
            if len(value) >= 5:
                result_source     = value[0] & 0x1F  # [0] ACSE / [1] xDLMS
                result_diagnostic = value[4]

        elif tag == 0xBE:  # [30] user-information
            # Contains InitiateResponse or ConfirmedServiceError inside an OCTET STRING
            if len(value) >= 2 and value[0] == 0x04:
                inner = value[2:2 + value[1]]
                if inner and inner[0] == 0x08:  # InitiateResponse tag
                    # Skip: negotiated-quality-of-service (1 byte, optional)
                    #       negotiated-dlms-version (1 byte)
                    #       negotiated-conformance (6 bytes: 5F 04 LL XX XX XX)
                    #       server-max-receive-pdu-size (2 bytes)
                    #       VAA-name (2 bytes)
                    j = 1
                    # optional quality-of-service indicator (0x00 or value)
                    if j < len(inner) and inner[j] != 0x06:  # if not the dlms-version yet
                        j += 1
                    j += 1  # dlms-version
                    if j + 6 <= len(inner) and inner[j] == 0x5F:
                        negotiated_conformance = inner[j:j + 6]
                        j += 6
                    if j + 2 <= len(inner):
                        server_max_pdu = int.from_bytes(inner[j:j + 2], "big")

        i += 2 + sub_len

    return {
        "result": result,
        "result_source": result_source,
        "result_diagnostic": result_diagnostic,
        "server_max_pdu": server_max_pdu,
        "negotiated_conformance": negotiated_conformance,
    }


# ---------------------------------------------------------------------------
# GET.request / GET.response
# ---------------------------------------------------------------------------

# Invoke-id-and-priority: bit 7 = priority, bit 6 = service-class (1=confirmed),
# bits 0-3 = invoke-id. 0xC1 = priority-high + confirmed + invoke-id 1.
DEFAULT_INVOKE_ID = 0xC1


def build_get_request_normal(
    class_id: int,
    obis: bytes,
    attribute: int,
    invoke_id: int = DEFAULT_INVOKE_ID,
) -> bytes:
    """
    Build a GET-Request-Normal PDU to read one attribute of one COSEM object.

        GET.request  tag = 0xC0
        · request-type = 0x01 (normal)
        · invoke-id-and-priority
        · cosem-attribute-descriptor:
            class-id              (2 bytes, big-endian)
            instance-id (OBIS)    (6 bytes)
            attribute-index       (1 byte, signed)
            access-selection      (1 byte, 0x00 = none)

    Args:
        class_id:  COSEM interface class ID (e.g. 1 for "Data").
        obis:      6-byte OBIS code.
        attribute: attribute index to read (2 = value for most classes).
        invoke_id: invoke-id-and-priority byte.

    Returns:
        Raw GET.request bytes.
    """
    if len(obis) != 6:
        raise ValueError(f"OBIS must be 6 bytes, got {len(obis)}")

    return (
        bytes([0xC0, 0x01, invoke_id])
        + struct.pack(">H", class_id)
        + obis
        + bytes([attribute & 0xFF, 0x00])
    )


def parse_get_response(data: bytes) -> dict:
    """
    Parse a GET-Response PDU.

    Handles only GET-Response-Normal (the common case). Block-transfer
    responses can be added later if large data is needed.

        GET.response tag = 0xC4
        · response-type = 0x01 (normal)
        · invoke-id-and-priority
        · result: CHOICE
            [0] data              → raw attribute value
            [1] data-access-error → 1-byte error code

    Args:
        data: GET.response bytes.

    Returns:
        {
          "invoke_id": int,
          "success":   bool,
          "data":      bytes | None,   # raw attribute value if success
          "error":     int   | None,   # data-access-error code if failure
        }

    Raises:
        ValueError: on malformed or unsupported responses.
    """
    if len(data) < 4:
        raise ValueError(f"GET.response too short: {data.hex()}")
    if data[0] != 0xC4:
        raise ValueError(f"Not a GET.response (expected 0xC4, got {data[0]:#04x})")
    if data[1] != 0x01:
        raise ValueError(f"Only GET-Response-Normal (0x01) supported, got {data[1]:#04x}")

    invoke_id = data[2]
    choice    = data[3]

    if choice == 0x00:
        return {
            "invoke_id": invoke_id,
            "success":   True,
            "data":      data[4:],
            "error":     None,
        }
    elif choice == 0x01:
        if len(data) < 5:
            raise ValueError(f"Malformed GET.response error: {data.hex()}")
        return {
            "invoke_id": invoke_id,
            "success":   False,
            "data":      None,
            "error":     data[4],
        }
    else:
        raise ValueError(f"Unknown GET.response choice: {choice:#04x}")
