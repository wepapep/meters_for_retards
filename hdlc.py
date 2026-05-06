"""
hdlc.py — HDLC framing for DLMS/COSEM communication with Landis+Gyr meters.

Supports:
- 2-byte server (meter) address derived from serial number
- 1-byte client address (0x21, public client)
- SNRM frame construction (connection establishment)
- UA response parsing (connection acknowledgement)
- FCS-16 checksum (CRC-16/IBM as per IEC 13239)
"""

import struct

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HDLC_FLAG = 0x7E          # Frame delimiter
HDLC_CLIENT_ADDR = 0x21   # Public client address (self-terminating, LSB=1)
FRAME_TYPE_SNRM = 0x93    # Set Normal Response Mode (P/F bit set)
FRAME_TYPE_UA   = 0x73    # Unnumbered Acknowledgement (P/F bit set)
FRAME_TYPE_DISC = 0x53    # Disconnect (P/F bit set)
FRAME_FORMAT_BASE = 0xA000  # Frame format: type 3, no segmentation

# LLC headers (inserted before COSEM PDU inside an I-frame info field)
LLC_CLIENT_TO_SERVER = bytes([0xE6, 0xE6, 0x00])
LLC_SERVER_TO_CLIENT = bytes([0xE6, 0xE7, 0x00])


# ---------------------------------------------------------------------------
# CRC-16/IBM  (polynomial 0x8005, reflected — standard for HDLC)
# ---------------------------------------------------------------------------

def _make_crc_table() -> list[int]:
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408  # reflected 0x8005
            else:
                crc >>= 1
        table.append(crc)
    return table

_CRC_TABLE = _make_crc_table()


def fcs16(data: bytes) -> int:
    """Compute FCS-16 checksum over *data*. Returns 16-bit integer."""
    crc = 0xFFFF
    for byte in data:
        crc = (crc >> 8) ^ _CRC_TABLE[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFF


# ---------------------------------------------------------------------------
# Address encoding
# ---------------------------------------------------------------------------

def _encode_14bit(value: int, last: bool) -> bytes:
    """
    Encode a 14-bit integer as 2 HDLC address bytes (7 usable bits each).

    LSB of each byte is the continuation flag:
      0 = more address bytes follow
      1 = this is the last byte
    """
    high = ((value >> 7) & 0x7F) << 1          # upper 7 bits, LSB=0 always
    low  = ((value & 0x7F) << 1) | (0x01 if last else 0x00)
    return bytes([high, low])


def encode_server_address(serial: int, umac: int = 1) -> bytes:
    """
    Derive and encode the 4-byte HDLC server address from a meter serial number.

    The 4-byte address is split into two 2-byte halves:
      UMAC (upper MAC) — network/group identifier, default 1 (encodes to 00 02 on wire)
      LMAC (lower MAC) — derived from serial: (serial % 10000) + 1000

    Each half is encoded using 7 usable bits per byte with the LSB as a
    continuation flag (0 = more bytes follow, 1 = last byte).

    Args:
        serial: 8-digit meter serial number (e.g. 12345678)
        umac:   Upper MAC address, default 0x0002. Override if your site
                uses a different value.

    Returns:
        4-byte HDLC-encoded address.

    Raises:
        ValueError: if either UMAC or LMAC exceeds 14 bits.
    """
    lmac = (serial % 10000) + 1000  # range: 1000–10999

    if umac > 0x3FFF:
        raise ValueError(f"UMAC {umac:#06x} exceeds 14-bit HDLC limit")
    if lmac > 0x3FFF:
        raise ValueError(f"LMAC {lmac} exceeds 14-bit HDLC limit")

    return _encode_14bit(umac, last=False) + _encode_14bit(lmac, last=True)


def encode_client_address() -> bytes:
    """
    Return the encoded 1-byte HDLC client address.

    0x21 has LSB=1, so it is already self-terminating — no further encoding
    needed.
    """
    return bytes([HDLC_CLIENT_ADDR])


# ---------------------------------------------------------------------------
# Frame construction
# ---------------------------------------------------------------------------

def _build_frame(dst: bytes, src: bytes, control: int, info: bytes = b"") -> bytes:
    """
    Build a complete HDLC frame.

    Structure (with info):
        7E | frame_format (2) | dst | src | control | HCS (2) | info | FCS (2) | 7E

    Structure (without info):
        7E | frame_format (2) | dst | src | control | FCS (2) | 7E

    When there is no info field, HCS is omitted — the FCS covers the header
    directly. This matches the HDLC spec (ISO/IEC 13239) and is required for
    frames like DISC, UA with no info, and RR.
    """
    has_info   = len(info) > 0
    header_len = 2 + len(dst) + len(src) + 1
    hcs_len    = 2 if has_info else 0
    fcs_len    = 2

    frame_length = header_len + hcs_len + len(info) + fcs_len
    frame_format = FRAME_FORMAT_BASE | frame_length
    ff_bytes     = struct.pack(">H", frame_format)

    header = ff_bytes + dst + src + bytes([control])

    if has_info:
        hcs     = struct.pack("<H", fcs16(header))
        payload = header + hcs + info
    else:
        payload = header

    fcs = struct.pack("<H", fcs16(payload))
    return bytes([HDLC_FLAG]) + payload + fcs + bytes([HDLC_FLAG])


def _build_snrm_info(
    max_rx_size: int = 0x05DC,
    max_tx_size: int = 0x05DC,
    max_rx_window: int = 1,
    max_tx_window: int = 1,
) -> bytes:
    """
    Build the SNRM negotiation parameter payload (user info field).

    Parameters are encoded as TLV (tag, length, value):
      Tag 0x05 — max receive information length (2 bytes)
      Tag 0x06 — max transmit information length (2 bytes)
      Tag 0x07 — max receive window size (4 bytes)
      Tag 0x08 — max transmit window size (4 bytes)

    Wrapped in an outer TLV: tag 0x81, sub-tag 0x80.
    """
    params = (
        bytes([0x05, 0x02]) + struct.pack(">H", max_rx_size)   +
        bytes([0x06, 0x02]) + struct.pack(">H", max_tx_size)   +
        bytes([0x07, 0x04]) + struct.pack(">I", max_rx_window) +
        bytes([0x08, 0x04]) + struct.pack(">I", max_tx_window)
    )
    return bytes([0x81, 0x80, len(params)]) + params


def build_snrm_frame(
    serial: int,
    umac: int = 1,
    max_rx_size: int = 0x05DC,
    max_tx_size: int = 0x05DC,
    max_rx_window: int = 1,
    max_tx_window: int = 1,
) -> bytes:
    """
    Build an HDLC SNRM frame to initiate a connection with a meter.

    SNRM (Set Normal Response Mode) is the first frame sent to a meter.
    A successful meter response is a UA (Unnumbered Acknowledgement) frame.

    The frame includes negotiation parameters (max frame sizes and window sizes)
    which must match what the meter expects. Defaults match observed L+G captures:
    1500 byte frame size, window size 1.

    Args:
        serial:         8-digit meter serial number.
        umac:           Upper MAC address, default 1 (encodes to 00 02 on wire).
        max_rx_size:    Max receive frame size in bytes, default 1500.
        max_tx_size:    Max transmit frame size in bytes, default 1500.
        max_rx_window:  Max receive window size, default 1.
        max_tx_window:  Max transmit window size, default 1.

    Returns:
        Raw bytes ready to send over TCP to the serial device server.
    """
    dst  = encode_server_address(serial, umac=umac)
    src  = encode_client_address()
    info = _build_snrm_info(max_rx_size, max_tx_size, max_rx_window, max_tx_window)
    return _build_frame(dst=dst, src=src, control=FRAME_TYPE_SNRM, info=info)


# ---------------------------------------------------------------------------
# Frame parsing
# ---------------------------------------------------------------------------

def parse_ua_response(data: bytes) -> bool:
    """
    Validate that *data* is a well-formed UA (Unnumbered Acknowledgement) frame.

    Checks:
    - Opens and closes with HDLC flag (0x7E)
    - Control byte is UA (0x73)
    - FCS is valid

    Args:
        data: Raw bytes received from the meter.

    Returns:
        True if the frame is a valid UA response, False otherwise.
    """
    if len(data) < 8:
        return False
    if data[0] != HDLC_FLAG or data[-1] != HDLC_FLAG:
        return False

    inner = data[1:-1]  # strip flags

    # FCS covers everything except the trailing FCS bytes themselves
    payload  = inner[:-2]
    received_fcs = struct.unpack("<H", inner[-2:])[0]
    if fcs16(payload) != received_fcs:
        return False

    # Locate control byte: skip frame_format (2 bytes) + dst + src
    # We need to scan past variable-length dst/src addresses
    offset = 2  # skip frame format
    # skip dst (read until LSB=1)
    while offset < len(payload):
        b = payload[offset]
        offset += 1
        if b & 0x01:
            break
    # skip src (read until LSB=1)
    while offset < len(payload):
        b = payload[offset]
        offset += 1
        if b & 0x01:
            break

    if offset >= len(payload):
        return False

    control = payload[offset]
    # Mask out P/F bit (bit 4) for comparison
    return (control & ~0x10) == (FRAME_TYPE_UA & ~0x10)


# ---------------------------------------------------------------------------
# I-frames (Information frames) — carry COSEM PDUs
# ---------------------------------------------------------------------------

def build_iframe_control(ns: int, nr: int, pf: bool = True) -> int:
    """
    Build an I-frame control byte.

        Bit:    7 6 5   4   3 2 1   0
                N(R)    P/F N(S)     0 = I-frame

    Args:
        ns:  send sequence number (0-7)
        nr:  receive sequence number (0-7)
        pf:  P/F bit; True when expecting a response (default)

    Returns:
        Control byte as int.
    """
    if not 0 <= ns <= 7:
        raise ValueError(f"N(S) out of range: {ns}")
    if not 0 <= nr <= 7:
        raise ValueError(f"N(R) out of range: {nr}")
    return ((nr & 0x07) << 5) | (0x10 if pf else 0x00) | ((ns & 0x07) << 1)


def parse_iframe_control(control: int) -> tuple[int, int, bool] | None:
    """
    Parse an I-frame control byte.

    Returns:
        (ns, nr, pf) tuple if this is an I-frame, None otherwise.
    """
    if control & 0x01:  # LSB must be 0 for I-frames
        return None
    ns = (control >> 1) & 0x07
    nr = (control >> 5) & 0x07
    pf = bool(control & 0x10)
    return ns, nr, pf


def build_iframe(
    serial: int,
    ns: int,
    nr: int,
    info: bytes,
    umac: int = 1,
    pf: bool = True,
    include_llc: bool = True,
) -> bytes:
    """
    Build an HDLC I-frame carrying a COSEM PDU.

    The COSEM PDU is prefixed with the LLC header (E6 E6 00) unless
    include_llc=False (caller provides the full info field themselves).

    Args:
        serial:      meter serial number
        ns:          send sequence number
        nr:          receive sequence number
        info:        COSEM PDU bytes
        umac:        upper MAC, default 1
        pf:          P/F bit, default True (expecting response)
        include_llc: prepend LLC header, default True

    Returns:
        Raw HDLC frame bytes.
    """
    dst     = encode_server_address(serial, umac=umac)
    src     = encode_client_address()
    control = build_iframe_control(ns=ns, nr=nr, pf=pf)

    payload = (LLC_CLIENT_TO_SERVER + info) if include_llc else info
    return _build_frame(dst=dst, src=src, control=control, info=payload)


def parse_iframe(data: bytes) -> dict | None:
    """
    Parse an HDLC I-frame received from a meter.

    Validates the flags and FCS, then extracts the control byte and info
    payload. If the info payload begins with the server→client LLC header
    (E6 E7 00), it is stripped.

    Args:
        data: raw bytes including opening and closing 0x7E flags.

    Returns:
        {
          "ns":      int,   # N(S) from the meter
          "nr":      int,   # N(R) from the meter
          "pf":      bool,
          "info":    bytes, # COSEM PDU (LLC header stripped if present)
          "has_llc": bool,
        }
        or None if the frame is malformed or not an I-frame.
    """
    if len(data) < 8 or data[0] != HDLC_FLAG or data[-1] != HDLC_FLAG:
        return None

    inner   = data[1:-1]
    payload = inner[:-2]
    received_fcs = struct.unpack("<H", inner[-2:])[0]
    if fcs16(payload) != received_fcs:
        return None

    # Skip frame format (2) + dst (variable) + src (variable) → control byte
    offset = 2
    while offset < len(payload) and not (payload[offset] & 0x01):
        offset += 1
    offset += 1  # consume the last dst byte (LSB=1)
    while offset < len(payload) and not (payload[offset] & 0x01):
        offset += 1
    offset += 1  # consume the last src byte

    if offset >= len(payload):
        return None

    control = payload[offset]
    parsed  = parse_iframe_control(control)
    if parsed is None:
        return None
    ns, nr, pf = parsed

    # Skip HCS (2 bytes) to reach info field
    info_start = offset + 1 + 2
    info_end   = len(payload)  # FCS is already stripped above
    info       = payload[info_start:info_end]

    has_llc = info.startswith(LLC_SERVER_TO_CLIENT) or info.startswith(LLC_CLIENT_TO_SERVER)
    if info.startswith(LLC_SERVER_TO_CLIENT):
        info = info[len(LLC_SERVER_TO_CLIENT):]
    elif info.startswith(LLC_CLIENT_TO_SERVER):
        info = info[len(LLC_CLIENT_TO_SERVER):]

    return {
        "ns": ns,
        "nr": nr,
        "pf": pf,
        "info": info,
        "has_llc": has_llc,
    }


# ---------------------------------------------------------------------------
# DISC frame (disconnect)
# ---------------------------------------------------------------------------

def build_disc_frame(serial: int, umac: int = 1) -> bytes:
    """
    Build an HDLC DISC frame to close a session.

    The meter responds with UA.
    """
    dst = encode_server_address(serial, umac=umac)
    src = encode_client_address()
    return _build_frame(dst=dst, src=src, control=FRAME_TYPE_DISC)
