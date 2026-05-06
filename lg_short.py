"""
lg_short.py — Landis+Gyr proprietary "short" protocol used on ZMD-series
meters over HDLC.

This predates / coexists with standard DLMS/COSEM and uses compact
2-byte object codes (e.g. 0xC1C8 = device ID 1) instead of 6-byte OBIS
codes. Frames are wrapped in the same HDLC I-frame / LLC envelope as
standard COSEM — only the PDU content differs.

Protocol layout (confirmed against captured frames):

  REQUEST (client → meter):
    Subtype 0x01 — read by short object code:
        05 01 02 OO OO                        (5 bytes)
                 └─┴─ 16-bit object code

    Subtype 0x02 — multi-read with extended addresses:
        05 02 02 AA AA AA AA AA ...           (variable)
        Each address is 2 bytes (e.g. FD 08, FF 08).

  RESPONSE (meter → client):
    0C SS ST DATA...
    │  │  │  └── DLMS-tagged data item(s)
    │  │  └──── status (0x00 = success)
    │  └─────── subtype (matches request)
    └────────── response tag

  DLMS data item tags observed:
    0x09 LL ...   OCTET STRING, length LL
    0x0A LL ...   VISIBLE STRING, length LL
"""

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TAG_REQUEST   = 0x05
TAG_RESPONSE  = 0x0C

SUBTYPE_READ_SHORT = 0x01
SUBTYPE_READ_EXT   = 0x02
ATTR_VALUE         = 0x02    # observed — always 0x02 in practice

STATUS_SUCCESS = 0x00

# DLMS data type tags
DTYPE_OCTET_STRING   = 0x09
DTYPE_VISIBLE_STRING = 0x0A


# ---------------------------------------------------------------------------
# Known object codes (ZMD-series). Curated from observed captures.
# ---------------------------------------------------------------------------

OBJECTS: dict[str, int] = {
    "device_id_1":            0xC1C8,   # 19-byte config string (meaning TBD)
    "serial_number":          0x5A88,   # Serial as VISIBLE STRING e.g. "51282380"
    "device_identification":  0x3848,   # Firmware/model string
}

# Multi-read extended addresses (subtype 0x02)
EXT_ADDRESSES: dict[str, bytes] = {
    "manufacturer_and_serial": bytes.fromhex("FD08"),  # e.g. "LGZ51282380"
    "meter_type_code":         bytes.fromhex("FF08"),  # e.g. "B32"
}


# ---------------------------------------------------------------------------
# Request building
# ---------------------------------------------------------------------------

def build_read_request(obj_code: int, attribute: int = ATTR_VALUE) -> bytes:
    """
    Build a short-code read request (subtype 0x01).

    Layout:   05 01 AA OO OO
    """
    if not 0 <= obj_code <= 0xFFFF:
        raise ValueError(f"obj_code out of range: {obj_code:#06x}")
    if not 0 <= attribute <= 0xFF:
        raise ValueError(f"attribute out of range: {attribute}")

    return bytes([
        TAG_REQUEST,
        SUBTYPE_READ_SHORT,
        attribute,
        (obj_code >> 8) & 0xFF,
        obj_code & 0xFF,
    ])


def build_read_request_by_name(name: str, attribute: int = ATTR_VALUE) -> bytes:
    """Build a request using a known object name from OBJECTS."""
    if name not in OBJECTS:
        raise KeyError(f"Unknown object '{name}'. Known: {sorted(OBJECTS)}")
    return build_read_request(OBJECTS[name], attribute)


def build_multi_read_request(addresses: list[bytes], attribute: int = ATTR_VALUE) -> bytes:
    """
    Build an extended multi-read request (subtype 0x02).

    Layout:   05 02 [AA <addr1>] [AA <addr2>] ...
    where each item is (attribute, address) — the attribute is repeated
    for every address, not just stated once at the start.

    Example: reading FD08 and FF08 with attribute=0x02 →
        05 02 02 FD 08 02 FF 08
    """
    if not addresses:
        raise ValueError("at least one address required")

    pairs = b"".join(bytes([attribute]) + addr for addr in addresses)
    return bytes([TAG_REQUEST, SUBTYPE_READ_EXT]) + pairs


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

@dataclass
class ReadResponse:
    """A single-item read response."""
    success:   bool
    status:    int          # 0 = success
    data_type: int | None   # DLMS data type tag (0x09, 0x0A, ...)
    value:     bytes        # raw value bytes

    def as_octet_string(self) -> bytes:
        """Return the value as raw bytes (works for any data type)."""
        return self.value

    def as_visible_string(self) -> str:
        """Decode the value as ASCII, stripping trailing zero padding."""
        return self.value.rstrip(b"\x00").decode("ascii", errors="replace")


def parse_read_response(data: bytes) -> ReadResponse:
    """
    Parse a subtype-0x01 (single short-code) read response.

    Layout:  0C 01 SS DT LL VV...VV
    """
    if len(data) < 3:
        raise ValueError(f"Response too short: {data.hex()}")
    if data[0] != TAG_RESPONSE:
        raise ValueError(f"Not a read response (expected 0x0C, got {data[0]:#04x})")

    subtype = data[1]
    if subtype != SUBTYPE_READ_SHORT:
        raise ValueError(f"Use parse_multi_read_response() for subtype 0x{subtype:02X}")

    status = data[2]
    if status != STATUS_SUCCESS:
        return ReadResponse(success=False, status=status, data_type=None, value=b"")

    if len(data) < 5:
        raise ValueError(f"Success response missing data type/length: {data.hex()}")

    dtype = data[3]
    dlen  = data[4]
    value = data[5:5 + dlen]
    if len(value) != dlen:
        raise ValueError(
            f"Truncated value: expected {dlen} bytes, got {len(value)}: {data.hex()}"
        )

    return ReadResponse(success=True, status=status, data_type=dtype, value=value)


def parse_multi_read_response(data: bytes) -> list[ReadResponse]:
    """
    Parse a subtype-0x02 (multi-read) response.

    NOTE: the exact framing of multiple items is not fully confirmed.
    This is best-effort: assumes DLMS-tagged (type, length, value) items,
    possibly separated by zero bytes.
    """
    if len(data) < 3:
        raise ValueError(f"Response too short: {data.hex()}")
    if data[0] != TAG_RESPONSE or data[1] != SUBTYPE_READ_EXT:
        raise ValueError(f"Not a multi-read response: {data.hex()}")

    status = data[2]
    items  = []

    i = 3
    while i < len(data):
        while i < len(data) and data[i] == 0x00:
            i += 1
        if i >= len(data):
            break

        dtype = data[i]
        dlen  = data[i + 1]
        value = data[i + 2:i + 2 + dlen]
        items.append(ReadResponse(
            success=True, status=status, data_type=dtype, value=value
        ))
        i += 2 + dlen

    return items


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def describe_object(obj_code: int) -> str:
    """Return the known name of an object code, or a hex fallback."""
    for name, code in OBJECTS.items():
        if code == obj_code:
            return name
    return f"0x{obj_code:04X}"
