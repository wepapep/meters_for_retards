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


# ===========================================================================
# Convenience subclass — wires up SN referencing and named object lookup
# ===========================================================================

from ..meter import Meter as _BaseMeter
from ..cosem import Referencing as _Referencing


class LandisGyrZMD(_BaseMeter):
    """
    Convenience subclass for L+G ZMD-series meters.

    Defaults to Short Name referencing and exposes a name-based read()
    that looks up the underlying object code:

        with LandisGyrZMD.over_tcp(host, port, serial) as m:
            print(m.read("serial_number"))           # → '51282380'
            print(m.read("device_identification"))   # → 'B.M4CCPTSCMDO...'
            print(m.read(0xC1C8))                    # raw int input also OK
    """

    def __init__(self, *args, **kwargs):
        # Force SN referencing for ZMD meters
        kwargs.setdefault("referencing", _Referencing.SN)
        super().__init__(*args, **kwargs)

    def read(self, target):
        """
        Read by friendly name or 2-byte object code.

        - "serial_number" → looks up 0x5A88, reads it, decodes the value
        - 0xC1C8          → reads that short name directly
        """
        if isinstance(target, str):
            if target not in OBJECTS:
                raise KeyError(
                    f"Unknown object '{target}'. Known: {sorted(OBJECTS)}"
                )
            return self.read_sn(OBJECTS[target])
        return self.read_sn(int(target))

    def read_multi(self, addresses):
        """
        Multi-read using L+G extended-address PDU (subtype 0x02).

        Bypasses the generic GET pipeline since multi-read is an L+G
        extension to the SN protocol, not part of standard COSEM.
        """
        from .. import hdlc
        from ..meter import MeterError
        from ..transport import TransportError
        from ..connection import MeterConnectionError

        if not self._associated:
            raise MeterError("Not associated — use 'with LandisGyrZMD(...)' first")

        request = build_multi_read_request(addresses)
        frame   = hdlc.build_iframe(
            serial=self._serial, ns=self._ns, nr=self._nr, info=request,
        )
        try:
            self._conn.send_frame(frame)
            raw = self._conn.recv_frame()
        except (TransportError, MeterConnectionError) as e:
            raise MeterError(f"Multi-read exchange failed: {e}") from e

        parsed = hdlc.parse_iframe(raw)
        self._ns = (self._ns + 1) % 8
        self._nr = (self._nr + 1) % 8

        return parse_multi_read_response(parsed["info"])


# ===========================================================================
# L+G ZMQ-series object codes
# ===========================================================================
# Confirmed from real captures against ZMQ meter 51624762:
#   0xA598 → serial number ('51624762')
#   0x3848 → device identification (same as ZMD, e.g. 'H.WM0205VHNp')
#   0xC1C8 → device info structure (different content than ZMD)
#   0xBD68 → some additional info string (often paired with C1C8)
# Multi-read extended addresses (FD08, FF08) work the same as ZMD.

OBJECTS_ZMQ: dict[str, int] = {
    "serial_number":          0xA598,
    "device_identification":  0x3848,
    "device_info":            0xC1C8,
    "device_info_2":          0xBD68,
}


class LandisGyrZMQ(_BaseMeter):
    """
    Convenience subclass for L+G ZMQ-series meters.

    ZMQ uses different short codes than ZMD for some objects — notably
    the serial number is at 0xA598 (vs 0x5A88 on ZMD). Defaults to SN
    referencing and exposes a name-based read():

        with LandisGyrZMQ.over_tcp(host, port, serial) as m:
            print(m.read("serial_number"))           # → '51624762'
            print(m.read("device_identification"))   # → 'H.WM0205VHNp'
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("referencing", _Referencing.SN)
        super().__init__(*args, **kwargs)

    def read(self, target):
        """Read by friendly name or 2-byte object code."""
        if isinstance(target, str):
            if target not in OBJECTS_ZMQ:
                raise KeyError(
                    f"Unknown ZMQ object '{target}'. Known: {sorted(OBJECTS_ZMQ)}"
                )
            return self.read_sn(OBJECTS_ZMQ[target])
        return self.read_sn(int(target))
