"""
landis_gyr.py — Landis+Gyr meter support (ZMD, ZMQ, and other SN families).

This module exposes:

- `LandisGyrMeter`: the unified meter class. Auto-detects the meter's
  software ID (e.g. "B32", "H03") and routes name lookups through the
  matching catalogue loaded by `dlms_meter.catalogue_loader`.

- Protocol-level helpers for the L+G short-code read service:
  - `build_read_request(short_name)` — subtype 0x01 (single short-code read)
  - `build_multi_read_request(addresses)` — subtype 0x02 (extended multi-read)
  - `parse_read_response(data)` — single-read response
  - `parse_multi_read_response(data)` — multi-read response

For backwards compatibility, `LandisGyrZMD` and `LandisGyrZMQ` are exported
as aliases for `LandisGyrMeter`. They are scheduled for removal in a future
release; new code should use `LandisGyrMeter`.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..meter import Meter as _BaseMeter, MeterError
from ..cosem import Referencing as _Referencing
from .. import hdlc
from ..transport import TransportError
from ..connection import MeterConnectionError
from ..catalogue_loader import resolve_address, describe, get_catalogue


# ===========================================================================
# Constants — L+G short-protocol PDU layout
# ===========================================================================

TAG_REQUEST   = 0x05
TAG_RESPONSE  = 0x0C

SUBTYPE_READ_SHORT = 0x01
SUBTYPE_READ_EXT   = 0x02
ATTR_VALUE         = 0x02   # observed — always 0x02 in practice

STATUS_SUCCESS = 0x00

# DLMS data type tags (subset commonly seen in responses)
DTYPE_OCTET_STRING   = 0x09
DTYPE_VISIBLE_STRING = 0x0A


# ===========================================================================
# Extended-address codes for multi-read (subtype 0x02)
# ===========================================================================
# These are not variant-specific — same across the whole ZMD/ZMQ family.

EXT_ADDRESSES: dict[str, bytes] = {
    "manufacturer_and_serial": bytes.fromhex("FD08"),
    "meter_type_code":         bytes.fromhex("FF08"),
}


# ===========================================================================
# Universal fallback object map
# ===========================================================================
# Used when no catalogue is loaded or the meter's software ID isn't in the
# loaded catalogue. These objects are observed at the same short codes
# across all L+G variants seen so far.

UNIVERSAL_OBJECTS: dict[str, int] = {
    "device_identification": 0x3848,   # StringRegisterConfigId
    "device_id_1":           0xC1C8,   # Option1IdentCopy
}


# ===========================================================================
# Request building
# ===========================================================================

def build_read_request(short_name: int, attribute: int = ATTR_VALUE) -> bytes:
    """Build a short-code read request (subtype 0x01)."""
    if not 0 <= short_name <= 0xFFFF:
        raise ValueError(f"short_name out of range: {short_name:#06x}")
    return bytes([
        TAG_REQUEST,
        SUBTYPE_READ_SHORT,
        attribute,
        (short_name >> 8) & 0xFF,
        short_name & 0xFF,
    ])


def build_multi_read_request(addresses: list[bytes], attribute: int = ATTR_VALUE) -> bytes:
    """
    Build an extended multi-read request (subtype 0x02).

    Layout:   05 02 [AA <addr1>] [AA <addr2>] ...
    where each item is (attribute, address) — the attribute is repeated
    for every address.
    """
    if not addresses:
        raise ValueError("at least one address required")
    pairs = b"".join(bytes([attribute]) + addr for addr in addresses)
    return bytes([TAG_REQUEST, SUBTYPE_READ_EXT]) + pairs


# ===========================================================================
# Response parsing
# ===========================================================================

@dataclass
class ReadResponse:
    """A single-item read response."""
    success:   bool
    status:    int
    data_type: int | None
    value:     bytes

    def as_octet_string(self) -> bytes:
        return self.value

    def as_visible_string(self) -> str:
        return self.value.rstrip(b"\x00").decode("ascii", errors="replace")


def parse_read_response(data: bytes) -> ReadResponse:
    """Parse a subtype-0x01 (single short-code) read response."""
    if len(data) < 3:
        raise ValueError(f"Response too short: {data.hex()}")
    if data[0] != TAG_RESPONSE:
        raise ValueError(f"Not a read response: got {data[0]:#04x}")

    if data[1] != SUBTYPE_READ_SHORT:
        raise ValueError(f"Use parse_multi_read_response() for subtype 0x{data[1]:02X}")

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
    """Parse a subtype-0x02 (multi-read) response."""
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


# ===========================================================================
# Unified meter class
# ===========================================================================

class LandisGyrMeter(_BaseMeter):
    """
    Unified L+G meter class — handles ZMD, ZMQ and other SN-based families.

    On first read of an object by name, the meter's software ID is fetched
    (FF08 short code), and the corresponding catalogue is used to resolve
    names to short codes. If no catalogue is loaded, or the meter's variant
    isn't catalogued, falls back to a universal small dict.

    Usage:

        # Load catalogues once at program startup (from default ~/.dlms_meter/)
        from dlms_meter.catalogue_loader import load_catalogues
        load_catalogues()

        # Then read any meter — variant is detected automatically
        with LandisGyrMeter.over_tcp(host, port, serial) as m:
            print(m.software_id)              # → 'B32'
            print(m.read('serial_number'))    # → '51282380'
            print(m.read('StringRegisterID2_1'))   # also works (official L+G name)
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("referencing", _Referencing.SN)
        super().__init__(*args, **kwargs)
        self._software_id: str | None = None

    # ------------------------------------------------------------------
    # Vendor discovery
    # ------------------------------------------------------------------

    @property
    def software_id(self) -> str:
        """The meter's software ID (e.g. 'B32', 'H03'). Lazily read once."""
        if self._software_id is None:
            results = self.read_multi([EXT_ADDRESSES["meter_type_code"]])
            self._software_id = results[0].as_visible_string()
        return self._software_id

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def read(self, target: str | int):
        """
        Read an object by friendly name, official L+G name, or short code.

        Examples:
            m.read('serial_number')           # friendly alias
            m.read('StringRegisterID2_1')     # official L+G name
            m.read(0x5A88)                    # raw short code
        """
        if isinstance(target, int):
            return self.read_sn(int(target))

        if not isinstance(target, str):
            raise TypeError(f"target must be str or int, got {type(target).__name__}")

        # Strategy: try catalogue lookup first, then universal fallback.
        addr = resolve_address(self.software_id, target)
        if addr is not None:
            return self.read_sn(addr)

        if target in UNIVERSAL_OBJECTS:
            return self.read_sn(UNIVERSAL_OBJECTS[target])

        # No match anywhere — produce a helpful error
        cat = get_catalogue(self.software_id)
        if cat is None:
            raise MeterError(
                f"Unknown object '{target}'. No catalogue loaded for variant "
                f"'{self.software_id}'. Either pass a raw int short code or "
                f"load the L+G catalogues via dlms_meter.catalogue_loader."
            )
        else:
            raise MeterError(
                f"Unknown object '{target}' for variant '{self.software_id}'. "
                f"Catalogue contains {len(cat)} addresses; try one of those, "
                f"or use a friendly alias like 'serial_number'."
            )

    def describe_address(self, address: int):
        """Look up what an address means in this meter's catalogue."""
        return describe(self.software_id, address)

    # ------------------------------------------------------------------
    # Multi-read (vendor extension on top of standard SN)
    # ------------------------------------------------------------------

    def read_multi(self, addresses: list[bytes]) -> list[ReadResponse]:
        """
        Multi-read using L+G extended-address PDU (subtype 0x02).

        Bypasses the generic GET pipeline since multi-read is an L+G
        extension to the SN protocol.
        """
        if not self._associated:
            raise MeterError("Not associated — use 'with LandisGyrMeter(...)' first")

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
# Backwards-compatibility aliases
# ===========================================================================
# Existing code that uses LandisGyrZMD or LandisGyrZMQ keeps working.
# Both names now point at the unified class.

LandisGyrZMD = LandisGyrMeter
LandisGyrZMQ = LandisGyrMeter
