"""
data_types.py — Decoders for DLMS-tagged data values.

A DLMS data value is a tag-prefixed item:

    TAG  [LEN]  VALUE

Some types (integers, floats, bool) have a fixed length and no length byte.
Other types (strings, arrays) carry a length byte (or a multi-byte length
in the case of structures/arrays).

The decoder dispatches on the tag and returns a Python value of the
natural type:

    int   for integer types
    float for floating-point types
    bool  for boolean
    str   for VISIBLE_STRING and UTF8_STRING (also dates/times as ISO strings)
    bytes for OCTET_STRING when not clearly printable
    list  for ARRAY and STRUCTURE
    None  for null
    datetime / date / time for date/time types

Reference: DLMS Blue Book Edition 12, section 6.2 — A-XDR encoding rules.
"""

from __future__ import annotations

import datetime as _dt
import struct


# ---------------------------------------------------------------------------
# Tags (from DLMS spec)
# ---------------------------------------------------------------------------

NULL              = 0x00
ARRAY             = 0x01
STRUCTURE         = 0x02
BOOLEAN           = 0x03
BIT_STRING        = 0x04
DOUBLE_LONG       = 0x05   # int32
DOUBLE_LONG_UNSIGNED = 0x06  # uint32
OCTET_STRING      = 0x09
VISIBLE_STRING    = 0x0A
UTF8_STRING       = 0x0C
BCD               = 0x0D
INTEGER           = 0x0F   # int8
LONG              = 0x10   # int16
UNSIGNED          = 0x11   # uint8
LONG_UNSIGNED     = 0x12   # uint16
LONG64            = 0x14   # int64
LONG64_UNSIGNED   = 0x15   # uint64
ENUM              = 0x16
FLOAT32           = 0x17
FLOAT64           = 0x18
DATE_TIME         = 0x19   # 12 bytes
DATE              = 0x1A   # 5 bytes
TIME              = 0x1B   # 4 bytes


_TAG_NAMES = {
    NULL: "null", ARRAY: "array", STRUCTURE: "structure", BOOLEAN: "boolean",
    BIT_STRING: "bit_string", DOUBLE_LONG: "int32", DOUBLE_LONG_UNSIGNED: "uint32",
    OCTET_STRING: "octet_string", VISIBLE_STRING: "visible_string",
    UTF8_STRING: "utf8_string", BCD: "bcd", INTEGER: "int8", LONG: "int16",
    UNSIGNED: "uint8", LONG_UNSIGNED: "uint16", LONG64: "int64",
    LONG64_UNSIGNED: "uint64", ENUM: "enum", FLOAT32: "float32",
    FLOAT64: "float64", DATE_TIME: "date_time", DATE: "date", TIME: "time",
}


def tag_name(tag: int) -> str:
    """Human-readable name for a tag (or 'unknown(0xXX)')."""
    return _TAG_NAMES.get(tag, f"unknown(0x{tag:02X})")


# ---------------------------------------------------------------------------
# Length encoding — A-XDR variable length
# ---------------------------------------------------------------------------
#
# Length < 0x80    → single byte = length
# Length 0x81 NN   → length = NN  (one extra byte)
# Length 0x82 NN NN → length = uint16  (two extra bytes)
# Length 0x83 NN NN NN → length = uint24 (three extra bytes)
# Length 0x84 NN NN NN NN → length = uint32 (four extra bytes)

def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    """Read an A-XDR length. Returns (length, new_offset)."""
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    n = first & 0x7F
    if n == 0 or n > 4:
        raise ValueError(f"Invalid length encoding at offset {offset}: {first:#04x}")
    length = int.from_bytes(data[offset + 1:offset + 1 + n], "big")
    return length, offset + 1 + n


# ---------------------------------------------------------------------------
# Date / time decoders
# ---------------------------------------------------------------------------

def _decode_date(b: bytes):
    """COSEM date (5 bytes): year(2) month day day_of_week."""
    year  = int.from_bytes(b[0:2], "big")
    month = b[2]
    day   = b[3]
    # day_of_week b[4] ignored
    if year == 0xFFFF or month in (0xFF, 0xFE) or day in (0xFF, 0xFE):
        return None
    try:
        return _dt.date(year, month, day)
    except ValueError:
        return None


def _decode_time(b: bytes):
    """COSEM time (4 bytes): hour minute second hundredths."""
    h, m, s, hs = b
    if h == 0xFF or m == 0xFF or s == 0xFF:
        return None
    try:
        return _dt.time(h, m, s, microsecond=hs * 10000 if hs != 0xFF else 0)
    except ValueError:
        return None


def _decode_date_time(b: bytes):
    """
    COSEM date_time (12 bytes):
        year(2) month day day_of_week hour minute second hundredths
        deviation(2) clock_status(1)
    """
    date = _decode_date(b[0:4])  # uses first 4 of the date part; day_of_week is byte 4
    # Actually COSEM date_time is:
    # year(2) month(1) day(1) day-of-week(1) hour(1) minute(1) second(1) hundredths(1) deviation(2) clock-status(1)
    year  = int.from_bytes(b[0:2], "big")
    month, day = b[2], b[3]
    # b[4] = day_of_week
    h, m, s, hs = b[5], b[6], b[7], b[8]
    if year == 0xFFFF or month == 0xFF or day == 0xFF:
        return None
    try:
        return _dt.datetime(year, month, day, h, m, s,
                            microsecond=hs * 10000 if hs != 0xFF else 0)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Main decoder
# ---------------------------------------------------------------------------

def decode(data: bytes, offset: int = 0) -> tuple[object, int]:
    """
    Decode a single DLMS-tagged value.

    Args:
        data:   bytes containing one or more tagged values.
        offset: where in `data` to start decoding.

    Returns:
        (value, new_offset) — the decoded Python value and the offset of
        the byte immediately after the value.
    """
    if offset >= len(data):
        raise ValueError("Unexpected end of data")

    tag = data[offset]
    offset += 1

    # --- Fixed-length numeric types (no length byte) ---

    if tag == NULL:
        return None, offset

    if tag == BOOLEAN:
        return bool(data[offset]), offset + 1

    if tag == INTEGER:
        return _signed(data[offset:offset + 1]), offset + 1

    if tag == UNSIGNED or tag == ENUM:
        return data[offset], offset + 1

    if tag == LONG:
        return _signed(data[offset:offset + 2]), offset + 2

    if tag == LONG_UNSIGNED:
        return int.from_bytes(data[offset:offset + 2], "big"), offset + 2

    if tag == DOUBLE_LONG:
        return _signed(data[offset:offset + 4]), offset + 4

    if tag == DOUBLE_LONG_UNSIGNED:
        return int.from_bytes(data[offset:offset + 4], "big"), offset + 4

    if tag == LONG64:
        return _signed(data[offset:offset + 8]), offset + 8

    if tag == LONG64_UNSIGNED:
        return int.from_bytes(data[offset:offset + 8], "big"), offset + 8

    if tag == FLOAT32:
        return struct.unpack(">f", data[offset:offset + 4])[0], offset + 4

    if tag == FLOAT64:
        return struct.unpack(">d", data[offset:offset + 8])[0], offset + 8

    # --- Fixed-length date/time types ---

    if tag == DATE:
        return _decode_date(data[offset:offset + 5]), offset + 5

    if tag == TIME:
        return _decode_time(data[offset:offset + 4]), offset + 4

    if tag == DATE_TIME:
        return _decode_date_time(data[offset:offset + 12]), offset + 12

    # --- Variable-length types ---

    if tag in (OCTET_STRING, VISIBLE_STRING, UTF8_STRING, BIT_STRING, BCD):
        length, offset = _read_length(data, offset)
        raw = data[offset:offset + length]
        offset += length

        if tag == VISIBLE_STRING:
            return raw.decode("ascii", errors="replace"), offset
        if tag == UTF8_STRING:
            return raw.decode("utf-8", errors="replace"), offset
        if tag == BIT_STRING:
            # value is a bit-aligned string; return as bytes for caller to decode
            return raw, offset
        if tag == BCD:
            # Each nibble is a decimal digit
            return "".join(f"{b >> 4}{b & 0x0F}" for b in raw), offset

        # OCTET_STRING: best-effort string if printable, else bytes
        stripped = raw.rstrip(b"\x00")
        if stripped and all(32 <= b < 127 for b in stripped):
            return stripped.decode("ascii"), offset
        return raw, offset

    # --- Structured types ---

    if tag in (ARRAY, STRUCTURE):
        count, offset = _read_length(data, offset)
        items = []
        for _ in range(count):
            value, offset = decode(data, offset)
            items.append(value)
        return items, offset

    raise ValueError(f"Unsupported DLMS tag: 0x{tag:02X} at offset {offset - 1}")


def decode_one(data: bytes) -> object:
    """Decode a single value from the start of *data* (ignores trailing bytes)."""
    value, _ = decode(data, 0)
    return value


def decode_all(data: bytes) -> list:
    """Decode every tagged value in *data*."""
    out = []
    offset = 0
    while offset < len(data):
        value, offset = decode(data, offset)
        out.append(value)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _signed(b: bytes) -> int:
    """Decode big-endian signed integer of any width."""
    return int.from_bytes(b, "big", signed=True)
