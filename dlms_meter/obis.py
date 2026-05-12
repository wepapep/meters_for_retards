"""
obis.py — OBIS (Object Identification System) code handling.

OBIS codes uniquely identify what a meter measures. They appear in two forms:

  String:  "1-0:1.8.0*255"  or simplified  "1.0.1.8.0.255"  or "1.0.1.8.0"
  Bytes:   6-byte sequence  01 00 01 08 00 FF

Structure:  A.B.C.D.E.F
  A — medium (0=abstract, 1=electricity, 7=gas, 8=water, ...)
  B — channel (0 = no channel)
  C — physical quantity (1=energy, 21=voltage, 31=current, ...)
  D — measurement type (1=total, 7=instantaneous, ...)
  E — tariff (0=total, 1=tariff 1, ...)
  F — billing period (255 = current, 0..99 = historical)

The F group is usually 255 ("current value"); the simplified 5-group
form omits it and we substitute 255 automatically.

Encoding never has 7-bit shifts or continuation flags — each group
is a single byte, range 0..255.
"""

from __future__ import annotations

import re


_OBIS_PATTERN = re.compile(
    r"^(?:(\d+)-)?(\d+):"            # optional A- prefix, then B:
    r"(\d+)\.(\d+)\.(\d+)"           # C.D.E
    r"(?:\*(\d+))?$"                 # optional *F
)


def encode(obis: str | bytes | tuple[int, ...]) -> bytes:
    """
    Convert an OBIS code to its 6-byte binary form.

    Accepted input forms:
        "1-0:1.8.0*255"   canonical
        "1-0:1.8.0"       missing F → defaults to 255
        "1.0.1.8.0.255"   dot-separated, 6 groups
        "1.0.1.8.0"       dot-separated, 5 groups (F defaults to 255)
        "0.0.96.1.0"      common abstract-medium form
        bytes / bytearray of length 6 (returned as-is)
        tuple/list of 5 or 6 ints

    Raises:
        ValueError: if the input cannot be parsed or any group is out of range.
    """
    if isinstance(obis, (bytes, bytearray)):
        if len(obis) != 6:
            raise ValueError(f"OBIS bytes must be 6 bytes, got {len(obis)}")
        return bytes(obis)

    if isinstance(obis, (tuple, list)):
        groups = list(obis)
        if len(groups) == 5:
            groups.append(255)
        if len(groups) != 6:
            raise ValueError(f"OBIS tuple must have 5 or 6 groups, got {len(groups)}")
        return _validate_groups(groups)

    if not isinstance(obis, str):
        raise TypeError(f"OBIS must be str, bytes or tuple, got {type(obis).__name__}")

    # Try canonical form: A-B:C.D.E*F  (with all variants of missing fields)
    m = _OBIS_PATTERN.match(obis.strip())
    if m:
        groups = [
            int(m.group(1)) if m.group(1) else 0,
            int(m.group(2)),
            int(m.group(3)),
            int(m.group(4)),
            int(m.group(5)),
            int(m.group(6)) if m.group(6) else 255,
        ]
        return _validate_groups(groups)

    # Try dot-separated form
    parts = obis.strip().split(".")
    if 5 <= len(parts) <= 6 and all(p.isdigit() for p in parts):
        groups = [int(p) for p in parts]
        if len(groups) == 5:
            groups.append(255)
        return _validate_groups(groups)

    raise ValueError(f"Cannot parse OBIS code: {obis!r}")


def decode(obis: bytes) -> str:
    """
    Convert 6-byte binary OBIS to its dotted string form (A.B.C.D.E.F).

    The F (billing period) field is always included, even when 255.
    Use decode_canonical() if you want the standard A-B:C.D.E*F form.
    """
    if len(obis) != 6:
        raise ValueError(f"OBIS must be 6 bytes, got {len(obis)}")
    return ".".join(str(b) for b in obis)


def decode_canonical(obis: bytes) -> str:
    """Return OBIS in canonical 'A-B:C.D.E*F' form."""
    if len(obis) != 6:
        raise ValueError(f"OBIS must be 6 bytes, got {len(obis)}")
    a, b, c, d, e, f = obis
    return f"{a}-{b}:{c}.{d}.{e}*{f}"


def _validate_groups(groups: list[int]) -> bytes:
    for i, g in enumerate(groups):
        if not 0 <= g <= 255:
            raise ValueError(f"OBIS group {i} out of range: {g}")
    return bytes(groups)


# ---------------------------------------------------------------------------
# Common OBIS codes — a starter registry. Extend per vendor / region.
# ---------------------------------------------------------------------------

COMMON: dict[str, str] = {
    # Abstract / identification
    "device_address":          "0-0:0.0.0*255",
    "logical_device_name":     "0-0:42.0.0*255",
    "manufacturer":            "0-0:96.1.4*255",
    "serial_number":           "0-0:96.1.0*255",
    "firmware_version":        "1-0:0.2.0*255",
    "clock":                   "0-0:1.0.0*255",

    # Electricity — energy
    "energy_active_import":    "1-0:1.8.0*255",   # kWh total
    "energy_active_export":    "1-0:2.8.0*255",
    "energy_reactive_import":  "1-0:3.8.0*255",
    "energy_reactive_export":  "1-0:4.8.0*255",

    # Electricity — instantaneous
    "power_active_import":     "1-0:1.7.0*255",   # kW
    "power_active_export":     "1-0:2.7.0*255",
    "voltage_l1":              "1-0:32.7.0*255",
    "voltage_l2":              "1-0:52.7.0*255",
    "voltage_l3":              "1-0:72.7.0*255",
    "current_l1":              "1-0:31.7.0*255",
    "current_l2":              "1-0:51.7.0*255",
    "current_l3":              "1-0:71.7.0*255",
    "frequency":               "1-0:14.7.0*255",
}


def lookup(name: str) -> bytes:
    """Look up a common OBIS code by friendly name → 6 bytes."""
    if name not in COMMON:
        raise KeyError(f"Unknown OBIS name '{name}'. Known: {sorted(COMMON)}")
    return encode(COMMON[name])
