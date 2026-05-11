"""
example_generic.py — Read from any DLMS meter using the generic API.

Demonstrates four usage patterns:
  1. example_inspect       — connect, print capabilities, no reads
  2. example_lg_zmd        — vendor-specific subclass (L+G ZMD)
  3. example_auto_detect   — let the library pick LN vs SN
  4. example_with_password — LLS authentication

Usage:
    python example_generic.py <host> <port> <serial>
"""

import sys

from dlms_meter         import Meter, MeterError, TransportError
from dlms_meter.cosem   import Referencing, AuthMech
from dlms_meter.vendors.landis_gyr import LandisGyrZMD


def example_inspect(host: str, port: int, serial: int) -> None:
    """Open a session and print what the meter announced it supports."""
    print(f"\n--- Inspecting meter {serial} ---")
    try:
        with Meter.connect_auto(host, port, serial) as m:
            print(f"  Referencing in use : {m.referencing.name}")
            print(f"  Server max PDU     : {m.info.server_max_pdu}")
            print(f"  Capabilities       : {m.capabilities}")
    except (MeterError, TransportError) as e:
        print(f"  failed: {e}")


def example_lg_zmd(host: str, port: int, serial: int) -> None:
    """L+G ZMD via the convenience subclass (forces SN referencing)."""
    print(f"\n--- L+G ZMD read from {serial} ---")
    try:
        with LandisGyrZMD.over_tcp(host, port, serial=serial) as m:
            print(f"  serial_number         : {m.read('serial_number')!r}")
            print(f"  device_identification : {m.read('device_identification')!r}")
            print(f"  device_id_1 (0xC1C8)  : {m.read(0xC1C8)!r}")
    except (MeterError, TransportError) as e:
        print(f"  failed: {e}")


def example_auto_detect(host: str, port: int, serial: int) -> None:
    """
    Connect without knowing the meter's referencing style.

    connect_auto() opens, inspects capabilities, and either keeps the
    session or transparently reconnects with the right style.
    """
    print(f"\n--- Auto-detect read from {serial} ---")
    try:
        with Meter.connect_auto(host, port, serial) as m:
            print(f"  Detected referencing : {m.referencing.name}")

            if m.capabilities.can_read_ln:
                # Standard COSEM names
                serial_str = m.read_ln("0-0:96.1.0", class_id=1, attribute=2)
                print(f"  serial (LN)          : {serial_str!r}")
            elif m.capabilities.can_read_sn:
                # L+G-style short name (0x5A88 = serial on ZMD)
                print(f"  serial (SN 0x5A88)   : {m.read_sn(0x5A88)!r}")

    except (MeterError, TransportError) as e:
        print(f"  failed: {e}")


def example_with_password(host: str, port: int, serial: int) -> None:
    """LN with Low Level Security (password)."""
    print(f"\n--- LN with LLS password ---")
    try:
        with Meter.over_tcp(host, port, serial=serial,
                            referencing=Referencing.LN,
                            auth=AuthMech.LOW,
                            password=b"00000000") as m:
            print(f"  serial: {m.read_ln('0-0:96.1.0', class_id=1, attribute=2)!r}")
    except (MeterError, TransportError) as e:
        print(f"  failed: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python example_generic.py <host> <port> <serial>")
        sys.exit(1)

    host    = sys.argv[1]
    port    = int(sys.argv[2])
    serial  = int(sys.argv[3])

    example_inspect(host, port, serial)
    example_auto_detect(host, port, serial)
    example_lg_zmd(host, port, serial)
    # Uncomment to try LLS:
    # example_with_password(host, port, serial)
