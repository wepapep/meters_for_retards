"""
example_generic.py — Read from any DLMS meter using the generic API.

Demonstrates:
  - Logical Name (LN) reads — modern meters
  - Short Name (SN) reads via the vendor subclass — L+G ZMD
  - Authentication parameters

Usage:
    python example_generic.py <host> <port> <serial>
"""

import sys

from dlms_meter         import Meter, MeterError, TransportError
from dlms_meter.cosem   import Referencing, AuthMech
from dlms_meter.vendors.landis_gyr import LandisGyrZMD


def example_ln_read(host: str, port: int, serial: int) -> None:
    """Standard COSEM LN read — works on most modern meters."""
    print(f"\n--- LN (standard COSEM) read from {serial} ---")
    try:
        with Meter.over_tcp(host, port, serial=serial,
                            referencing=Referencing.LN) as m:
            # Serial number — OBIS 0-0:96.1.0, class Data(1), attribute 2
            serial_str = m.read_ln("0-0:96.1.0", class_id=1, attribute=2)
            print(f"  serial:  {serial_str!r}")

            # Active energy import — OBIS 1-0:1.8.0, class Register(3), attribute 2
            energy = m.read_ln("1-0:1.8.0", class_id=3, attribute=2)
            print(f"  energy:  {energy} (kWh, scaled by Register scaler)")

    except (MeterError, TransportError) as e:
        print(f"  failed: {e}")


def example_lg_zmd(host: str, port: int, serial: int) -> None:
    """L+G ZMD via the convenience subclass."""
    print(f"\n--- L+G ZMD (SN referencing) read from {serial} ---")
    try:
        with LandisGyrZMD.over_tcp(host, port, serial=serial) as m:
            print(f"  serial_number         : {m.read('serial_number')!r}")
            print(f"  device_identification : {m.read('device_identification')!r}")
            print(f"  device_id_1 (0xC1C8)  : {m.read(0xC1C8)!r}")

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

    example_lg_zmd(host, port, serial)
    # Uncomment to try the others:
    # example_ln_read(host, port, serial)
    # example_with_password(host, port, serial)
