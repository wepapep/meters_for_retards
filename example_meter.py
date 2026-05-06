"""
example_meter.py — Read multiple values from a meter using the high-level API.

Usage:
    python example_meter.py <host> <port> <serial>
    python example_meter.py 192.168.1.10 8000 51282380
"""

import sys

from meter    import Meter, MeterError
from transport import TcpTransport, TransportError
import lg_short


def read_one_meter(host: str, port: int, serial: int) -> None:
    print(f"Connecting to meter {serial} at {host}:{port}...\n")
    try:
        with Meter.over_tcp(host, port, serial=serial) as m:
            print(f"Associated. Server max PDU = {m.info.server_max_pdu}\n")

            # Single-object reads, auto-decoded
            print(f"  serial_number          : {m.read('serial_number')!r}")
            print(f"  device_identification  : {m.read('device_identification')!r}")

            # Read by raw object code
            device_id_1 = m.read_response(0xC1C8)
            print(f"  0xC1C8 (device_id_1)   : type=0x{device_id_1.data_type:02X}, "
                  f"{len(device_id_1.value)} bytes = {device_id_1.value.hex(' ').upper()}")

            # Multi-read using extended addresses (subtype 0x02)
            print()
            results = m.read_multi([
                lg_short.EXT_ADDRESSES["manufacturer_and_serial"],
                lg_short.EXT_ADDRESSES["meter_type_code"],
            ])
            print(f"  multi-read manufacturer: {results[0].as_visible_string()!r}")
            print(f"  multi-read type code   : {results[1].as_visible_string()!r}")

    except (MeterError, TransportError) as e:
        print(f"Failed: {e}", file=sys.stderr)
        sys.exit(1)


def read_multiple_meters_one_port(host: str, port: int, serials: list[int]) -> None:
    """
    Multiple meters sharing a single TCP connection.

    Each meter gets a fresh SNRM → AARQ → reads → DISC cycle, but the
    underlying TCP socket stays open across all of them.
    """
    print(f"Reading {len(serials)} meters via shared {host}:{port}...\n")
    transport = TcpTransport(host, port)
    transport.open()
    try:
        for serial in serials:
            try:
                with Meter(transport, serial=serial) as m:
                    print(f"  meter {serial}: serial={m.read('serial_number')!r}, "
                          f"id={m.read('device_identification')[:30]!r}...")
            except (MeterError, TransportError) as e:
                print(f"  meter {serial}: FAILED — {e}")
    finally:
        transport.close()


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python example_meter.py <host> <port> <serial> [<serial>...]")
        sys.exit(1)

    host    = sys.argv[1]
    port    = int(sys.argv[2])
    serials = [int(s) for s in sys.argv[3:]]

    if len(serials) == 1:
        read_one_meter(host, port, serials[0])
    else:
        read_multiple_meters_one_port(host, port, serials)
