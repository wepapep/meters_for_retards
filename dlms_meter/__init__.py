"""
dlms_meter — read values from DLMS/COSEM energy meters over HDLC.

Main entry points:

    from dlms_meter import Meter, LandisGyrMeter
    from dlms_meter.catalogue_loader import load_catalogues

    # Load L+G catalogues once at program startup (default: ~/.dlms_meter/catalogues.py).
    # Generate the catalogues file with `python -m dlms_meter.tools.build_catalogues`.
    load_catalogues()

    # Read any L+G meter — variant detection is automatic.
    with LandisGyrMeter.over_tcp(host, port, serial) as m:
        print(m.software_id)             # e.g. 'B32'
        print(m.read('serial_number'))   # variant-aware
        print(m.read(0x3848))             # raw short code also works

    # Or use generic COSEM directly (for non-L+G meters that support LN):
    with Meter.over_tcp(host, port, serial) as m:
        val = m.read_ln("0.0.96.1.0", class_id=1, attribute=2)
"""

from .meter             import Meter, MeterError, MeterInfo
from .transport         import Transport, TcpTransport, UdpTransport, TransportError
from .connection        import MeterConnection, MeterConnectionError
from .catalogue_loader  import load_catalogues, get_catalogues, get_catalogue, loaded_from
from .vendors.landis_gyr import LandisGyrMeter, LandisGyrZMD, LandisGyrZMQ

__all__ = [
    "Meter", "MeterError", "MeterInfo",
    "Transport", "TcpTransport", "UdpTransport", "TransportError",
    "MeterConnection", "MeterConnectionError",
    "LandisGyrMeter", "LandisGyrZMD", "LandisGyrZMQ",
    "load_catalogues", "get_catalogues", "get_catalogue", "loaded_from",
]
