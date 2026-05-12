"""
dlms_meter — read values from DLMS/COSEM energy meters over HDLC.

Main entry points:

    from dlms_meter import Meter
    from dlms_meter.transport import TcpTransport, UdpTransport

    # Standard COSEM (Logical Name) reads — works on most modern meters:
    with Meter.over_tcp("192.168.1.10", 8000, serial=12345678) as m:
        val = m.read_ln("0.0.96.1.0", class_id=1, attribute=2)

    # Short Name reads (older meters, including L+G ZMD):
    with Meter.over_tcp(host, port, serial, referencing="sn") as m:
        val = m.read_sn(0xC1C8)

    # Vendor-specific named reads:
    from dlms_meter.vendors.landis_gyr import LandisGyrZMD
    with LandisGyrZMD.over_tcp(host, port, serial) as m:
        print(m.read("serial_number"))
"""

from .meter      import Meter, MeterError, MeterInfo
from .transport  import Transport, TcpTransport, UdpTransport, TransportError
from .connection import MeterConnection, MeterConnectionError

__all__ = [
    "Meter", "MeterError", "MeterInfo",
    "Transport", "TcpTransport", "UdpTransport", "TransportError",
    "MeterConnection", "MeterConnectionError",
]
