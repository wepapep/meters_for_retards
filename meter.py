"""
meter.py — High-level facade for reading values from Landis+Gyr ZMD meters.

This module wraps the full session lifecycle:
    SNRM/UA  →  AARQ/AARE  →  one or more reads  →  DISC/UA

Sequence numbers N(S) and N(R) are tracked internally, so callers just
issue reads by name or object code without thinking about the framing.

Typical usage:

    with Meter.over_tcp("192.168.1.10", 8000, serial=51282380) as m:
        print(m.read("serial_number"))           # → "51282380"
        print(m.read("device_identification"))   # → "B.M4CCPTSCMDO..."
        print(m.read_raw(0xC1C8))                # → bytes([0x02, 0xCB, ...])

For multiple meters sharing one TCP port, share a Transport across Meters:

    transport = TcpTransport("192.168.1.10", 8000)
    transport.open()
    try:
        for serial in [51282380, 51282381, 51282382]:
            with Meter(transport, serial=serial) as m:
                print(serial, m.read("serial_number"))
    finally:
        transport.close()
"""

from __future__ import annotations

from dataclasses import dataclass

import hdlc
import cosem
import lg_short
from connection import (
    MeterConnection,
    MeterConnectionError,
    DEFAULT_TIMEOUT,
    DEFAULT_RETRIES,
)
from transport import Transport, TcpTransport, UdpTransport, TransportError


class MeterError(Exception):
    """Raised on any meter read failure."""


@dataclass
class MeterInfo:
    """Information collected during AARE handshake."""
    server_max_pdu: int | None
    negotiated_conformance: bytes | None


class Meter:
    """
    High-level meter session.

    Manages the HDLC session (via MeterConnection), the COSEM association
    (via cosem.build_aarq / parse_aare), and the L+G short-protocol reads
    (via lg_short). Sequence numbers are tracked across the session.
    """

    def __init__(
        self,
        transport: Transport,
        serial: int,
        umac: int = 1,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ):
        self._serial   = serial
        self._conn     = MeterConnection(
            transport, serial=serial, umac=umac,
            timeout=timeout, retries=retries,
        )
        self._owns_transport_via_conn = False  # see convenience constructors
        self._ns = 0   # send sequence number
        self._nr = 0   # receive sequence number
        self._associated = False
        self._info: MeterInfo | None = None

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def over_tcp(
        cls,
        host: str,
        port: int,
        serial: int,
        umac: int = 1,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> "Meter":
        """Create a Meter with a dedicated TCP transport."""
        transport = TcpTransport(host, port)
        m = cls(transport, serial=serial, umac=umac,
                timeout=timeout, retries=retries)
        m._owns_transport_via_conn = True
        m._conn._owns_transport = True
        return m

    @classmethod
    def over_udp(
        cls,
        host: str,
        port: int,
        serial: int,
        umac: int = 1,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> "Meter":
        """Create a Meter with a dedicated UDP transport."""
        transport = UdpTransport(host, port)
        m = cls(transport, serial=serial, umac=umac,
                timeout=timeout, retries=retries)
        m._owns_transport_via_conn = True
        m._conn._owns_transport = True
        return m

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "Meter":
        # MeterConnection's __enter__ handles transport open + SNRM/UA
        self._conn.__enter__()
        try:
            self._associate()
        except Exception:
            self._conn.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # We don't bother sending a graceful AARQ release (RLRQ);
        # the DISC at the HDLC layer is sufficient for these meters.
        self._associated = False
        self._conn.__exit__(exc_type, exc, tb)

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    @property
    def serial(self) -> int:
        return self._serial

    @property
    def info(self) -> MeterInfo | None:
        """Negotiated session parameters from AARE; None until associated."""
        return self._info

    def _associate(self) -> None:
        """Perform the COSEM AARQ/AARE handshake."""
        aarq = cosem.build_aarq()
        response_info = self._exchange(aarq)
        aare = cosem.parse_aare(response_info)
        if aare["result"] != 0:
            raise MeterError(
                f"AARE rejected: result={aare['result']} "
                f"source={aare['result_source']} "
                f"diagnostic={aare['result_diagnostic']}"
            )
        self._info = MeterInfo(
            server_max_pdu=aare["server_max_pdu"],
            negotiated_conformance=aare["negotiated_conformance"],
        )
        self._associated = True

    def _exchange(self, request_pdu: bytes) -> bytes:
        """
        Send a request PDU as an I-frame, receive and validate the response,
        and return the response info field (with LLC header stripped).

        Updates internal N(S)/N(R) counters.
        """
        frame = hdlc.build_iframe(
            serial=self._serial,
            ns=self._ns,
            nr=self._nr,
            info=request_pdu,
        )
        try:
            self._conn.send_frame(frame)
            raw = self._conn.recv_frame()
        except (TransportError, MeterConnectionError) as e:
            raise MeterError(f"Frame exchange failed: {e}") from e

        parsed = hdlc.parse_iframe(raw)
        if parsed is None:
            raise MeterError(f"Could not parse response as I-frame: {raw.hex()}")

        # Sanity-check sequence numbers:
        # The meter's N(S) should equal our outgoing N(R) (next expected seq from meter)
        # The meter's N(R) should equal our outgoing N(S) + 1 (acknowledging our send)
        expected_meter_ns = self._nr
        expected_meter_nr = (self._ns + 1) % 8
        if parsed["ns"] != expected_meter_ns or parsed["nr"] != expected_meter_nr:
            # Not a hard error — log-worthy but don't fail the read
            # (some meters tolerate slight deviations)
            pass

        # Advance our counters: we've now sent N(S) and received from meter,
        # so next outgoing N(S) increments and N(R) tracks meter's next expected
        self._ns = (self._ns + 1) % 8
        self._nr = (self._nr + 1) % 8

        return parsed["info"]

    # ------------------------------------------------------------------
    # High-level read API
    # ------------------------------------------------------------------

    def read_raw(self, target: int | str) -> bytes:
        """
        Read a single object and return the raw value bytes.

        Args:
            target: object code as int (e.g. 0xC1C8) or registered name
                    from lg_short.OBJECTS (e.g. "device_id_1").

        Returns:
            Raw value bytes (no padding stripped, no decoding applied).
        """
        if not self._associated:
            raise MeterError("Not associated — use 'with Meter(...)' first")

        if isinstance(target, str):
            obj_code = lg_short.OBJECTS.get(target)
            if obj_code is None:
                raise KeyError(
                    f"Unknown object name '{target}'. "
                    f"Known: {sorted(lg_short.OBJECTS)}"
                )
        else:
            obj_code = target

        request = lg_short.build_read_request(obj_code)
        info    = self._exchange(request)
        resp    = lg_short.parse_read_response(info)

        if not resp.success:
            raise MeterError(
                f"Read of {lg_short.describe_object(obj_code)} failed "
                f"with status 0x{resp.status:02X}"
            )
        return resp.value

    def read(self, target: int | str) -> str | bytes:
        """
        Read a single object and auto-decode based on its DLMS data type.

        - VISIBLE STRING (0x0A) → returns Python str (zero-padding stripped)
        - OCTET STRING   (0x09) → returns Python str if all bytes printable,
                                  else bytes
        - other / unknown       → returns raw bytes

        For full control over the response (status, data type, raw bytes),
        use read_response() instead.
        """
        resp = self.read_response(target)

        if resp.data_type == lg_short.DTYPE_VISIBLE_STRING:
            return resp.as_visible_string()

        if resp.data_type == lg_short.DTYPE_OCTET_STRING:
            stripped = resp.value.rstrip(b"\x00")
            if stripped and all(32 <= b < 127 for b in stripped):
                return stripped.decode("ascii")
            return resp.value

        return resp.value

    def read_response(self, target: int | str) -> lg_short.ReadResponse:
        """
        Read a single object and return the full ReadResponse object.

        Use response.as_visible_string() / .as_octet_string() / .value
        to access the value in the form you need.
        """
        if not self._associated:
            raise MeterError("Not associated — use 'with Meter(...)' first")

        if isinstance(target, str):
            obj_code = lg_short.OBJECTS.get(target)
            if obj_code is None:
                raise KeyError(
                    f"Unknown object name '{target}'. "
                    f"Known: {sorted(lg_short.OBJECTS)}"
                )
        else:
            obj_code = target

        request = lg_short.build_read_request(obj_code)
        info    = self._exchange(request)
        resp    = lg_short.parse_read_response(info)

        if not resp.success:
            raise MeterError(
                f"Read of {lg_short.describe_object(obj_code)} failed "
                f"with status 0x{resp.status:02X}"
            )
        return resp

    def read_multi(self, addresses: list[bytes]) -> list[lg_short.ReadResponse]:
        """
        Multi-read using extended addresses (subtype 0x02).

        Args:
            addresses: list of 2-byte extended addresses, e.g.
                       [bytes.fromhex("FD08"), bytes.fromhex("FF08")]
                       or use lg_short.EXT_ADDRESSES["..."] values.

        Returns:
            List of ReadResponse, one per address.
        """
        if not self._associated:
            raise MeterError("Not associated — use 'with Meter(...)' first")

        request = lg_short.build_multi_read_request(addresses)
        info    = self._exchange(request)
        return lg_short.parse_multi_read_response(info)


# ===========================================================================
# Dependencies
# ===========================================================================
#
# Standard library only — no external packages required.
#
#   abc          — Transport abstract base class
#   dataclasses  — MeterInfo, ReadResponse
#   socket       — TCP/UDP transports
#   struct       — binary encoding (frame format, FCS, addresses)
#   typing       — type hints (uses 3.10+ "X | None" syntax)
#
# Python version: 3.10 or newer (uses PEP 604 union types like `int | str`).
#
# Internal modules (in this package):
#   hdlc.py       — HDLC framing, FCS-16, addresses, SNRM/UA/I-frame/DISC
#   transport.py  — TcpTransport, UdpTransport, frame boundary detection
#   connection.py — MeterConnection: SNRM/UA handshake with retries
#   cosem.py      — AARQ/AARE association, GET request/response (for future)
#   lg_short.py   — L+G ZMD short-code protocol (read by 16-bit object code)
#   meter.py      — this module: high-level facade
#
# ===========================================================================
