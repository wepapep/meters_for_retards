"""
connection.py — MeterConnection: manages an HDLC session with one meter.

A MeterConnection pairs a Transport with a meter serial number. It handles
the SNRM/UA handshake on entry and cleanup on exit. Higher-level COSEM logic
(AARQ/AARE, GET.request/response) will send and receive frames through it.

The transport is decoupled, so the same MeterConnection works for:
- TCP, single meter per port
- TCP, multiple meters per port  (use one Transport for several MeterConnections)
- UDP, single meter per port
"""

from __future__ import annotations

import hdlc
from transport import Transport, TcpTransport, UdpTransport, TransportError


DEFAULT_TIMEOUT = 5.0    # seconds
DEFAULT_RETRIES = 3      # total attempts = retries (i.e. 3 tries max)


class MeterConnectionError(Exception):
    """Raised when the HDLC session cannot be established or maintained."""


class MeterConnection:
    """
    HDLC session with a single meter.

    Typical usage:
        transport = TcpTransport("192.168.1.10", 8000)
        transport.open()
        with MeterConnection(transport, serial=12342380) as meter:
            # send/receive higher-level COSEM frames through `meter`
            ...
        transport.close()

    For the common case of one meter per connection, use the convenience
    constructors `MeterConnection.over_tcp(...)` / `MeterConnection.over_udp(...)`.
    """

    def __init__(
        self,
        transport: Transport,
        serial: int,
        umac: int = 1,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ):
        self._transport = transport
        self._serial    = serial
        self._umac      = umac
        self._timeout   = timeout
        self._retries   = retries
        self._owns_transport = False  # set by convenience constructors
        self._connected = False

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
    ) -> "MeterConnection":
        """Create a MeterConnection with a dedicated TCP transport."""
        t = TcpTransport(host, port)
        c = cls(t, serial=serial, umac=umac, timeout=timeout, retries=retries)
        c._owns_transport = True
        return c

    @classmethod
    def over_udp(
        cls,
        host: str,
        port: int,
        serial: int,
        umac: int = 1,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> "MeterConnection":
        """Create a MeterConnection with a dedicated UDP transport."""
        t = UdpTransport(host, port)
        c = cls(t, serial=serial, umac=umac, timeout=timeout, retries=retries)
        c._owns_transport = True
        return c

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "MeterConnection":
        if self._owns_transport:
            self._transport.open()
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.disconnect()
        finally:
            if self._owns_transport:
                self._transport.close()

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """
        Perform the HDLC SNRM/UA handshake.

        Retries up to `self._retries` times on TransportError.
        """
        snrm = hdlc.build_snrm_frame(self._serial, umac=self._umac)

        last_error: Exception | None = None
        for attempt in range(1, self._retries + 1):
            try:
                self._transport.send(snrm)
                response = self._transport.recv_frame(self._timeout)
                if not hdlc.parse_ua_response(response):
                    raise MeterConnectionError(
                        f"Expected UA response, got: {response.hex()}"
                    )
                self._connected = True
                return
            except (TransportError, MeterConnectionError) as e:
                last_error = e
                if attempt == self._retries:
                    break

        raise MeterConnectionError(
            f"SNRM handshake failed after {self._retries} attempt(s): {last_error}"
        )

    def disconnect(self) -> None:
        """
        Close the HDLC session gracefully.

        Currently a no-op placeholder — we'll send a DISC frame once that's
        implemented in hdlc.py.
        """
        # TODO: send DISC frame, wait for UA
        self._connected = False

    # ------------------------------------------------------------------
    # Frame exchange (for higher layers)
    # ------------------------------------------------------------------

    @property
    def serial(self) -> int:
        return self._serial

    @property
    def connected(self) -> bool:
        return self._connected

    def send_frame(self, frame: bytes) -> None:
        """Send a pre-built HDLC frame."""
        if not self._connected:
            raise MeterConnectionError("Not connected — call connect() first")
        self._transport.send(frame)

    def recv_frame(self) -> bytes:
        """Receive one HDLC frame from the meter."""
        if not self._connected:
            raise MeterConnectionError("Not connected — call connect() first")
        return self._transport.recv_frame(self._timeout)
