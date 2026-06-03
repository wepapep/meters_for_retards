"""
transport.py — Transport abstraction for meter communication.

Provides a common interface over TCP and UDP so the higher-level
MeterConnection code doesn't need to know which is used.

Each transport ships raw bytes to and from a serial device server.
Frame boundary detection (HDLC 0x7E flags) is handled here: recv_frame()
returns a complete HDLC frame including both opening and closing flags.
"""

import socket
from abc import ABC, abstractmethod

from .hdlc import HDLC_FLAG


class TransportError(Exception):
    """Raised when a transport-level operation fails."""


class Transport(ABC):
    """Abstract base class for meter transports."""

    @abstractmethod
    def open(self) -> None:
        """Open the underlying connection."""

    @abstractmethod
    def close(self) -> None:
        """Close the underlying connection."""

    @abstractmethod
    def send(self, data: bytes) -> None:
        """Send raw bytes."""

    @abstractmethod
    def recv_frame(self, timeout: float) -> bytes:
        """
        Receive a complete HDLC frame (bounded by 0x7E flags).

        Returns:
            Raw frame bytes including opening and closing 0x7E flags.

        Raises:
            TransportError: on timeout, disconnect, or malformed frame.
        """


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------

class TcpTransport(Transport):
    """
    TCP connection to a serial device server.

    Supports both "single meter per port" and "multiple meters per port"
    setups — the transport layer doesn't need to know which, since HDLC
    addressing inside the frame identifies the meter.
    """

    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._sock: socket.socket | None = None

    def open(self) -> None:
        if self._sock is not None:
            return
        try:
            self._sock = socket.create_connection((self._host, self._port))
        except OSError as e:
            raise TransportError(f"TCP connect to {self._host}:{self._port} failed: {e}") from e

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def send(self, data: bytes) -> None:
        if self._sock is None:
            raise TransportError("TCP transport is not open")
        try:
            self._sock.sendall(data)
        except OSError as e:
            raise TransportError(f"TCP send failed: {e}") from e

    def recv_frame(self, timeout: float) -> bytes:
        """
        Read a complete HDLC frame from the socket.

        HDLC frames carry their own length in the frame format field, so we
        don't have to scan for the closing 0x7E flag — which is important
        because some serial-over-TCP gateways pass 0x7E bytes through raw
        (without byte stuffing). Scanning for 0x7E as a delimiter would
        incorrectly truncate frames whose address or payload contains 0x7E.

        Reading strategy:
          1. Scan byte-by-byte until we find an opening 0x7E flag
          2. Read the 2-byte frame format field
          3. Extract the lower 11 bits = total frame length (incl. flags)
          4. Read the remaining bytes for that frame
          5. Sanity-check: the last byte should be a 0x7E closing flag
          6. Validate the FCS

        If validation fails, discard and resume scanning from the next byte.
        """
        if self._sock is None:
            raise TransportError("TCP transport is not open")

        from . import hdlc as _hdlc

        self._sock.settimeout(timeout)
        debug = bytearray()

        def _read_exactly(n: int) -> bytes:
            """Read exactly n bytes from the socket, or raise."""
            buf = bytearray()
            while len(buf) < n:
                chunk = self._sock.recv(n - len(buf))
                if not chunk:
                    raise TransportError(
                        f"TCP connection closed mid-frame. "
                        f"All bytes received: {bytes(debug).hex(' ').upper()}"
                    )
                buf.extend(chunk)
                debug.extend(chunk)
            return bytes(buf)

        try:
            while True:
                # 1. Find the opening flag
                first = _read_exactly(1)
                if first[0] != HDLC_FLAG:
                    continue  # not a flag; keep scanning

                # 2. Read the frame format (2 bytes)
                ff_bytes = _read_exactly(2)
                ff       = int.from_bytes(ff_bytes, "big")

                # 3. Validate the frame format identifier (top 4 bits = 0xA for type-3)
                if (ff >> 12) != 0xA:
                    # Not a valid HDLC frame here. The 0x7E we read might have
                    # been a stray byte; resume scanning. (We can't reliably
                    # back up, but the next iteration will pick up where we are.)
                    continue

                # 4. Extract length and read the rest of the frame
                # claimed_len = bytes between the opening and closing flags
                # (i.e. frame format + addresses + control + [HCS] + [info] + FCS)
                claimed_len = ff & 0x07FF
                total_len   = claimed_len + 2   # add the two flags
                remaining   = total_len - 3     # we've already read flag(1) + ff(2)
                if remaining < 1:
                    continue  # impossibly short

                tail = _read_exactly(remaining)

                # 5. Last byte must be the closing flag
                if tail[-1] != HDLC_FLAG:
                    continue  # malformed; discard

                # 6. Validate FCS
                full    = bytes([HDLC_FLAG]) + ff_bytes + tail
                payload = full[1:-3]   # everything between flags except the 2-byte FCS
                received_fcs = int.from_bytes(full[-3:-1], "little")
                if _hdlc.fcs16(payload) != received_fcs:
                    continue   # bad checksum; discard

                return full

        except socket.timeout as e:
            raise TransportError(
                f"TCP recv timeout after {timeout}s. "
                f"Bytes received so far: {bytes(debug).hex(' ').upper() or '(none)'}"
            ) from e
        except OSError as e:
            raise TransportError(f"TCP recv failed: {e}") from e


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------

class UdpTransport(Transport):
    """
    UDP connection to a serial device server.

    Each HDLC frame is carried as a single UDP datagram.
    """

    # Max UDP payload we'll ever need — comfortably above any HDLC frame.
    _RECV_BUFFER = 4096

    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._sock: socket.socket | None = None

    def open(self) -> None:
        if self._sock is not None:
            return
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.connect((self._host, self._port))
        except OSError as e:
            raise TransportError(f"UDP setup for {self._host}:{self._port} failed: {e}") from e

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def send(self, data: bytes) -> None:
        if self._sock is None:
            raise TransportError("UDP transport is not open")
        try:
            self._sock.send(data)
        except OSError as e:
            raise TransportError(f"UDP send failed: {e}") from e

    def recv_frame(self, timeout: float) -> bytes:
        if self._sock is None:
            raise TransportError("UDP transport is not open")

        self._sock.settimeout(timeout)
        try:
            data = self._sock.recv(self._RECV_BUFFER)
        except socket.timeout as e:
            raise TransportError(f"UDP recv timeout after {timeout}s") from e
        except OSError as e:
            raise TransportError(f"UDP recv failed: {e}") from e

        if len(data) < 2 or data[0] != HDLC_FLAG or data[-1] != HDLC_FLAG:
            raise TransportError(f"UDP datagram is not a valid HDLC frame: {data.hex()}")

        return data
