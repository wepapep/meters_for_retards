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

from hdlc import HDLC_FLAG


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
        Read bytes from the socket until a complete HDLC frame is formed.

        An HDLC frame is delimited by 0x7E flags. We read the opening flag,
        then continue reading until we see the closing flag.
        """
        if self._sock is None:
            raise TransportError("TCP transport is not open")

        self._sock.settimeout(timeout)
        buf = bytearray()

        try:
            # Skip junk until we find the opening flag
            while True:
                b = self._sock.recv(1)
                if not b:
                    raise TransportError("TCP connection closed while waiting for frame")
                if b[0] == HDLC_FLAG:
                    buf.append(b[0])
                    break

            # Read until the closing flag
            while True:
                b = self._sock.recv(1)
                if not b:
                    raise TransportError("TCP connection closed mid-frame")
                buf.append(b[0])
                if b[0] == HDLC_FLAG and len(buf) > 1:
                    # Some devices send a shared flag between back-to-back frames,
                    # so if buf is exactly "7E 7E" treat the second as the opener
                    # of this frame (keep reading).
                    if len(buf) == 2:
                        buf = bytearray([HDLC_FLAG])
                        continue
                    break
        except socket.timeout as e:
            raise TransportError(f"TCP recv timeout after {timeout}s") from e
        except OSError as e:
            raise TransportError(f"TCP recv failed: {e}") from e

        return bytes(buf)


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
