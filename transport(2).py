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
        Read bytes from the socket until a complete, well-formed HDLC frame
        arrives.

        An HDLC frame is delimited by 0x7E flags, but on a shared bus we
        may receive stray bytes, partial frames, or back-to-back frames
        with shared flags. So we:
          1. Skip junk until we see an opening 0x7E
          2. Read bytes until the closing 0x7E
          3. Validate the candidate frame (length + FCS)
          4. If invalid, discard and resume scanning for the next opening flag

        This is robust to interleaved noise and TCP-level fragmentation.
        """
        if self._sock is None:
            raise TransportError("TCP transport is not open")

        # Import lazily to avoid a circular dependency at module load time
        from . import hdlc as _hdlc

        self._sock.settimeout(timeout)
        debug = bytearray()  # everything we've ever received this call

        def _read_one() -> int:
            b = self._sock.recv(1)
            if not b:
                raise TransportError(
                    f"TCP connection closed mid-frame. "
                    f"All bytes received: {bytes(debug).hex(' ').upper()}"
                )
            debug.append(b[0])
            return b[0]

        try:
            while True:
                # 1) Scan for opening flag
                while _read_one() != HDLC_FLAG:
                    pass

                # 2) Read until closing flag (skipping consecutive 0x7E shared flags)
                buf = bytearray([HDLC_FLAG])
                while True:
                    byte = _read_one()
                    if byte == HDLC_FLAG:
                        if len(buf) == 1:
                            # Two flags in a row (shared/back-to-back) — keep the
                            # second one as a fresh opener and continue.
                            continue
                        buf.append(byte)
                        break
                    buf.append(byte)

                # 3) Validate. Need at least: flag + frame-format(2) + dst(min 1) +
                #    src(1) + control(1) + FCS(2) + flag = 9 bytes.
                if len(buf) < 9:
                    continue  # too short to be valid; resume scanning

                # Frame format low 11 bits = total frame length (excluding flags? per spec, including).
                # Per ISO 13239 type-3 frame format: lower 11 bits = total length of the
                # frame, *excluding* the opening/closing flags. So total bytes = length + 2.
                ff = int.from_bytes(buf[1:3], "big")
                if (ff >> 12) != 0xA:
                    continue   # bad frame-format identifier
                claimed_len = ff & 0x07FF
                if len(buf) != claimed_len + 2:
                    continue   # length mismatch — almost certainly noise

                # Check FCS over everything between the flags except the FCS itself
                payload = bytes(buf[1:-3])
                received_fcs = int.from_bytes(buf[-3:-1], "little")
                if _hdlc.fcs16(payload) != received_fcs:
                    continue   # bad checksum — discard and keep looking

                return bytes(buf)

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
