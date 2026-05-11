"""
meter.py — Generic high-level facade for DLMS/COSEM meters over HDLC.

The class is vendor-neutral and supports both referencing styles:
  - Logical Name (LN)   — standard, 6-byte OBIS + class_id + attribute
  - Short Name (SN)     — older meters (incl. L+G ZMD), 2-byte object code

And three authentication modes:
  - None / public client  (default)
  - Low Level Security (LLS) — password sent in plaintext
  - High Level Security (HLS) — challenge-response (handshake handled here
    for the basic case; some vendors use proprietary HLS)

Typical usage:

    # LN, no auth — works on most modern meters
    with Meter.over_tcp("192.168.1.10", 8000, serial=12345678) as m:
        val = m.read_ln("1-0:1.8.0", class_id=3, attribute=2)

    # SN, no auth — L+G ZMD and similar
    with Meter.over_tcp(host, port, serial,
                        referencing=Referencing.SN) as m:
        val = m.read_sn(0xC1C8)

    # LN with password
    with Meter.over_tcp(host, port, serial,
                        auth=AuthMech.LOW,
                        password=b"00000000") as m:
        ...

The return value of read_ln() / read_sn() is the decoded Python value
(int, float, str, bytes, ...) according to the DLMS data type tag.
Use read_raw_ln() / read_raw_sn() to get the bytes including the tag.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import hdlc, cosem, obis, data_types
from .cosem      import Referencing, AuthMech, AssociationResult
from .connection import (
    MeterConnection,
    MeterConnectionError,
    DEFAULT_TIMEOUT,
    DEFAULT_RETRIES,
)
from .transport  import Transport, TcpTransport, UdpTransport, TransportError


class MeterError(Exception):
    """Raised on any meter read failure."""


@dataclass
class MeterInfo:
    """Negotiated session parameters from the AARE."""
    server_max_pdu:         int | None
    negotiated_conformance: bytes | None


class Meter:
    """
    Generic DLMS/COSEM meter session.

    Manages HDLC session, COSEM association, and request/response exchange.
    Use the read_ln() / read_sn() methods depending on the meter's
    referencing style.
    """

    def __init__(
        self,
        transport:    Transport,
        serial:       int,
        umac:         int = 1,
        referencing:  Referencing = Referencing.LN,
        auth:         AuthMech    = AuthMech.NONE,
        password:     bytes | None = None,
        max_pdu_size: int = 0,
        timeout:      float = DEFAULT_TIMEOUT,
        retries:      int   = DEFAULT_RETRIES,
    ):
        self._serial       = serial
        self._referencing  = referencing
        self._auth         = auth
        self._password     = password
        self._max_pdu_size = max_pdu_size
        self._conn         = MeterConnection(
            transport, serial=serial, umac=umac,
            timeout=timeout, retries=retries,
        )
        self._ns           = 0
        self._nr           = 0
        self._associated   = False
        self._info: MeterInfo | None = None

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def over_tcp(cls, host: str, port: int, serial: int, **kwargs) -> "Meter":
        """Create a Meter with a dedicated TCP transport."""
        transport = TcpTransport(host, port)
        m = cls(transport, serial=serial, **kwargs)
        m._conn._owns_transport = True
        return m

    @classmethod
    def over_udp(cls, host: str, port: int, serial: int, **kwargs) -> "Meter":
        """Create a Meter with a dedicated UDP transport."""
        transport = UdpTransport(host, port)
        m = cls(transport, serial=serial, **kwargs)
        m._conn._owns_transport = True
        return m

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "Meter":
        self._conn.__enter__()
        try:
            self._associate()
        except Exception:
            self._conn.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._associated = False
        self._conn.__exit__(exc_type, exc, tb)

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def serial(self) -> int:
        return self._serial

    @property
    def info(self) -> MeterInfo | None:
        return self._info

    @property
    def referencing(self) -> Referencing:
        return self._referencing

    # ------------------------------------------------------------------
    # Association
    # ------------------------------------------------------------------

    def _associate(self) -> None:
        aarq = cosem.build_aarq(
            referencing=self._referencing,
            auth=self._auth,
            password=self._password,
            max_pdu_size=self._max_pdu_size,
        )
        response_info = self._exchange(aarq)
        aare: AssociationResult = cosem.parse_aare(response_info)
        if not aare.accepted:
            raise MeterError(
                f"AARE rejected: result={aare.result} "
                f"source={aare.result_source} "
                f"diagnostic={aare.result_diagnostic}"
            )

        # HLS would do challenge-response here using ACTION services.
        # Skipping for now — only NONE and LOW are fully supported.
        if self._auth in (AuthMech.HIGH, AuthMech.HIGH_MD5, AuthMech.HIGH_SHA1,
                          AuthMech.HIGH_GMAC, AuthMech.HIGH_SHA256, AuthMech.HIGH_ECDSA):
            raise NotImplementedError(
                f"HLS authentication ({self._auth.name}) requires the "
                "challenge-response ACTION exchange; not yet implemented."
            )

        self._info = MeterInfo(
            server_max_pdu=aare.server_max_pdu,
            negotiated_conformance=aare.negotiated_conformance,
        )
        self._associated = True

    # ------------------------------------------------------------------
    # Frame exchange
    # ------------------------------------------------------------------

    def _exchange(self, request_pdu: bytes) -> bytes:
        """Send a PDU, receive the response, return its info field."""
        frame = hdlc.build_iframe(
            serial=self._serial, ns=self._ns, nr=self._nr, info=request_pdu,
        )
        try:
            self._conn.send_frame(frame)
            raw = self._conn.recv_frame()
        except (TransportError, MeterConnectionError) as e:
            raise MeterError(f"Frame exchange failed: {e}") from e

        parsed = hdlc.parse_iframe(raw)
        if parsed is None:
            raise MeterError(f"Could not parse response as I-frame: {raw.hex()}")

        # Advance sequence numbers
        self._ns = (self._ns + 1) % 8
        self._nr = (self._nr + 1) % 8

        return parsed["info"]

    # ------------------------------------------------------------------
    # Read API — Logical Name (LN)
    # ------------------------------------------------------------------

    def read_ln(
        self,
        obis_code: str | bytes,
        class_id:  int = 3,
        attribute: int = 2,
    ) -> object:
        """
        Read a COSEM attribute by Logical Name (OBIS) and return the
        decoded Python value.

        Args:
            obis_code: OBIS in string form ('1-0:1.8.0', '0.0.96.1.0') or bytes.
            class_id:  COSEM class ID (default 3 = Register, used for most
                       measurements; 1 = Data for static values).
            attribute: attribute index (default 2 = value).

        Returns:
            Decoded Python value (int, float, str, datetime, list, ...).

        Raises:
            MeterError: on access failure.
        """
        raw = self.read_raw_ln(obis_code, class_id=class_id, attribute=attribute)
        return data_types.decode_one(raw)

    def read_raw_ln(
        self,
        obis_code: str | bytes,
        class_id:  int = 3,
        attribute: int = 2,
    ) -> bytes:
        """
        Read a COSEM attribute by Logical Name and return the raw
        tagged data bytes (caller decodes via data_types.decode).
        """
        if not self._associated:
            raise MeterError("Not associated — use 'with Meter(...)' first")

        obis_bytes = obis.encode(obis_code) if isinstance(obis_code, str) else obis_code

        request = cosem.build_get_request_ln(
            class_id=class_id, obis=obis_bytes, attribute=attribute,
        )
        response_info = self._exchange(request)
        response = cosem.parse_get_response(response_info)

        if not response.success:
            raise MeterError(
                f"GET failed for {obis.decode_canonical(obis_bytes)}: "
                f"data-access-error 0x{response.error:02X}"
            )
        return response.data

    # ------------------------------------------------------------------
    # Read API — Short Name (SN)
    # ------------------------------------------------------------------

    def read_sn(self, short_name: int) -> object:
        """
        Read a COSEM attribute by Short Name (2-byte object code) and
        return the decoded value.

        Args:
            short_name: 16-bit object code (e.g. 0xC1C8).
        """
        raw = self.read_raw_sn(short_name)
        return data_types.decode_one(raw)

    def read_raw_sn(self, short_name: int) -> bytes:
        """
        Read a COSEM attribute by Short Name and return the raw tagged
        data bytes (including data type tag and length).
        """
        if not self._associated:
            raise MeterError("Not associated — use 'with Meter(...)' first")

        request = cosem.build_read_request_sn(short_name)
        response_info = self._exchange(request)

        # Response layout (SN):  0C 01 00 <tagged data>
        if len(response_info) < 3 or response_info[0] != 0x0C:
            raise MeterError(f"Not a READ.response: {response_info.hex()}")
        status = response_info[2]
        if status != 0:
            raise MeterError(
                f"SN read 0x{short_name:04X} failed with status 0x{status:02X}"
            )
        return response_info[3:]   # the data starts at offset 3 (tag + count + status)
