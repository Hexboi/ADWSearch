# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""MC-NMF: .NET Message Framing Protocol.

Framing for SOAP messages over the net.tcp transport (ADWS, TCP/9389). This module
builds and parses the individual framing records and the preamble. The full connection
handshake (preamble -> Negotiate upgrade -> NNS-secured Sized Envelopes) is assembled in
the connection layer, where the NNS security context is available.

Client flow for a secured Duplex connection:
    1. send Preamble  (Version, Mode=Duplex, Via, KnownEncoding=binary-session)
    2. send UpgradeRequest("application/negotiate")
    3. read UpgradeResponse, then run the NNS (Negotiate) handshake on the raw stream
    4. send PreambleEnd, read PreambleAck  (through the now-secured stream)
    5. exchange Sized Envelope records (each carrying an NBFSE message)
    6. End record to close
"""

from .nbf.primitives import Reader, encode_multibyteint31, encode_string

# Record types (MC-NMF section 2.1.1.1)
RT_VERSION = 0x00
RT_MODE = 0x01
RT_VIA = 0x02
RT_KNOWN_ENCODING = 0x03
RT_EXTENSIBLE_ENCODING = 0x04
RT_UNSIZED_ENVELOPE = 0x05
RT_SIZED_ENVELOPE = 0x06
RT_END = 0x07
RT_FAULT = 0x08
RT_UPGRADE_REQUEST = 0x09
RT_UPGRADE_RESPONSE = 0x0A
RT_PREAMBLE_ACK = 0x0B
RT_PREAMBLE_END = 0x0C

# Framing version (MC-NMF section 2.2.3.1)
MAJOR_VERSION = 0x01
MINOR_VERSION = 0x00

# Mode values (MC-NMF section 2.2.3.2)
MODE_SINGLETON_UNSIZED = 0x01
MODE_DUPLEX = 0x02
MODE_SIMPLEX = 0x03
MODE_SINGLETON_SIZED = 0x04

# Known encoding values (MC-NMF section 2.2.3.4). ADWS uses the binary in-band
# dictionary encoding (MC-NBFSE).
ENCODING_SOAP12_UTF8 = 0x03
ENCODING_BINARY = 0x07          # MC-NBFS
ENCODING_BINARY_SESSION = 0x08  # MC-NBFSE

# Upgrade protocol names (MC-NMF section 2.2.3.5)
UPGRADE_NEGOTIATE = "application/negotiate"
UPGRADE_SSL_TLS = "application/ssl-tls"


# --- record builders -------------------------------------------------------

def version_record() -> bytes:
    return bytes([RT_VERSION, MAJOR_VERSION, MINOR_VERSION])


def mode_record(mode: int = MODE_DUPLEX) -> bytes:
    return bytes([RT_MODE, mode])


def via_record(uri: str) -> bytes:
    return bytes([RT_VIA]) + encode_string(uri)


def known_encoding_record(encoding: int = ENCODING_BINARY_SESSION) -> bytes:
    return bytes([RT_KNOWN_ENCODING, encoding])


def upgrade_request_record(protocol: str = UPGRADE_NEGOTIATE) -> bytes:
    return bytes([RT_UPGRADE_REQUEST]) + encode_string(protocol)


def sized_envelope_record(payload: bytes) -> bytes:
    return bytes([RT_SIZED_ENVELOPE]) + encode_multibyteint31(len(payload)) + bytes(payload)


def preamble_end_record() -> bytes:
    return bytes([RT_PREAMBLE_END])


def end_record() -> bytes:
    return bytes([RT_END])


def build_preamble(via: str, mode: int = MODE_DUPLEX,
                   encoding: int = ENCODING_BINARY_SESSION) -> bytes:
    """Version + Mode + Via + KnownEncoding (MC-NMF Preamble Message, section 2.2.1)."""
    return version_record() + mode_record(mode) + via_record(via) + known_encoding_record(encoding)


# --- reading ---------------------------------------------------------------

_STRING_RECORDS = (RT_VIA, RT_EXTENSIBLE_ENCODING, RT_UPGRADE_REQUEST, RT_FAULT)
_EMPTY_RECORDS = (RT_END, RT_UPGRADE_RESPONSE, RT_PREAMBLE_ACK, RT_PREAMBLE_END)


def read_record(reader: Reader):
    """Read one framing record; return ``(record_type, data)``.

    data is: (major, minor) for Version; the octet for Mode/KnownEncoding; the string for
    Via/Upgrade/Fault; the payload bytes for a Sized Envelope; and None for the single-byte
    records (End, UpgradeResponse, PreambleAck, PreambleEnd).
    """
    rtype = reader.read_byte()
    if rtype == RT_VERSION:
        return rtype, (reader.read_byte(), reader.read_byte())
    if rtype in (RT_MODE, RT_KNOWN_ENCODING):
        return rtype, reader.read_byte()
    if rtype in _STRING_RECORDS:
        return rtype, reader.read_string()
    if rtype == RT_SIZED_ENVELOPE:
        size = reader.read_multibyteint31()
        return rtype, reader.read_bytes(size)
    if rtype in _EMPTY_RECORDS:
        return rtype, None
    raise ValueError(f"unsupported or unexpected NMF record type 0x{rtype:02X}")


def read_sized_envelope(reader: Reader) -> bytes:
    rtype, payload = read_record(reader)
    if rtype != RT_SIZED_ENVELOPE:
        raise ValueError(f"expected a Sized Envelope record, got 0x{rtype:02X}")
    return payload
