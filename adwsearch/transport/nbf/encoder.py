# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Encode a flat list of logical records into an NBFX byte stream (MC-NBFX).

The encoder always emits inline strings (never dictionary references) and the plain
(even) text records followed by an explicit EndElement. This keeps encoding independent
of the static/dynamic dictionaries: the ADWS server accepts inline strings. Decoding
the result reproduces the original records.
"""

from . import constants as c
from .primitives import encode_multibyteint31, encode_string
from .records import Attribute, Comment, EndElement, StartElement, Text, Xmlns


def encode(events) -> bytes:
    out = bytearray()
    for event in events:
        out += _encode_event(event)
    return bytes(out)


def _encode_event(event) -> bytes:
    if isinstance(event, StartElement):
        if event.prefix is None:
            return bytes([c.SHORT_ELEMENT]) + encode_string(event.name)
        return bytes([c.ELEMENT]) + encode_string(event.prefix) + encode_string(event.name)

    if isinstance(event, Xmlns):
        if event.prefix is None:
            return bytes([c.SHORT_XMLNS_ATTRIBUTE]) + encode_string(event.value)
        return (bytes([c.XMLNS_ATTRIBUTE])
                + encode_string(event.prefix) + encode_string(event.value))

    if isinstance(event, Attribute):
        if event.prefix is None:
            head = bytes([c.SHORT_ATTRIBUTE]) + encode_string(event.name)
        else:
            head = (bytes([c.ATTRIBUTE])
                    + encode_string(event.prefix) + encode_string(event.name))
        return head + _encode_text_value(event.value)

    if isinstance(event, Text):
        return _encode_text_value(event.value)

    if isinstance(event, EndElement):
        return bytes([c.END_ELEMENT])

    if isinstance(event, Comment):
        return bytes([c.COMMENT]) + encode_string(event.text)

    raise TypeError(f"cannot encode event of type {type(event).__name__}")


def _encode_text_value(value) -> bytes:
    # bool must be checked before int (bool is a subclass of int).
    if isinstance(value, bool):
        return bytes([0x86 if value else 0x84])

    if isinstance(value, int):
        if -(2 ** 31) <= value < 2 ** 31:
            return bytes([0x8C]) + value.to_bytes(4, "little", signed=True)
        if -(2 ** 63) <= value < 2 ** 63:
            return bytes([0x8E]) + value.to_bytes(8, "little", signed=True)
        if 0 <= value < 2 ** 64:
            return bytes([0xB2]) + value.to_bytes(8, "little")
        raise ValueError("integer out of range for NBFX text records")

    if isinstance(value, str):
        data = value.encode("utf-8")
        return _length_prefixed(0x98, 0x9A, 0x9C, data)

    if isinstance(value, (bytes, bytearray)):
        return _length_prefixed(0x9E, 0xA0, 0xA2, bytes(value))

    if value is None:
        return bytes([0xA8])  # EmptyText

    raise TypeError(f"cannot encode text value of type {type(value).__name__}")


def _length_prefixed(t8, t16, t32, data: bytes) -> bytes:
    n = len(data)
    if n < 0x100:
        return bytes([t8, n]) + data
    if n < 0x10000:
        return bytes([t16]) + n.to_bytes(2, "little") + data
    return bytes([t32]) + n.to_bytes(4, "little") + data


# encode_multibyteint31 is re-exported for callers that build framing around NBFX.
__all__ = ["encode", "encode_multibyteint31"]
