# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Decode an NBFX byte stream (MC-NBFX) into a flat list of logical records.

Dictionary strings (static from MC-NBFS, dynamic from MC-NBFSE) are resolved through
an injected ``dictionary`` mapping ``{id: string}``; callers that only ever emit inline
strings can pass ``None``.
"""

import struct
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from . import constants as c
from .primitives import Reader
from .records import Attribute, Comment, EndElement, StartElement, Text, Xmlns


def decode(data, dictionary=None):
    reader = Reader(data)
    events = []
    while not reader.eof():
        _read_record(reader, reader.read_byte(), events, dictionary)
    return events


def _resolve(dictionary, dict_id):
    if dictionary is None or dict_id not in dictionary:
        raise KeyError(f"NBF dictionary id {dict_id} is not defined")
    return dictionary[dict_id]


def _read_record(r, t, events, dic):
    if t == c.END_ELEMENT:
        events.append(EndElement())
    elif t == c.COMMENT:
        events.append(Comment(r.read_string()))
    elif t == c.ARRAY:
        _read_array(r, events, dic)
    elif c.SHORT_ELEMENT <= t <= c.PREFIX_ELEMENT_MAX:
        events.append(_read_element(r, t, dic))
    elif c.SHORT_ATTRIBUTE <= t <= c.PREFIX_ATTRIBUTE_MAX:
        _read_attribute(r, t, events, dic)
    elif c.TEXT_MIN <= t <= c.TEXT_MAX:
        events.append(Text(_read_text_value(r, t & 0xFE, dic)))
        if t & 0x01:
            events.append(EndElement())
    else:
        raise ValueError(f"unknown NBFX record type 0x{t:02X}")


def _read_element(r, t, dic):
    if t == c.SHORT_ELEMENT:
        return StartElement(None, r.read_string())
    if t == c.ELEMENT:
        prefix = r.read_string()
        return StartElement(prefix, r.read_string())
    if t == c.SHORT_DICTIONARY_ELEMENT:
        return StartElement(None, _resolve(dic, r.read_multibyteint31()))
    if t == c.DICTIONARY_ELEMENT:
        prefix = r.read_string()
        return StartElement(prefix, _resolve(dic, r.read_multibyteint31()))
    if c.PREFIX_DICTIONARY_ELEMENT_MIN <= t <= c.PREFIX_DICTIONARY_ELEMENT_MAX:
        prefix = chr(ord("a") + t - c.PREFIX_DICTIONARY_ELEMENT_MIN)
        return StartElement(prefix, _resolve(dic, r.read_multibyteint31()))
    prefix = chr(ord("a") + t - c.PREFIX_ELEMENT_MIN)
    return StartElement(prefix, r.read_string())


def _read_attribute(r, t, events, dic):
    if t == c.SHORT_XMLNS_ATTRIBUTE:
        events.append(Xmlns(None, r.read_string()))
        return
    if t == c.XMLNS_ATTRIBUTE:
        prefix = r.read_string()
        events.append(Xmlns(prefix, r.read_string()))
        return
    if t == c.SHORT_DICTIONARY_XMLNS_ATTRIBUTE:
        events.append(Xmlns(None, _resolve(dic, r.read_multibyteint31())))
        return
    if t == c.DICTIONARY_XMLNS_ATTRIBUTE:
        prefix = r.read_string()
        events.append(Xmlns(prefix, _resolve(dic, r.read_multibyteint31())))
        return

    if t == c.SHORT_ATTRIBUTE:
        prefix, name = None, r.read_string()
    elif t == c.ATTRIBUTE:
        prefix, name = r.read_string(), r.read_string()
    elif t == c.SHORT_DICTIONARY_ATTRIBUTE:
        prefix, name = None, _resolve(dic, r.read_multibyteint31())
    elif t == c.DICTIONARY_ATTRIBUTE:
        prefix, name = r.read_string(), _resolve(dic, r.read_multibyteint31())
    elif c.PREFIX_DICTIONARY_ATTRIBUTE_MIN <= t <= c.PREFIX_DICTIONARY_ATTRIBUTE_MAX:
        prefix = chr(ord("a") + t - c.PREFIX_DICTIONARY_ATTRIBUTE_MIN)
        name = _resolve(dic, r.read_multibyteint31())
    else:
        prefix = chr(ord("a") + t - c.PREFIX_ATTRIBUTE_MIN)
        name = r.read_string()

    events.append(Attribute(prefix, name, _read_attribute_value(r, dic)))


def _read_attribute_value(r, dic):
    t = r.read_byte()
    if t == c.STARTLIST_TEXT:
        return _read_list(r, dic)
    if not (c.TEXT_MIN <= t <= c.TEXT_MAX):
        raise ValueError(f"expected a text record as attribute value, got 0x{t:02X}")
    return _read_text_value(r, t & 0xFE, dic)


def _read_list(r, dic):
    values = []
    while True:
        t = r.read_byte()
        if t == c.ENDLIST_TEXT:
            return values
        if not (c.TEXT_MIN <= t <= c.TEXT_MAX):
            raise ValueError(f"unexpected record 0x{t:02X} inside a list")
        values.append(_read_text_value(r, t & 0xFE, dic))


def _read_array(r, events, dic):
    element = _read_element(r, r.read_byte(), dic)
    if r.read_byte() != c.END_ELEMENT:
        raise ValueError("array template element must be followed by EndElement")
    value_type = r.read_byte() & 0xFE
    count = r.read_multibyteint31()
    for _ in range(count):
        events.append(StartElement(element.prefix, element.name))
        events.append(Text(_read_text_value(r, value_type, dic)))
        events.append(EndElement())


def _read_int(r, size, signed):
    return int.from_bytes(r.read_bytes(size), "little", signed=signed)


def _read_chars(r, len_bytes):
    n = int.from_bytes(r.read_bytes(len_bytes), "little")
    return r.read_bytes(n).decode("utf-8")


def _read_unicode_chars(r, len_bytes):
    n = int.from_bytes(r.read_bytes(len_bytes), "little")
    return r.read_bytes(n).decode("utf-16-le")


def _read_bytes_value(r, len_bytes):
    n = int.from_bytes(r.read_bytes(len_bytes), "little")
    return r.read_bytes(n)


def _read_guid(r):
    return str(uuid.UUID(bytes_le=r.read_bytes(16)))


def _read_datetime(r, dic):
    raw = int.from_bytes(r.read_bytes(8), "little")
    kind = (raw >> 62) & 0x3
    ticks = raw & 0x3FFFFFFFFFFFFFFF
    value = datetime(1, 1, 1) + timedelta(microseconds=ticks // 10)
    if kind == 1:  # DateTimeKind.Utc
        value = value.replace(tzinfo=timezone.utc)
    return value


def _read_decimal(r, dic):
    r.read_bytes(2)  # reserved, must be zero
    scale = r.read_byte()
    sign = r.read_byte()
    hi = int.from_bytes(r.read_bytes(4), "little")
    lo = int.from_bytes(r.read_bytes(4), "little")
    mid = int.from_bytes(r.read_bytes(4), "little")
    coefficient = (hi << 64) | (mid << 32) | lo
    # Build the Decimal from its digit tuple so it is exact (28+ significant digits are
    # possible and scaleb() would otherwise round to the context precision).
    digits = tuple(int(ch) for ch in str(coefficient))
    return Decimal((1 if sign & 0x80 else 0, digits, -scale))


def _read_timespan(r, dic):
    # TimeSpan is a signed int64 of 100-nanosecond ticks. ``//`` keeps the
    # result an int so ``timedelta`` doesn't accrue binary-float rounding on
    # large spans.
    ticks = int.from_bytes(r.read_bytes(8), "little", signed=True)
    return timedelta(microseconds=ticks // 10)


def _read_qname(r, dic):
    prefix_index = r.read_byte()
    return chr(ord("a") + prefix_index) + ":" + _resolve(dic, r.read_multibyteint31())


# base (even) text record type -> reader(reader, dictionary) -> python value
_TEXT_VALUE = {
    0x80: lambda r, d: 0,
    0x82: lambda r, d: 1,
    0x84: lambda r, d: False,
    0x86: lambda r, d: True,
    0x88: lambda r, d: _read_int(r, 1, True),
    0x8A: lambda r, d: _read_int(r, 2, True),
    0x8C: lambda r, d: _read_int(r, 4, True),
    0x8E: lambda r, d: _read_int(r, 8, True),
    0x90: lambda r, d: struct.unpack("<f", r.read_bytes(4))[0],
    0x92: lambda r, d: struct.unpack("<d", r.read_bytes(8))[0],
    0x94: _read_decimal,
    0x96: _read_datetime,
    0x98: lambda r, d: _read_chars(r, 1),
    0x9A: lambda r, d: _read_chars(r, 2),
    0x9C: lambda r, d: _read_chars(r, 4),
    0x9E: lambda r, d: _read_bytes_value(r, 1),
    0xA0: lambda r, d: _read_bytes_value(r, 2),
    0xA2: lambda r, d: _read_bytes_value(r, 4),
    0xA8: lambda r, d: "",
    0xAA: lambda r, d: _resolve(d, r.read_multibyteint31()),
    0xAC: lambda r, d: "urn:uuid:" + _read_guid(r),
    0xB0: lambda r, d: _read_guid(r),
    0xAE: _read_timespan,
    0xB2: lambda r, d: _read_int(r, 8, False),
    0xB4: lambda r, d: bool(r.read_byte()),
    0xB6: lambda r, d: _read_unicode_chars(r, 1),
    0xB8: lambda r, d: _read_unicode_chars(r, 2),
    0xBA: lambda r, d: _read_unicode_chars(r, 4),
    0xBC: _read_qname,
}


def _read_text_value(r, base, dic):
    # StartList/EndList (0xA4/0xA6) are structural and handled in attribute context only.
    try:
        reader_fn = _TEXT_VALUE[base]
    except KeyError:
        raise ValueError(
            f"unknown or unsupported NBFX text record type 0x{base:02X}"
        ) from None
    return reader_fn(r, dic)
