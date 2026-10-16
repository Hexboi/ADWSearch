# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""MC-NBFSE: in-band StringTable framing wrapped around an NBFX document.

A message is a StringTable (a MultiByteInt31 byte-size prefix followed by the dynamic
dictionary strings) immediately followed by the NBFX body.
"""

from . import dictionary
from .decoder import decode
from .encoder import encode
from .primitives import Reader, encode_multibyteint31, encode_string


def build_stringtable(strings) -> bytes:
    body = bytearray()
    for text in strings:
        body += encode_string(text)
    return encode_multibyteint31(len(body)) + bytes(body)


def parse_stringtable(data, offset: int = 0):
    reader = Reader(data)
    reader.pos = offset
    size = reader.read_multibyteint31()
    end = reader.pos + size
    if end > len(reader.data):
        raise ValueError("string table size exceeds the available data")
    strings = []
    while reader.pos < end:
        strings.append(reader.read_string())
    if reader.pos != end:
        raise ValueError("string table overran its declared size")
    return strings, reader.pos


class NbfseSessionDecoder:
    """One cumulative inbound dynamic dictionary per connection.

    Commit the delta only after the entire message has decoded successfully.
    A Resource connection must never share this state with Enumeration.
    """
    def __init__(self, static_dictionary=None):
        self._static = dict(static_dictionary if static_dictionary is not None
                            else dictionary.STATIC_DICTIONARY)
        self._dynamic = []
        self._seen = set()

    def decode_message(self, data):
        strings, offset = parse_stringtable(data)
        if len(set(strings)) != len(strings) or self._seen.intersection(strings):
            raise ValueError('duplicate NBFSE dynamic dictionary string')
        candidate = self._dynamic + strings
        records = decode(bytes(data)[offset:], dictionary.merge(self._static, candidate))
        self._dynamic = candidate
        self._seen.update(strings)
        return records


def decode_message(data, static_dictionary=None):
    """Decode one standalone message using a fresh temporary session."""
    return NbfseSessionDecoder(static_dictionary).decode_message(data)


def encode_message(events) -> bytes:
    # We never emit dynamic dictionary strings, so the StringTable is always empty.
    return build_stringtable([]) + encode(events)
