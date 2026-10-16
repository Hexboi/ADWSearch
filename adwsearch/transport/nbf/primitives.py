# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Low-level primitives for the NBF codec (MC-NBFX section 2.1).

- MultiByteInt31: variable-length unsigned integer, 7 bits per byte, little-endian
  groups, high bit = "more bytes follow".
- String: MultiByteInt31 byte-length prefix followed by the UTF-8 bytes.
"""

_MAX_MULTIBYTEINT31 = 0x7FFFFFFF


def encode_multibyteint31(value: int) -> bytes:
    if value < 0:
        raise ValueError("MultiByteInt31 cannot encode a negative value")
    if value > _MAX_MULTIBYTEINT31:
        raise ValueError("MultiByteInt31 is limited to 31 bits")
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


def encode_string(text: str) -> bytes:
    data = text.encode("utf-8")
    return encode_multibyteint31(len(data)) + data


class Reader:
    """A forward cursor over a bytes buffer."""

    def __init__(self, data):
        self.data = bytes(data)
        self.pos = 0

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise EOFError("unexpected end of NBF stream")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def read_bytes(self, count: int) -> bytes:
        end = self.pos + count
        if end > len(self.data):
            raise EOFError("unexpected end of NBF stream")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def read_multibyteint31(self) -> int:
        value = 0
        shift = 0
        while True:
            byte = self.read_byte()
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
            if shift >= 35:
                raise ValueError("MultiByteInt31 is too long (more than 5 bytes)")

    def read_string(self) -> str:
        length = self.read_multibyteint31()
        return self.read_bytes(length).decode("utf-8")
