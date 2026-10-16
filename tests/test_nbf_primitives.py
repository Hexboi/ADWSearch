# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import pytest

from adwsearch.transport.nbf import primitives as p


# --- MultiByteInt31 (MC-NBFX section 2.1.2); vectors from the official spec ---

@pytest.mark.parametrize("value,encoded", [
    (0, b"\x00"),
    (1, b"\x01"),
    (127, b"\x7f"),
    (128, b"\x80\x01"),
    (145, b"\x91\x01"),            # MC-NBFX MultiByteInt31 example
    (5521, b"\x91\x2b"),           # MC-NBFX MultiByteInt31 example
    (16383, b"\xff\x7f"),
    (16384, b"\x80\x80\x01"),
    (2097151, b"\xff\xff\x7f"),
    (2097152, b"\x80\x80\x80\x01"),
    (268435455, b"\xff\xff\xff\x7f"),
])
def test_multibyteint31_encode(value, encoded):
    assert p.encode_multibyteint31(value) == encoded


@pytest.mark.parametrize("value,encoded", [
    (0, b"\x00"),
    (127, b"\x7f"),
    (145, b"\x91\x01"),
    (5521, b"\x91\x2b"),
    (16384, b"\x80\x80\x01"),
])
def test_multibyteint31_read(value, encoded):
    r = p.Reader(encoded)
    assert r.read_multibyteint31() == value
    assert r.pos == len(encoded)


def test_multibyteint31_negative_rejected():
    with pytest.raises(ValueError):
        p.encode_multibyteint31(-1)


# --- length-prefixed UTF-8 string (MC-NBFX section 2.1.5) ---

def test_encode_string_ascii():
    assert p.encode_string("doc") == b"\x03doc"


def test_encode_string_utf8_length_is_byte_count():
    # "e" + U+00E9 -> 3 UTF-8 bytes, so the length prefix must be 3, not 2 chars
    assert p.encode_string("café") == b"\x05caf\xc3\xa9"


def test_read_string_roundtrip():
    r = p.Reader(p.encode_string("hello"))
    assert r.read_string() == "hello"
    assert r.pos == 6


# --- low-level Reader helpers ---

def test_reader_read_byte_and_bytes():
    r = p.Reader(b"\x40\x03doc")
    assert r.read_byte() == 0x40
    assert r.read_bytes(1) == b"\x03"
    assert r.read_bytes(3) == b"doc"
    assert r.eof()


def test_reader_byte_past_end_raises():
    r = p.Reader(b"")
    with pytest.raises(EOFError):
        r.read_byte()
