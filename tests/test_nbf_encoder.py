# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from adwsearch.transport.nbf import decoder, encoder
from adwsearch.transport.nbf.records import (
    Attribute, EndElement, StartElement, Text, Xmlns,
)


# --- exact bytes against [MC-NBFX] Structure Examples (inline encoding) ---

def test_encode_short_element_empty():
    assert encoder.encode([StartElement(None, "doc"), EndElement()]) == \
        bytes.fromhex("40 03 64 6F 63 01".replace(" ", ""))


def test_encode_element_with_text():
    assert encoder.encode([StartElement(None, "doc"), Text("hello"), EndElement()]) == \
        bytes.fromhex("40 03 64 6F 63 98 05 68 65 6C 6C 6F 01".replace(" ", ""))


def test_encode_element_with_prefix_and_xmlns():
    got = encoder.encode([
        StartElement("pre", "doc"), Xmlns("pre", "http://abc"), EndElement()])
    assert got == bytes.fromhex(
        "41 03 70 72 65 03 64 6F 63 09 03 70 72 65 0A "
        "68 74 74 70 3A 2F 2F 61 62 63 01".replace(" ", ""))


def test_encode_short_xmlns_default():
    got = encoder.encode([StartElement(None, "doc"), Xmlns(None, "http://abc"), EndElement()])
    assert got == bytes.fromhex(
        "40 03 64 6F 63 08 0A 68 74 74 70 3A 2F 2F 61 62 63 01".replace(" ", ""))


def test_encode_short_attribute_false():
    got = encoder.encode([
        StartElement(None, "doc"), Attribute(None, "attr", False), EndElement()])
    assert got == bytes.fromhex("40 03 64 6F 63 04 04 61 74 74 72 84 01".replace(" ", ""))


# --- round-trip through the decoder ---

def test_roundtrip_mixed_document():
    events = [
        StartElement("s", "Envelope"),
        Xmlns("s", "http://www.w3.org/2003/05/soap-envelope"),
        StartElement(None, "Body"),
        StartElement(None, "value"),
        Attribute(None, "flag", True),
        Attribute(None, "count", 42),
        Text("hello world"),
        EndElement(),
        StartElement(None, "blob"),
        Text(bytes(range(10))),
        EndElement(),
        EndElement(),
        EndElement(),
    ]
    assert decoder.decode(encoder.encode(events)) == events


def test_roundtrip_large_string_uses_wider_length():
    big = "x" * 300  # > 255 bytes -> must use Chars16, not Chars8
    events = [StartElement(None, "a"), Text(big), EndElement()]
    raw = encoder.encode(events)
    assert raw[3] == 0x9A  # Chars16Text
    assert decoder.decode(raw) == events


def test_roundtrip_int64():
    events = [StartElement(None, "a"), Text(2**40), EndElement()]
    assert decoder.decode(encoder.encode(events)) == events
