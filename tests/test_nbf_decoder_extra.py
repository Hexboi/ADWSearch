# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Decoder coverage for the record types deferred in the first pass.

All byte vectors are taken verbatim from [MC-NBFX] Structure Examples.
"""

from datetime import datetime, timedelta
from decimal import Decimal

from adwsearch.transport.nbf import decoder
from adwsearch.transport.nbf.records import (
    Attribute, EndElement, StartElement, Text,
)


def d(hexstr, dictionary=None):
    return decoder.decode(bytes.fromhex(hexstr.replace(" ", "")), dictionary)


def test_datetime_text():
    # 40 01 "a" 97 <8 bytes>  ->  <a>2006-05-17T00:00:00</a>
    assert d("40 01 61 97 00 40 8E F9 5B 47 C8 08") == [
        StartElement(None, "a"), Text(datetime(2006, 5, 17, 0, 0, 0)), EndElement()]


def test_decimal_text_attribute():
    # 40 03 "doc" 04 03 "int" 94 <16 bytes> 01  ->  <doc int="5.123456"></doc>
    assert d("40 03 64 6F 63 04 03 69 6E 74 94 "
             "00 00 06 00 00 00 00 00 80 2D 4E 00 00 00 00 00 01") == [
        StartElement(None, "doc"), Attribute(None, "int", Decimal("5.123456")), EndElement()]


def test_decimal_max_value():
    # 40 08 "MaxValue" 95 <16 bytes>  ->  79228162514264337593543950335
    assert d("40 08 4D 61 78 56 61 6C 75 65 95 "
             "00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF")[1] == \
        Text(Decimal("79228162514264337593543950335"))


def test_timespan_text():
    # 40 03 "doc" AE <8 bytes> 01  ->  <doc>-PT5M44S</doc>  (=-344 seconds)
    assert d("40 03 64 6F 63 AE 00 C4 F5 32 FF FF FF FF 01") == [
        StartElement(None, "doc"), Text(timedelta(seconds=-344)), EndElement()]


def test_list_attribute_value():
    # 40 03 "doc" 04 01 "a" A4 88 7B 98 05 "hello" 86 A6 01  ->  <doc a="123 hello true">
    assert d("40 03 64 6F 63 04 01 61 A4 88 7B 98 05 68 65 6C 6C 6F 86 A6 01") == [
        StartElement(None, "doc"), Attribute(None, "a", [123, "hello", True]), EndElement()]


def test_qname_dictionary_text_content():
    # 40 04 "Type" BD 12 <name id=912>  ->  <Type>s:...</Type>
    assert d("40 04 54 79 70 65 BD 12 90 07", {912: "MyType"}) == [
        StartElement(None, "Type"), Text("s:MyType"), EndElement()]


def test_array_of_int16():
    # 03 40 03 "arr" 01 8B 03 <3x int16>  ->  three <arr> values
    assert d("03 40 03 61 72 72 01 8B 03 33 33 88 88 DD DD") == [
        StartElement(None, "arr"), Text(13107), EndElement(),
        StartElement(None, "arr"), Text(-30584), EndElement(),
        StartElement(None, "arr"), Text(-8739), EndElement(),
    ]
