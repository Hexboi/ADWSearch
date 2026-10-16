# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from adwsearch.transport.nbf import decoder
from adwsearch.transport.nbf.records import (
    Attribute, EndElement, StartElement, Text, Xmlns,
)


def d(hexstr, dictionary=None):
    return decoder.decode(bytes.fromhex(hexstr.replace(" ", "")), dictionary)


# All byte vectors below are taken verbatim from [MC-NBFX] Structure Examples.

def test_short_element_empty():
    # 40 03 "doc" 01  ->  <doc></doc>
    assert d("40 03 64 6F 63 01") == [StartElement(None, "doc"), EndElement()]


def test_short_element_with_text():
    # 40 03 "doc" 98 05 "hello" 01  ->  <doc>hello</doc>
    assert d("40 03 64 6F 63 98 05 68 65 6C 6C 6F 01") == [
        StartElement(None, "doc"), Text("hello"), EndElement()]


def test_chars8_with_end_element():
    # 40 01 "a" 99 05 "hello"  ->  <a>hello</a>  (0x99 carries the EndElement)
    assert d("40 01 61 99 05 68 65 6C 6C 6F") == [
        StartElement(None, "a"), Text("hello"), EndElement()]


def test_short_attribute_false():
    # 40 03 "doc" 04 04 "attr" 84 01  ->  <doc attr="false"></doc>
    assert d("40 03 64 6F 63 04 04 61 74 74 72 84 01") == [
        StartElement(None, "doc"), Attribute(None, "attr", False), EndElement()]


def test_short_xmlns_attribute():
    # 40 03 "doc" 08 0A "http://abc" 01
    assert d("40 03 64 6F 63 08 0A 68 74 74 70 3A 2F 2F 61 62 63 01") == [
        StartElement(None, "doc"), Xmlns(None, "http://abc"), EndElement()]


def test_element_with_prefix_and_xmlns():
    # 41 03 "pre" 03 "doc" 09 03 "pre" 0A "http://abc" 01
    assert d("41 03 70 72 65 03 64 6F 63 09 03 70 72 65 0A "
             "68 74 74 70 3A 2F 2F 61 62 63 01") == [
        StartElement("pre", "doc"), Xmlns("pre", "http://abc"), EndElement()]


def test_prefix_element_letter_a():
    # 5E ("PrefixElementA") 05 "hello" 09 01 "a" 0A "http://abc" 01
    assert d("5E 05 68 65 6C 6C 6F 09 01 61 0A 68 74 74 70 3A 2F 2F 61 62 63 01") == [
        StartElement("a", "hello"), Xmlns("a", "http://abc"), EndElement()]


def test_bool_shortcut_texts():
    assert d("40 03 61 62 63 87")[1] == Text(True)   # TrueTextWithEndElement
    assert d("40 03 61 62 63 85")[1] == Text(False)  # FalseTextWithEndElement
    assert d("40 03 61 62 63 81")[1] == Text(0)      # ZeroTextWithEndElement
    assert d("40 03 61 62 63 83")[1] == Text(1)      # OneTextWithEndElement


def test_int32_max():
    # 40 01 "a" 8D FF FF FF 7F  ->  <a>2147483647</a>
    assert d("40 01 61 8D FF FF FF 7F") == [
        StartElement(None, "a"), Text(2147483647), EndElement()]


def test_int16_negative():
    # 40 01 "a" 8B 00 80  ->  <a>-32768</a>
    assert d("40 01 61 8B 00 80") == [
        StartElement(None, "a"), Text(-32768), EndElement()]


def test_bytes8_text_is_raw_bytes():
    # 40 03 "doc" 9E 08 00 01 02 03 04 05 06 07 01
    assert d("40 03 64 6F 63 9E 08 00 01 02 03 04 05 06 07 01")[1] == Text(bytes(range(8)))


def test_empty_attribute_value():
    # 40 03 "doc" 04 01 "a" A8 01  ->  <doc a=""></doc>
    assert d("40 03 64 6F 63 04 01 61 A8 01") == [
        StartElement(None, "doc"), Attribute(None, "a", ""), EndElement()]


def test_dictionary_text_resolves_via_injected_dictionary():
    # 40 04 "Type" AB <id=196> ; 0xAB is DictionaryTextWithEndElement
    assert d("40 04 54 79 70 65 AB C4 01", {196: "resolved"}) == [
        StartElement(None, "Type"), Text("resolved"), EndElement()]


def test_short_dictionary_element_resolves_name():
    # 42 0E 01  ->  <str14></str14> with id 14 resolved from the dictionary
    assert d("42 0E 01", {14: "Inventory"}) == [
        StartElement(None, "Inventory"), EndElement()]
