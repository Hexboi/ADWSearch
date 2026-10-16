# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""NBFX record type byte values (MC-NBFX section 2, Table 1)."""

END_ELEMENT = 0x01
COMMENT = 0x02
ARRAY = 0x03

# Attribute / xmlns records (0x04..0x3F)
SHORT_ATTRIBUTE = 0x04
ATTRIBUTE = 0x05
SHORT_DICTIONARY_ATTRIBUTE = 0x06
DICTIONARY_ATTRIBUTE = 0x07
SHORT_XMLNS_ATTRIBUTE = 0x08
XMLNS_ATTRIBUTE = 0x09
SHORT_DICTIONARY_XMLNS_ATTRIBUTE = 0x0A
DICTIONARY_XMLNS_ATTRIBUTE = 0x0B
PREFIX_DICTIONARY_ATTRIBUTE_MIN = 0x0C  # 'a'..'z' -> 0x0C..0x25
PREFIX_DICTIONARY_ATTRIBUTE_MAX = 0x25
PREFIX_ATTRIBUTE_MIN = 0x26             # 'a'..'z' -> 0x26..0x3F
PREFIX_ATTRIBUTE_MAX = 0x3F

# Element records (0x40..0x77)
SHORT_ELEMENT = 0x40
ELEMENT = 0x41
SHORT_DICTIONARY_ELEMENT = 0x42
DICTIONARY_ELEMENT = 0x43
PREFIX_DICTIONARY_ELEMENT_MIN = 0x44    # 'a'..'z' -> 0x44..0x5D
PREFIX_DICTIONARY_ELEMENT_MAX = 0x5D
PREFIX_ELEMENT_MIN = 0x5E               # 'a'..'z' -> 0x5E..0x77
PREFIX_ELEMENT_MAX = 0x77

# Text records occupy 0x80..0xBF; even = value, odd = value followed by EndElement.
TEXT_MIN = 0x80
TEXT_MAX = 0xBF

# List text records (valid only as an attribute value): a run of value records
# between StartList and EndList.
STARTLIST_TEXT = 0xA4
ENDLIST_TEXT = 0xA6
