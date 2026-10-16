# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from adwsearch.transport import nbf
from adwsearch.transport.nbf.records import EndElement, StartElement, Text


def test_package_level_message_roundtrip():
    events = [StartElement(None, "doc"), Text("hi"), EndElement()]
    raw = nbf.encode_message(events)
    assert nbf.decode_message(raw) == events


def test_package_level_nbfx_roundtrip():
    events = [StartElement(None, "a"), Text(123), EndElement()]
    assert nbf.decode(nbf.encode(events)) == events
