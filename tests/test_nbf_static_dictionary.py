# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from adwsearch.transport.nbf import dictionary as di


def test_static_dictionary_is_complete_and_even():
    keys = sorted(di.STATIC_DICTIONARY)
    # MC-NBFS defines even ids 0x00..0x3CC (487 entries).
    assert keys == list(range(0, 973, 2))
    assert len(keys) == 487


def test_known_static_entries():
    d = di.STATIC_DICTIONARY
    assert d[0x00] == "mustUnderstand"
    assert d[0x02] == "Envelope"
    assert d[0x04] == "http://www.w3.org/2003/05/soap-envelope"
    assert d[0x06] == "http://www.w3.org/2005/08/addressing"
    assert d[0x08] == "Header"
    assert d[0x3CC] == "detail"


def test_merge_keeps_static_and_adds_dynamic():
    merged = di.merge(di.STATIC_DICTIONARY, ["dyn0", "dyn1"])
    assert merged[0x02] == "Envelope"  # static entry preserved
    assert merged[1] == "dyn0"         # dynamic entries at odd ids
    assert merged[3] == "dyn1"
