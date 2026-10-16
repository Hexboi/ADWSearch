# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from adwsearch.transport.nbf import dictionary, nbfse
from adwsearch.transport.nbf.records import EndElement, StartElement


def fh(s):
    return bytes.fromhex(s.replace(" ", ""))


# --- StringTable (MC-NBFSE section 2.1); golden vector from MC-NBFSE Examples ---

def test_build_stringtable_matches_spec_example():
    assert nbfse.build_stringtable(["action", "Inventory"]) == fh(
        "11 06 61 63 74 69 6F 6E 09 49 6E 76 65 6E 74 6F 72 79")


def test_parse_stringtable_matches_spec_example():
    strings, offset = nbfse.parse_stringtable(
        fh("11 06 61 63 74 69 6F 6E 09 49 6E 76 65 6E 74 6F 72 79"))
    assert strings == ["action", "Inventory"]
    assert offset == 18


def test_empty_stringtable():
    assert nbfse.build_stringtable([]) == b"\x00"
    strings, offset = nbfse.parse_stringtable(b"\x00\x40")
    assert strings == []
    assert offset == 1


def test_overrun_stringtable_rejected():
    # declared size 5 but only a 3-byte string record follows
    import pytest
    with pytest.raises(ValueError):
        nbfse.parse_stringtable(fh("05 02 61 62"))


# --- dictionary merge: static entries at even ids, dynamic at odd ids (1,3,5,...) ---

def test_merge_assigns_odd_ids_to_dynamic_strings():
    merged = dictionary.merge({0: "s0", 2: "s2"}, ["action", "Inventory"])
    assert merged == {0: "s0", 2: "s2", 1: "action", 3: "Inventory"}


# --- end to end: StringTable + NBFX body resolved together ---

def test_decode_message_resolves_dynamic_dictionary():
    # StringTable: [ "Inventory" ] -> id 1 ; body: ShortDictionaryElement(id=1) EndElement
    msg = fh("0A 09 49 6E 76 65 6E 74 6F 72 79 42 01 01")
    assert nbfse.decode_message(msg) == [StartElement(None, "Inventory"), EndElement()]


def test_encode_message_prepends_empty_stringtable():
    got = nbfse.encode_message([StartElement(None, "doc"), EndElement()])
    assert got == b"\x00" + fh("40 03 64 6F 63 01")


def test_decode_message_uses_real_static_dictionary_by_default():
    # empty StringTable (00) + ShortDictionaryElement(id=0x02 -> "Envelope") + EndElement
    assert nbfse.decode_message(fh("00 42 02 01")) == [
        StartElement(None, "Envelope"), EndElement()]


def test_session_reuses_string_from_previous_document():
    session = nbfse.NbfseSessionDecoder()
    first = nbfse.build_stringtable(['Inventory']) + fh('42 01 01')
    assert session.decode_message(first) == session.decode_message(fh('00 42 01 01'))


def test_session_appends_new_ids_and_isolates_connections():
    import pytest
    session = nbfse.NbfseSessionDecoder()
    session.decode_message(nbfse.build_stringtable(['Inventory']) + fh('42 01 01'))
    result = session.decode_message(nbfse.build_stringtable(['Other']) + fh('42 03 01'))
    assert result == [StartElement(None, 'Other'), EndElement()]
    with pytest.raises(KeyError):
        nbfse.NbfseSessionDecoder().decode_message(fh('00 42 03 01'))


def test_duplicate_or_malformed_delta_does_not_commit_state():
    import pytest
    session = nbfse.NbfseSessionDecoder()
    session.decode_message(nbfse.build_stringtable(['Inventory']) + fh('42 01 01'))
    for data in (nbfse.build_stringtable(['Inventory']) + fh('42 01 01'),
                 nbfse.build_stringtable(['Other', 'Other']) + fh('42 03 01'),
                 fh('05 02 61 62'), nbfse.build_stringtable(['Invalid']) + b'\xff'):
        with pytest.raises(ValueError):
            session.decode_message(data)
    assert session.decode_message(nbfse.build_stringtable(['Other']) + fh('42 03 01')) == [
        StartElement(None, 'Other'), EndElement()]

