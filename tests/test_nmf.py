# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import pytest

from adwsearch.transport import nmf
from adwsearch.transport.nbf.primitives import Reader


# --- record builders: exact bytes from [MC-NMF] ---

def test_version_record():
    assert nmf.version_record() == b"\x00\x01\x00"


def test_mode_record_default_is_duplex():
    assert nmf.mode_record() == b"\x01\x02"
    assert nmf.mode_record(nmf.MODE_SINGLETON_SIZED) == b"\x01\x04"


def test_via_record():
    assert nmf.via_record("a") == b"\x02\x01a"


def test_via_record_multibyte_length():
    uri = "x" * 200
    assert nmf.via_record(uri) == b"\x02\xc8\x01" + b"x" * 200


def test_known_encoding_record_default_is_binary_session():
    assert nmf.known_encoding_record() == b"\x03\x08"
    assert nmf.known_encoding_record(nmf.ENCODING_BINARY) == b"\x03\x07"


def test_upgrade_request_record_negotiate():
    # "application/negotiate" is 21 bytes -> MultiByteInt31 0x15
    assert nmf.upgrade_request_record() == b"\x09\x15application/negotiate"


def test_sized_envelope_record():
    assert nmf.sized_envelope_record(b"hello") == b"\x06\x05hello"


def test_sized_envelope_record_multibyte_size():
    payload = b"z" * 300
    assert nmf.sized_envelope_record(payload) == b"\x06\xac\x02" + payload


def test_single_byte_records():
    assert nmf.preamble_end_record() == b"\x0c"
    assert nmf.end_record() == b"\x07"


def test_build_preamble_is_version_mode_via_encoding():
    via = "net.tcp://dc01.corp.local:9389/ActiveDirectoryWebServices/Windows/Enumeration"
    preamble = nmf.build_preamble(via)
    assert preamble == (
        nmf.version_record()
        + nmf.mode_record(nmf.MODE_DUPLEX)
        + nmf.via_record(via)
        + nmf.known_encoding_record(nmf.ENCODING_BINARY_SESSION)
    )
    assert preamble.startswith(b"\x00\x01\x00\x01\x02\x02")


# --- reading records back ---

def test_read_version_record():
    assert nmf.read_record(Reader(b"\x00\x01\x00")) == (nmf.RT_VERSION, (1, 0))


def test_read_mode_and_encoding():
    assert nmf.read_record(Reader(b"\x01\x02")) == (nmf.RT_MODE, 0x02)
    assert nmf.read_record(Reader(b"\x03\x08")) == (nmf.RT_KNOWN_ENCODING, 0x08)


def test_read_via_and_upgrade_strings():
    assert nmf.read_record(Reader(b"\x02\x01a")) == (nmf.RT_VIA, "a")
    assert nmf.read_record(Reader(b"\x09\x15application/negotiate")) == (
        nmf.RT_UPGRADE_REQUEST, "application/negotiate")


def test_read_sized_envelope_record():
    assert nmf.read_record(Reader(b"\x06\x05hello")) == (nmf.RT_SIZED_ENVELOPE, b"hello")


def test_read_single_byte_records():
    assert nmf.read_record(Reader(b"\x0a")) == (nmf.RT_UPGRADE_RESPONSE, None)
    assert nmf.read_record(Reader(b"\x0b")) == (nmf.RT_PREAMBLE_ACK, None)
    assert nmf.read_record(Reader(b"\x07")) == (nmf.RT_END, None)


def test_read_sized_envelope_helper():
    assert nmf.read_sized_envelope(Reader(b"\x06\x05hello")) == b"hello"


def test_read_sized_envelope_helper_rejects_wrong_type():
    with pytest.raises(ValueError):
        nmf.read_sized_envelope(Reader(b"\x0b"))
