# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import importlib
import pytest

INIT = bytes.fromhex('604306092a864886f712010202020111001000ffff61a8ae1b07cdd6c618b7e36973f42a098b09901d85fa0fb6518a4adf09a693743245662cd7a007817b40475ce0f63f96')
ACCEPT = bytes.fromhex('604306092a864886f712010202020111001000ffff61a8ae1bf832293918b7e36973f42a098b09901d85fa0fb6518a4adf09a693743245662cd7a007817b40475ce0f63f96')
KEY = b'\x11' * 16
DATA = b'ADWS diagnostic payload'


def backend():
    from adwsearch.auth import kerberos
    assert hasattr(kerberos, 'rc4'), 'authenticated RC4 backend is absent'
    return importlib.import_module('adwsearch.auth.kerberos_rc4')


def test_wrap_matches_independent_golden_token(monkeypatch):
    rc4 = backend()
    monkeypatch.setattr(rc4.secrets, 'token_bytes', lambda n: b'A' * n)
    assert rc4.wrap(KEY, DATA, 7) == INIT


def test_unwrap_independent_acceptor_token():
    rc4 = backend()
    assert rc4.unwrap(KEY, ACCEPT, 7) == DATA


@pytest.mark.parametrize('offset', [0, 1, 4, 13, 21, 29, 40, 57, 68])
def test_altered_token_rejected(offset):
    rc4 = backend()
    altered = bytearray(ACCEPT)
    altered[offset] ^= 1
    with pytest.raises(ValueError):
        rc4.unwrap(KEY, bytes(altered), 7)


def test_wrong_sequence_and_reflection_rejected():
    rc4 = backend()
    for token, sequence in [(ACCEPT, 8), (INIT, 7)]:
        with pytest.raises(ValueError):
            rc4.unwrap(KEY, token, sequence)


@pytest.mark.parametrize('token', [b'', ACCEPT[:-1], ACCEPT+b'x', b'\x60\x80'+ACCEPT[2:]])
def test_bad_framing_rejected(token):
    rc4 = backend()
    with pytest.raises(ValueError):
        rc4.unwrap(KEY, token, 7)


def test_rc4_counter_exhaustion_rejected():
    rc4 = backend()
    with pytest.raises(ValueError):
        rc4.wrap(KEY, b'a', 2**32)


def test_wrap_matches_public_ms_kile_standard_context_vector(monkeypatch):
    # MS-KILE 4.5 GSS_WrapEx: DCE_STYLE FALSE, confidentiality TRUE.
    rc4 = backend()
    monkeypatch.setattr(rc4.secrets, 'token_bytes', lambda n: bytes.fromhex('5256f3fb630cf12a'))
    token = rc4.wrap(bytes.fromhex('81a2cb90af7fc2d19554a150d8185359'),
                     bytes.fromhex('112233445566778899aabbccddeeff'), 0x60cbacd3)
    assert token == bytes.fromhex(
        '603b06092a864886f712010202020111001000ffffe29e8bbc6348e740'
        'ebaa619244a156a13b5cf65e3c21b9aa8ed63f0ac83815335b72e293bae1f660')
