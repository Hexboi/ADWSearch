# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Real authenticated AP-REPs, not a sequence learned from the first frame."""
import struct

import pytest
from impacket.krb5.asn1 import AP_REP, EncAPRepPart
from impacket.krb5.crypto import Key, _AES128CTS
from impacket.spnego import SPNEGO_NegTokenResp
from pyasn1.codec.der import encoder

from adwsearch.auth.credentials import Credentials
from adwsearch.auth.kerberos import KerberosSecurityContext
from tests.test_kerberos_security import _simulate_server_wrap


KEY = Key(17, b'\x31' * 16)
SUBKEY = Key(17, b'\x42' * 16)
TIMESTAMP = '20260101000000Z'


def reply(sequence=1314924281, *, tamper=False, subkey=SUBKEY):
    part = EncAPRepPart()
    part['ctime'] = TIMESTAMP
    part['cusec'] = 0
    if sequence is not None:
        part['seq-number'] = sequence
    part['subkey']['keytype'] = subkey.enctype
    part['subkey']['keyvalue'] = subkey.contents
    ciphertext = _AES128CTS.encrypt(KEY, 12, encoder.encode(part), None)
    if tamper:
        ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    ap = AP_REP()
    ap['pvno'], ap['msg-type'] = 5, 15
    ap['enc-part']['etype'] = 17
    ap['enc-part']['cipher'] = ciphertext
    token = SPNEGO_NegTokenResp()
    token['ResponseToken'] = encoder.encode(ap)
    return token.getData()


def context():
    ctx = KerberosSecurityContext(Credentials('alice'), 'dc')
    ctx._cipher, ctx._session_key, ctx._state = _AES128CTS(), KEY, 'mutual'
    ctx._initiator_timestamp = (TIMESTAMP, 0)
    return ctx


@pytest.mark.parametrize('sequence', [1314924281, None, 2**32 - 1])
def test_authenticated_sequence_and_independent_sender(sequence):
    ctx = context()
    ctx.step(reply(sequence))
    seq = sequence or 0
    frame = _simulate_server_wrap(SUBKEY, _AES128CTS, b'answer', seq)
    assert ctx.unwrap(frame) == b'answer'
    assert ctx._recv_seq == seq + 1
    assert struct.unpack('>Q', ctx.wrap(b'request')[8:16])[0] == 0
    with pytest.raises(ValueError, match='seq'):
        ctx.unwrap(frame)


def test_tampered_aprep_does_not_commit_state():
    ctx = context()
    with pytest.raises(RuntimeError, match='integrity'):
        ctx.step(reply(tamper=True))
    assert not ctx.complete
    assert ctx._recv_seq == 0
    assert ctx._session_key is KEY


def test_mutual_auth_cannot_downgrade_aes_to_rc4():
    ctx = context()
    with pytest.raises(RuntimeError, match='policy'):
        ctx.step(reply(subkey=Key(23, b'\x55' * 16)))
    assert not ctx.complete
    assert ctx._recv_seq == 0


def test_aes_sequence_exhaustion_does_not_wrap():
    ctx = context()
    ctx.step(reply())
    ctx._send_seq = 2**64
    with pytest.raises(ValueError, match='exhausted'):
        ctx.wrap(b'overflow')
