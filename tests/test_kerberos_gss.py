# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Real RC4 authenticators/AP-REPs; only the external ticket lookup is replaced."""
import struct

import pytest
from impacket.krb5.asn1 import (AP_REQ, AP_REP, Authenticator, EncAPRepPart,
                                TGS_REP, seq_set)
from impacket.krb5.crypto import Key, _RC4
from impacket.krb5.gssapi import MechIndepToken
from impacket.krb5.types import Principal
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from pyasn1.codec.der import decoder, encoder

from adwsearch.auth.credentials import Credentials
from adwsearch.auth.kerberos import KerberosSecurityContext, KerberosAuthenticationError
from tests.test_kerberos_mutual import context as aes_context, reply as aes_reply

KEY = Key(23, b'\x31' * 16)
SUBKEY = Key(23, b'\x42' * 16)
OID = TypesMech['KRB5 - Kerberos 5']


def ticket():
    rep = TGS_REP()
    rep['pvno'], rep['msg-type'], rep['crealm'] = 5, 13, 'REALM'
    seq_set(rep, 'cname', Principal('alice', type=1).components_to_asn1)
    t = rep['ticket']
    t['tkt-vno'], t['realm'] = 5, 'REALM'
    seq_set(t, 'sname', Principal('host/dc', type=2).components_to_asn1)
    t['enc-part']['etype'], t['enc-part']['cipher'] = 18, b'opaque-ticket'
    rep['enc-part']['etype'], rep['enc-part']['cipher'] = 23, b'opaque-reply'
    return {'KDC_REP': encoder.encode(rep), 'cipher': _RC4(), 'sessionKey': KEY}


def rc4_context(monkeypatch, policy='rc4'):
    monkeypatch.setattr('adwsearch.auth.kerberos.load_service_ticket', lambda *a, **kw: ticket())
    ctx = KerberosSecurityContext(Credentials('alice', 'REALM'), 'dc', policy=policy)
    initial = ctx.step(None)
    return ctx, initial


def response(ctx, *, change=None, gss=True):
    part = EncAPRepPart()
    part['ctime'], part['cusec'] = ctx._initiator_timestamp
    if change == 'timestamp':
        part['cusec'] = (int(part['cusec']) + 1) % 1000000
    part['seq-number'] = 7
    part['subkey']['keytype'] = 17 if change == 'subkey' else 23
    part['subkey']['keyvalue'] = SUBKEY.contents
    plaintext = encoder.encode(part) + (b'x' if change == 'plaintext-tail' else b'')
    ciphertext = _RC4.encrypt(KEY, 12, plaintext, None)
    if change == 'ciphertext':
        ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    ap = AP_REP()
    ap['pvno'], ap['msg-type'] = 5, 15
    ap['enc-part']['etype'], ap['enc-part']['cipher'] = 23, ciphertext
    raw = encoder.encode(ap) + (b'x' if change == 'ap-tail' else b'')
    if change == 'version':
        raw = raw.replace(b'\xa0\x03\x02\x01\x05', b'\xa0\x03\x02\x01\x04', 1)
    if change == 'message':
        raw = raw.replace(b'\xa1\x03\x02\x01\x0f', b'\xa1\x03\x02\x01\x0e', 1)
    if gss:
        marker = b'\x01\x00' if change == 'marker' else b'\x02\x00'
        oid = b'\x06\x03\x2a\x03\x04' if change == 'oid' else b'\x06\x09' + OID
        raw = b''.join(MechIndepToken(marker + raw, oid=oid).to_bytes())
        if change == 'gss-tail':
            raw += b'x'
        if change == 'truncated':
            raw = raw[:-1]
    token = SPNEGO_NegTokenResp()
    token['NegState'] = b'\x01' if change == 'state' else b'\x00'
    token['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'] if change == 'mechanism' else OID
    token['ResponseToken'] = raw
    return token.getData() + (b'x' if change == 'spnego-tail' else b'')


@pytest.mark.parametrize('policy', ['rc4', 'auto'])
def test_permitted_rc4_initial_authenticator_uses_standard_gss(monkeypatch, policy):
    ctx, initial = rc4_context(monkeypatch, policy)
    mech = MechIndepToken.from_bytes(SPNEGO_NegTokenInit(initial)['MechToken'])
    ap, tail = decoder.decode(mech.data[2:], asn1Spec=AP_REQ())
    auth, auth_tail = decoder.decode(_RC4.decrypt(KEY, 11, ap['authenticator']['cipher']),
                                     asn1Spec=Authenticator())
    flags = struct.unpack('<I', auth['cksum']['checksum'].asOctets()[20:24])[0]
    assert flags == 0x3e  # mutual, replay, sequence, confidentiality, integrity; NOT DCE.
    assert not tail and not auth_tail
    assert int(ap['ap-options'][2]) == 1  # mutual-required
    assert str(ap['ticket']['sname']['name-string'][1]) == 'dc'
    assert (str(auth['ctime']), int(auth['cusec'])) == ctx._initiator_timestamp


def test_standard_rc4_aprep_finishes_without_third_leg(monkeypatch):
    ctx, _ = rc4_context(monkeypatch)
    assert ctx.step(response(ctx)) is None
    assert ctx.complete and ctx._session_key.contents == SUBKEY.contents
    assert ctx._recv_seq == 7 and ctx._send_seq == 0


@pytest.mark.parametrize('change', ['timestamp', 'subkey', 'ciphertext', 'version', 'message',
    'plaintext-tail', 'ap-tail', 'oid', 'marker', 'gss-tail', 'truncated', 'state',
    'mechanism', 'spnego-tail'])
def test_standard_rc4_rejects_invalid_envelope_or_authenticated_reply(monkeypatch, change):
    ctx, _ = rc4_context(monkeypatch)
    with pytest.raises(KerberosAuthenticationError):
        ctx.step(response(ctx, change=change))
    assert not ctx.complete and ctx._recv_seq == 0 and ctx._session_key is KEY


def test_standard_context_refuses_raw_dce_reply(monkeypatch):
    ctx, _ = rc4_context(monkeypatch)
    with pytest.raises(KerberosAuthenticationError):
        ctx.step(response(ctx, gss=False))


@pytest.mark.parametrize('trailer', [b'x', b'\x00'])
def test_dce_aprep_rejects_trailing_spnego_bytes(trailer):
    ctx = aes_context()
    with pytest.raises(KerberosAuthenticationError):
        ctx.step(aes_reply() + trailer)


def test_dce_context_refuses_gss_wrapped_reply():
    ctx = aes_context()
    token = SPNEGO_NegTokenResp(aes_reply())
    token['ResponseToken'] = b''.join(MechIndepToken(b'\x02\x00' + token['ResponseToken']).to_bytes())
    with pytest.raises(KerberosAuthenticationError):
        ctx.step(token.getData())
