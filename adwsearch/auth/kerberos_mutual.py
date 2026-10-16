# SPDX-License-Identifier: MPL-2.0 AND LicenseRef-Impacket
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)
# Portions adapted from impacket: Copyright Fortra, LLC and its affiliated companies.
# All rights reserved. Upstream author: Alberto Solino (@agsolino).
# Upstream terms: NOTICE; MPL-2.0 covers ADWSearch additions.

"""Authenticated standard/DCE AP-REP metadata (RFC4120, key usage 12).

Uses impacket ASN.1 and crypto primitives; see NOTICE.
The acceptor sequence seeds receive state, never the independent sender state.
"""
import datetime
import struct

from impacket.krb5.asn1 import AP_REP, AP_REQ, Authenticator, EncAPRepPart
from impacket.krb5.gssapi import MechIndepToken
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.types import KerberosTime
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp
from pyasn1.codec.der import decoder, encoder
from adwsearch.auth.spnego import parse_response, verify_completion as _verify_completion


_KERBEROS_OIDS = ('1.2.840.113554.1.2.2', '1.2.840.48018.1.2.2')


def _negotiation(raw, expected_state):
    return parse_response(raw, expected_state, mechanisms=_KERBEROS_OIDS)


def _der_value(raw, expected_tag):
    """Read one canonical, bounded DER TLV, retaining the unconsumed suffix."""
    if len(raw) < 2 or raw[0] != expected_tag:
        raise ValueError('invalid Kerberos GSS envelope')
    size, offset = raw[1], 2
    if size >= 128:
        count = size & 127
        if not count or count > 4 or len(raw) < 2 + count or raw[2] == 0:
            raise ValueError('invalid Kerberos GSS length')
        size = int.from_bytes(raw[2:2 + count], 'big')
        offset += count
        if size < 128:
            raise ValueError('noncanonical Kerberos GSS length')
    if size > len(raw) - offset:
        raise ValueError('truncated Kerberos GSS token')
    return raw[offset:offset + size], raw[offset + size:]


def _gss_data(raw, marker):
    body, tail = _der_value(raw, 0x60)
    oid, data = _der_value(body, 0x06)
    if tail or oid != bytes.fromhex('2a864886f712010202') or data[:2] != marker:
        raise ValueError('invalid Kerberos GSS mechanism or token id')
    return data[2:]


def standard_initial_token(cipher, key, raw):
    """Adapt our own generated authenticator, never the opaque ticket or cache.

    impacket's initial helper fixes DCE_STYLE on. Clear just that flag before
    sending RC4 with the ordinary GSS wrap backend; retain its timestamp and all
    mutual-authentication/sign/seal/replay flags. No global impacket patch.
    """
    token = SPNEGO_NegTokenInit(raw)
    ap, tail = decoder.decode(_gss_data(token['MechToken'], b'\x01\x00'), asn1Spec=AP_REQ())
    auth, auth_tail = decoder.decode(cipher.decrypt(key, 11, ap['authenticator']['cipher']),
                                    asn1Spec=Authenticator())
    checksum = auth['cksum']['checksum'].asOctets()
    if (tail or auth_tail or int(auth['cksum']['cksumtype']) != 0x8003 or
            len(checksum) != 24 or checksum[:4] != b'\x10\x00\x00\x00'):
        raise ValueError('invalid initiator Kerberos authenticator')
    flags = struct.unpack('<I', checksum[20:24])[0]
    if flags != 0x103e:
        raise ValueError('unexpected initiator Kerberos context flags')
    auth['cksum']['checksum'] = checksum[:20] + struct.pack('<I', flags & ~0x1000)
    ap['authenticator']['cipher'] = cipher.encrypt(key, 11, encoder.encode(auth), None)
    token['MechToken'] = b''.join(MechIndepToken(b'\x01\x00' + encoder.encode(ap)).to_bytes())
    return token.getData()


def verify_completion(raw):
    _verify_completion(raw, mechanisms=_KERBEROS_OIDS)


def _authenticated_part(cipher, key, auth_data, *, dce_style=True):
    token = _negotiation(auth_data, 1 if dce_style else 0)
    if not token['token'].hasValue() or (not dce_style and not token['state'].hasValue()):
        raise ValueError('missing Kerberos mutual response')
    raw = token['token'].asOctets()
    if not dce_style:
        raw = _gss_data(raw, b'\x02\x00')
    ap, tail = decoder.decode(raw, asn1Spec=AP_REP())
    if tail or int(ap['enc-part']['etype']) != cipher.enctype:
        raise ValueError('invalid Kerberos AP-REP framing or enctype')
    plaintext = cipher.decrypt(key, 12, ap['enc-part']['cipher'])
    part, tail = decoder.decode(plaintext, asn1Spec=EncAPRepPart())
    if tail:
        raise ValueError('trailing Kerberos AP-REP plaintext')
    seq = int(part['seq-number']) if part['seq-number'].hasValue() else 0
    if not 0 <= seq < 2**32:
        raise ValueError('invalid Kerberos AP-REP sequence')
    return ap, part, seq


def _acceptor_initial_sequence(cipher, session_key, auth_data: bytes) -> int:
    return _authenticated_part(cipher, session_key, auth_data)[2]


def initial_timestamp(cipher, key, raw):
    """Read our own generated authenticator so the peer must echo this exchange."""
    token = SPNEGO_NegTokenInit(raw)
    mech = MechIndepToken.from_bytes(token['MechToken'])
    if mech.data[:2] != b'\x01\x00':
        raise ValueError('invalid initiator Kerberos token')
    ap, tail = decoder.decode(mech.data[2:], asn1Spec=AP_REQ())
    if tail:
        raise ValueError('trailing initiator Kerberos token')
    auth, tail = decoder.decode(cipher.decrypt(key, 11, ap['authenticator']['cipher']),
                                asn1Spec=Authenticator())
    if tail:
        raise ValueError('trailing Kerberos authenticator')
    return str(auth['ctime']), int(auth['cusec'])


def mutual_exchange(cipher, key, auth_data, allowed, expected_timestamp, *, dce_style=True):
    ap, part, sequence = _authenticated_part(cipher, key, auth_data, dce_style=dce_style)
    if (str(part['ctime']), int(part['cusec'])) != expected_timestamp:
        raise ValueError('Kerberos AP-REP does not echo this authenticator')
    enctype = int(part['subkey']['keytype']) if part['subkey'].hasValue() else cipher.enctype
    if enctype not in allowed:
        raise ValueError('Kerberos mutual authentication enctype violates negotiated policy')
    session_key = (Key(enctype, part['subkey']['keyvalue'].asOctets())
                   if part['subkey'].hasValue() else key)
    if not dce_style:
        return _enctype_table[enctype](), session_key, None, sequence
    # DCE third leg echoes the authenticated sequence under the original key.
    response_part = EncAPRepPart()
    now = datetime.datetime.now(datetime.timezone.utc)
    response_part['ctime'] = KerberosTime.to_asn1(now)
    response_part['cusec'] = now.microsecond
    response_part['seq-number'] = sequence
    ap['enc-part']['cipher'] = cipher.encrypt(key, 12, encoder.encode(response_part), None)
    response = SPNEGO_NegTokenResp()
    response['ResponseToken'] = encoder.encode(ap)
    return _enctype_table[enctype](), session_key, response.getData(), sequence
