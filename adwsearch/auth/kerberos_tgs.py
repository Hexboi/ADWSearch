# SPDX-License-Identifier: MPL-2.0 AND LicenseRef-Impacket
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)
# Portions adapted from impacket: Copyright Fortra, LLC and its affiliated companies.
# All rights reserved. Upstream author: Alberto Solino (@agsolino).
# Upstream terms: NOTICE; MPL-2.0 covers ADWSearch additions.

"""TGS exchange with an explicit session-enctype offer and bounded I/O.

Uses impacket's ASN.1/crypto building blocks, not its fixed RC4-first offer.
Request structure follows RFC4120 and impacket (Fortra/Alberto Solino);
see NOTICE for the impacket license.
"""

import datetime
import secrets
import socket
import struct

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from pyasn1.error import PyAsn1Error
from impacket.krb5 import constants
from impacket.krb5.asn1 import (AS_REP, TGS_REP, TGS_REQ, AP_REQ, Authenticator,
                               EncTGSRepPart, KRB_ERROR, seq_set, seq_set_iter)
from impacket.krb5.types import Principal, Ticket, KerberosTime
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import KerberosError


def _exchange(data, realm, host, timeout):
    def exact(sock, count):
        chunks = bytearray()
        while len(chunks) < count:
            chunk = sock.recv(count - len(chunks))
            if not chunk:
                raise ConnectionError('KDC closed the connection')
            chunks.extend(chunk)
        return bytes(chunks)
    with socket.create_connection((host or realm, 88), timeout=timeout) as sock:
        sock.sendall(struct.pack('>I', len(data)) + data)
        size = struct.unpack('>I', exact(sock, 4))[0]
        if not 0 < size <= 16 * 1024 * 1024:
            raise ValueError('invalid KDC reply size')
        return exact(sock, size)


def request_service_ticket(tgt: dict, spn: str, realm: str, kdc_host: str | None,
                           *, enctypes, timeout=30) -> dict:
    if tuple(enctypes) not in ((18, 17), (23,)):
        raise ValueError('unsupported Kerberos enctype offer')
    try:
        source = decoder.decode(tgt['KDC_REP'], asn1Spec=AS_REP())[0]
    except PyAsn1Error:
        source = decoder.decode(tgt['KDC_REP'], asn1Spec=TGS_REP())[0]
    cipher, key = tgt['cipher'], tgt['sessionKey']
    principal = Principal()
    principal.from_asn1(source, 'crealm', 'cname')
    ticket = Ticket()
    ticket.from_asn1(source['ticket'])
    auth = Authenticator()
    auth['authenticator-vno'] = 5
    auth['crealm'] = str(source['crealm'])
    seq_set(auth, 'cname', principal.components_to_asn1)
    now = datetime.datetime.now(datetime.timezone.utc)
    auth['ctime'], auth['cusec'] = KerberosTime.to_asn1(now), now.microsecond
    ap = AP_REQ()
    ap['pvno'], ap['msg-type'] = 5, 14
    ap['ap-options'] = constants.encodeFlags([])
    seq_set(ap, 'ticket', ticket.to_asn1)
    ap['authenticator']['etype'] = cipher.enctype
    ap['authenticator']['cipher'] = cipher.encrypt(key, 7, encoder.encode(auth), None)
    request = TGS_REQ()
    request['pvno'], request['msg-type'] = 5, 12
    request['padata'] = noValue
    request['padata'][0]['padata-type'] = 1
    request['padata'][0]['padata-value'] = encoder.encode(ap)
    body = seq_set(request, 'req-body')
    body['kdc-options'] = constants.encodeFlags([1, 8, 27])
    server = Principal(spn, type=2)
    seq_set(body, 'sname', server.components_to_asn1)
    body['realm'] = realm.upper()
    body['till'] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    nonce = secrets.randbits(31)
    body['nonce'] = nonce
    seq_set_iter(body, 'etype', enctypes)
    raw = _exchange(encoder.encode(request), realm, kdc_host, timeout)
    try:
        response, tail = decoder.decode(raw, asn1Spec=TGS_REP())
    except PyAsn1Error:
        error, tail = decoder.decode(raw, asn1Spec=KRB_ERROR())
        if tail:
            raise ValueError('trailing KDC error bytes')
        raise KerberosError(packet=error) from None
    if tail:
        raise ValueError('trailing KDC reply bytes')
    if int(response['enc-part']['etype']) != cipher.enctype:
        raise ValueError('KDC reply encryption metadata mismatch')
    part, tail = decoder.decode(cipher.decrypt(key, 8, response['enc-part']['cipher']),
                                asn1Spec=EncTGSRepPart())
    if tail:
        raise ValueError('trailing encrypted KDC reply bytes')
    returned = Principal()
    returned.from_asn1(response['ticket'], 'realm', 'sname')
    encrypted_server = Principal()
    encrypted_server.from_asn1(part, 'srealm', 'sname')
    requested = f'{spn}@{realm}'.casefold()
    returned_client = Principal()
    returned_client.from_asn1(response, 'crealm', 'cname')
    if (str(returned).casefold() != requested or str(encrypted_server).casefold() != requested
            or str(returned_client).casefold() != str(principal).casefold()
            or int(part['nonce']) != nonce):
        raise ValueError('KDC reply identity, service, realm or nonce mismatch')
    enctype = int(part['key']['keytype'])
    if enctype not in enctypes:
        raise ValueError('KDC selected an unoffered session enctype')
    session_key = Key(enctype, part['key']['keyvalue'].asOctets())
    return {'KDC_REP': raw, 'cipher': _enctype_table[enctype](), 'sessionKey': session_key}
