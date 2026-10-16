# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Strict NegTokenResp parsing shared by Kerberos and NTLM completion gates."""
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, tag, univ


class _NegTokenResp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('state', univ.Enumerated().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('mechanism', univ.ObjectIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('token', univ.OctetString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.OptionalNamedType('mic', univ.OctetString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
    )
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))


def parse_response(raw, expected_state, *, mechanisms):
    try:
        token, tail = decoder.decode(raw, asn1Spec=_NegTokenResp())
        if tail or encoder.encode(token) != raw:
            raise ValueError('invalid SPNEGO framing')
        if token['state'].hasValue() and int(token['state']) != expected_state:
            raise ValueError('unexpected SPNEGO state')
        if token['mechanism'].hasValue() and str(token['mechanism']) not in mechanisms:
            raise ValueError('unexpected SPNEGO mechanism')
        if token['mic'].hasValue():
            raise ValueError('unexpected mechanism-list MIC')
        return token
    except PyAsn1Error as exc:
        raise ValueError('invalid SPNEGO encoding') from exc


def verify_completion(raw, *, mechanisms):
    token = parse_response(raw, 0, mechanisms=mechanisms)
    if not token['state'].hasValue() or token['token'].hasValue():
        raise ValueError('invalid SPNEGO completion acknowledgment')
