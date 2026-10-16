# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Build ADWS SOAP requests as NBF record lists (ready for nbf.encode / encode_message).

Covers the WS-Enumeration operations used for search: Enumerate, Pull, Release. The message
shapes follow the MS-ADDM / MS-WSDS examples (SOAP 1.2 + WS-Addressing + the LdapQuery and
XPath-Level-1 dialects).
"""

import uuid

from adwsearch.transport.nbf.records import (
    Attribute, EndElement, StartElement, Text, Xmlns,
)

# Namespaces
NS_SOAP = "http://www.w3.org/2003/05/soap-envelope"
NS_WSA = "http://www.w3.org/2005/08/addressing"
NS_WSEN = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
NS_AD = "http://schemas.microsoft.com/2008/1/ActiveDirectory"
NS_ADDATA = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
NS_ADLQ = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery"
NS_XPATH1 = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1"
NS_WXF = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
NS_XSD = "http://www.w3.org/2001/XMLSchema"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"

# WS-Enumeration actions
ACTION_ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
ACTION_PULL = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
ACTION_RELEASE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Release"
# WS-Transfer action (single-object read; MS-ADDM 2.1).
ACTION_GET = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"

ANONYMOUS = "http://www.w3.org/2005/08/addressing/anonymous"
ENUMERATION_ENDPOINT = "/ActiveDirectoryWebServices/Windows/Enumeration"
# WS-Transfer resource endpoints. MS-ADDM 2.1 documents /Windows/Resource as the
# primary target for Get; a few deployments expose only /Windows/ResourceFactory,
# so AdwsClient.get auto-detects and memoises the right one per host.
RESOURCE_ENDPOINT = "/ActiveDirectoryWebServices/Windows/Resource"
RESOURCE_FACTORY_ENDPOINT = "/ActiveDirectoryWebServices/Windows/ResourceFactory"

# CLI scope -> LdapQuery dialect scope value
SCOPE = {"base": "base", "one": "onelevel", "sub": "subtree"}


def _el(prefix, name, *, ns=(), attrs=(), text=None, children=()):
    events = [StartElement(prefix, name)]
    events += [Xmlns(p, uri) for p, uri in ns]
    events += [Attribute(ap, an, av) for ap, an, av in attrs]
    if text is not None:
        events.append(Text(text))
    for child in children:
        events += child
    events.append(EndElement())
    return events


def _endpoint(host, port, path=ENUMERATION_ENDPOINT):
    return f"net.tcp://{host}:{port}{path}"


def _message_id(message_id):
    return message_id or ("urn:uuid:" + str(uuid.uuid4()))


def _header(action, to, message_id, extra_children=()):
    children = [
        _el("wsa", "Action", attrs=[("s", "mustUnderstand", "1")], text=action),
        # ADWS routes every request through <ad:instance> (which backend to hit).
        # ``ldap:389`` is the only supported value; without this header the server
        # replies with wsa:EndpointUnavailable ("bad parameter"). Verified against
        # a live DC and against SOAPy's reference templates.
        _el("ad", "instance", ns=[("ad", NS_AD)], text="ldap:389"),
        _el("wsa", "MessageID", text=message_id),
        _el("wsa", "ReplyTo", children=[_el("wsa", "Address", text=ANONYMOUS)]),
        _el("wsa", "To", attrs=[("s", "mustUnderstand", "1")], text=to),
    ]
    children.extend(extra_children)
    return _el("s", "Header", children=children)


def _envelope(header, body, extra_ns=()):
    # ADWS resolves attribute-name prefixes (``addata:cn`` text in a
    # ad:SelectionProperty, ``adlq:...`` in LdapQuery filters) against the
    # Envelope's namespace context. Declaring ``ad`` / ``addata`` / ``adlq``
    # here matches SOAPy's reference templates and keeps the server from
    # faulting with ``InvalidPropertyFault`` on well-formed selections.
    ns = [("s", NS_SOAP), ("wsa", NS_WSA),
          ("ad", NS_AD), ("addata", NS_ADDATA), ("adlq", NS_ADLQ),
          ("xsd", NS_XSD), ("xsi", NS_XSI)]
    ns.extend(extra_ns)
    return _el("s", "Envelope", ns=ns, children=[header, body])


def enumerate_request(host, base, scope, ldap_filter, selection=None,
                      message_id=None, port=9389, controls=None):
    # ``controls`` is accepted here for backward-compat but ignored: ADWS requires
    # LDAP controls on the Pull message (see pull_request). Older code that passes
    # them here still works; the controls just travel on the first Pull instead.
    ldap_query = _el("adlq", "LdapQuery", children=[
        _el("adlq", "Filter", text=ldap_filter),
        _el("adlq", "BaseObject", text=base),
        _el("adlq", "Scope", text=scope),
    ])
    enumerate_children = [
        _el("wsen", "Filter", attrs=[(None, "Dialect", NS_ADLQ)], children=[ldap_query]),
    ]
    if selection:
        properties = [_el("ad", "SelectionProperty", text=p) for p in selection]
        enumerate_children.append(
            _el("ad", "Selection", attrs=[(None, "Dialect", NS_XPATH1)], children=properties))

    body = _el("s", "Body", children=[
        _el("wsen", "Enumerate",
            ns=[("wsen", NS_WSEN), ("ad", NS_AD), ("adlq", NS_ADLQ)],
            children=enumerate_children),
    ])
    return _envelope(_header(ACTION_ENUMERATE, _endpoint(host, port), _message_id(message_id)), body)


def pull_request(host, context, max_elements, message_id=None, port=9389,
                 controls=None):
    """Build a WS-Enumeration Pull. LDAP controls (e.g. SD_FLAGS 801) attach
    here as ``<ad:controls><ad:control type=... criticality=true>
    <ad:controlValue xsi:type=xsd:base64Binary>...</ad:controlValue></ad:control>``,
    the shape MS-ADDM accepts (verified against a live DC + SOAPy)."""
    pull_children = [
        _el("wsen", "EnumerationContext", text=context),
        _el("wsen", "MaxElements", text=str(max_elements)),
    ]
    if controls:
        control_elems = [
            _el("ad", "control",
                attrs=[(None, "type", ctype), (None, "criticality", "true")],
                children=[
                    _el("ad", "controlValue",
                        attrs=[("xsi", "type", "xsd:base64Binary")],
                        text=cvalue),
                ])
            for ctype, cvalue in controls
        ]
        pull_children.append(_el("ad", "controls", children=control_elems))
    body = _el("s", "Body", children=[
        _el("wsen", "Pull", ns=[("wsen", NS_WSEN)], children=pull_children),
    ])
    return _envelope(_header(ACTION_PULL, _endpoint(host, port), _message_id(message_id)), body)


def release_request(host, context, message_id=None, port=9389):
    body = _el("s", "Body", children=[
        _el("wsen", "Release", ns=[("wsen", NS_WSEN)], children=[
            _el("wsen", "EnumerationContext", text=context),
        ]),
    ])
    return _envelope(_header(ACTION_RELEASE, _endpoint(host, port), _message_id(message_id)), body)


def get_request(host, dn, message_id=None, port=9389,
                endpoint=RESOURCE_ENDPOINT):
    """Build a WS-Transfer Get for a single AD object identified by ``dn``.

    The resource is identified by an ``<ad:objectReferenceProperty>`` SOAP
    header carrying the DN (MS-ADDM §2.3.1 accepts DN or objectGUID forms).
    Per WS-Transfer and the MS-ADDM §3.1 example, the SOAP Body MUST be
    empty for a Get request; emitting ``<wxf:Get/>`` as a body child causes
    ADWS to reject the message with a SOAP Fault. ``_header`` already emits
    the ``<ad:instance>ldap:389</ad:instance>`` ADWS routing header; the
    ``ad`` namespace is declared on the envelope so neither a local xmlns
    redeclaration nor a ``mustUnderstand`` flag is required on the
    reference-property header (the MS-ADDM example sets neither).
    """
    object_ref = _el("ad", "objectReferenceProperty", text=dn)
    body = _el("s", "Body")
    return _envelope(
        _header(ACTION_GET, _endpoint(host, port, endpoint),
                _message_id(message_id),
                extra_children=[object_ref]),
        body,
    )
