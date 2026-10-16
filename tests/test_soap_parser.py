# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from adwsearch.soap import templates
from adwsearch.soap import parser
from adwsearch.transport import nbf
from adwsearch.transport.nbf.records import (
    EndElement, StartElement, Text, Xmlns,
)


def el(prefix, name, children=(), text=None):
    ev = [StartElement(prefix, name)]
    if name == 'Envelope':
        ev.extend([Xmlns('s', templates.NS_SOAP), Xmlns('wsa', templates.NS_WSA),
                   Xmlns('addata', templates.NS_ADDATA), Xmlns('ad', templates.NS_AD)])
    if text is not None:
        ev.append(Text(text))
    for c in children:
        ev += c
    ev.append(EndElement())
    return ev


def value(v):
    return el("ad", "value", text=v)


def pull_response(context, items, end_of_sequence=False):
    inner = [el("wsen", "EnumerationContext", text=context)]
    if end_of_sequence:
        inner.append(el("wsen", "EndOfSequence"))
    inner.append(el("wsen", "Items", children=items))
    return el("s", "Envelope", children=[
        el("s", "Body", children=[el("wsen", "PullResponse", children=inner)]),
    ])


def test_parses_context_and_items():
    resp = pull_response("CTX-NEXT", items=[
        el("addata", "user", children=[
            el("ad", "objectReferenceProperty", children=[value("373e1409")]),
            el("ad", "relativeDistinguishedName", children=[value("CN=TestUser1")]),
            el("addata", "givenName", children=[value("John")]),
        ]),
        el("addata", "user", children=[
            el("ad", "relativeDistinguishedName", children=[value("CN=TestUser2")]),
            el("addata", "givenName", children=[value("Robert")]),
        ]),
    ])
    result = parser.parse_pull_response(resp)
    assert result.context == "CTX-NEXT"
    assert result.end_of_sequence is False
    assert len(result.items) == 2
    assert result.items[0].object_class == "user"
    assert result.items[0].attributes["givenName"] == ["John"]
    assert result.items[0].attributes["relativeDistinguishedName"] == ["CN=TestUser1"]
    assert result.items[1].attributes["givenName"] == ["Robert"]


def test_multi_valued_attribute():
    resp = pull_response("CTX", items=[
        el("addata", "group", children=[
            el("addata", "member", children=[value("CN=a"), value("CN=b"), value("CN=c")]),
        ]),
    ])
    result = parser.parse_pull_response(resp)
    assert result.items[0].object_class == "group"
    assert result.items[0].attributes["member"] == ["CN=a", "CN=b", "CN=c"]


def test_end_of_sequence_detected():
    resp = pull_response("CTX", items=[], end_of_sequence=True)
    result = parser.parse_pull_response(resp)
    assert result.end_of_sequence is True
    assert result.items == []


def test_empty_string_value_is_preserved():
    """An `<ad:value/>` (empty string) must be kept as `""`, not dropped."""
    empty_value = [StartElement("ad", "value"), EndElement()]
    resp = pull_response("CTX", items=[
        el("addata", "user", children=[
            el("addata", "description", children=[empty_value])])
    ])
    result = parser.parse_pull_response(resp)
    assert result.items[0].attributes["description"] == [""]


def test_parses_from_encoded_bytes():
    # end to end: encode the response, decode it, then parse
    resp = pull_response("CTX", items=[
        el("addata", "user", children=[el("addata", "cn", children=[value("Alice")])]),
    ])
    result = parser.parse_pull_response(nbf.decode(nbf.encode(resp)))
    assert result.items[0].attributes["cn"] == ["Alice"]


# --- parse_get_response ---------------------------------------------------

def _get_response(single_item):
    return el("s", "Envelope", children=[
        el("s", "Header", children=[el("wsa", "Action", text="http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse")]),
        el("s", "Body", children=[single_item])])


def test_parse_get_response_returns_single_adobject():
    resp = _get_response(el("addata", "user", children=[
        el("addata", "sAMAccountName", children=[value("alice")]),
        el("addata", "memberOf", children=[value("CN=g1,DC=x"), value("CN=g2,DC=x")]),
    ]))
    obj = parser.parse_get_response(resp)
    assert obj is not None
    assert obj.object_class == "user"
    assert obj.attributes["sAMAccountName"] == ["alice"]
    assert obj.attributes["memberOf"] == ["CN=g1,DC=x", "CN=g2,DC=x"]


def test_parse_get_response_empty_body_returns_none():
    resp = el("s", "Envelope", children=[
        el("s", "Header", children=[el("wsa", "Action", text="http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse")]),
        el("s", "Body")])
    assert parser.parse_get_response(resp) is None


def test_parse_get_response_missing_element_raises():
    import pytest
    resp = el("s", "Envelope", children=[el("s", "Body")])
    with pytest.raises(ValueError):
        parser.parse_get_response(resp)


# --- SOAP Fault handling --------------------------------------------------

def _fault_response(code="s:Sender", subcode="wsa:ActionNotSupported", reason=None):
    code_children = [el("s", "Value", text=code)]
    if subcode is not None:
        code_children.append(el("s", "Subcode", children=[el("s", "Value", text=subcode)]))
    fault_children = [el("s", "Code", children=code_children)]
    if reason is not None:
        fault_children.append(el("s", "Reason", children=[el("s", "Text", text=reason)]))
    return el("s", "Envelope", children=[el("s", "Body", children=[
        el("s", "Fault", children=fault_children),
    ])])


def test_parse_get_response_raises_adws_soap_fault_with_subcode():
    """A SOAP Fault envelope must raise AdwsSoapFault carrying code/subcode/reason.

    AdwsClient.get keys its "retry other endpoint / fall back to search"
    decision off ``subcode``; the parser is the only place that extracts
    it, so the extraction has to be correct.
    """
    import pytest
    resp = _fault_response(code="s:Sender",
                           subcode="wsa:ActionNotSupported",
                           reason="The server did not understand the action")
    with pytest.raises(parser.AdwsSoapFault) as excinfo:
        parser.parse_get_response(resp)
    fault = excinfo.value
    assert fault.code == "s:Sender"
    assert fault.subcode == "wsa:ActionNotSupported"
    assert fault.reason == "The server did not understand the action"


def test_parse_get_response_fault_without_subcode():
    """Code without Subcode is still a legitimate fault (just no retry hint)."""
    import pytest
    resp = _fault_response(code="s:Receiver", subcode=None, reason="internal error")
    with pytest.raises(parser.AdwsSoapFault) as excinfo:
        parser.parse_get_response(resp)
    assert excinfo.value.code == "s:Receiver"
    assert excinfo.value.subcode is None
    assert excinfo.value.reason == "internal error"
