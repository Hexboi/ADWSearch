# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import logging

import pytest

from adwsearch.adws.client import AdwsClient, selection_property
from adwsearch.soap import templates
from adwsearch.soap.parser import AdwsSoapFault
from adwsearch.transport.nbf.records import EndElement, StartElement, Text, Xmlns


# --- helpers to build scripted responses and inspect requests ---

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


def enum_response(context):
    return el("s", "Envelope", [el("s", "Body", [
        el("wsen", "EnumerateResponse", [el("wsen", "EnumerationContext", text=context)])])])


def item(object_class, attrs):
    children = [el("addata", n, [el("ad", "value", text=v) for v in vals])
                for n, vals in attrs.items()]
    return el("addata", object_class, children)


def pull_response(context, items, end=False):
    inner = []
    if context is not None:
        inner.append(el("wsen", "EnumerationContext", text=context))
    if end:
        inner.append(el("wsen", "EndOfSequence"))
    inner.append(el("wsen", "Items", items))
    return el("s", "Envelope", [el("s", "Body", [el("wsen", "PullResponse", inner)])])


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, events):
        self.requests.append(events)
        return self.responses.pop(0)


def text_of(events, name, prefix=None):
    for i, e in enumerate(events):
        if isinstance(e, StartElement) and e.name == name and (prefix is None or e.prefix == prefix):
            for e2 in events[i + 1:]:
                if isinstance(e2, Text):
                    return e2.value
                if isinstance(e2, (StartElement, EndElement)):
                    return None
    return None


def action_of(events):
    return text_of(events, "Action")


def selection_props(events):
    return [events[i + 1].value for i, e in enumerate(events)
            if isinstance(e, StartElement) and e.name == "SelectionProperty"]


def names(events):
    return [e.name for e in events if isinstance(e, StartElement)]


# --- selection_property mapping ---

def test_selection_property_mapping():
    assert selection_property("sAMAccountName") == "addata:sAMAccountName"
    assert selection_property("distinguishedName") == "ad:distinguishedName"
    assert selection_property("ad:objectSid") == "ad:objectSid"  # already qualified


# --- search orchestration ---

def test_search_yields_all_items_until_end_of_sequence():
    t = FakeTransport([
        enum_response("C1"),
        pull_response("C2", [item("user", {"cn": ["Alice"]}), item("user", {"cn": ["Bob"]})]),
        pull_response(None, [item("user", {"cn": ["Carol"]})], end=True),
    ])
    items = list(AdwsClient(t, "dc01").search("DC=x", "sub", "(objectClass=user)"))
    assert [i.attributes["cn"][0] for i in items] == ["Alice", "Bob", "Carol"]
    assert [action_of(r) for r in t.requests] == [
        templates.ACTION_ENUMERATE, templates.ACTION_PULL, templates.ACTION_PULL]
    # EndOfSequence reached -> no Release
    assert all(action_of(r) != templates.ACTION_RELEASE for r in t.requests)


def test_search_size_limit_stops_and_releases_current_context():
    t = FakeTransport([
        enum_response("C1"),
        pull_response("C2", [item("user", {"cn": ["Alice"]}), item("user", {"cn": ["Bob"]})]),
    ])
    items = list(AdwsClient(t, "dc01").search("DC=x", "sub", "(objectClass=*)", size_limit=1))
    assert len(items) == 1 and items[0].attributes["cn"] == ["Alice"]
    assert action_of(t.requests[-1]) == templates.ACTION_RELEASE
    assert text_of(t.requests[-1], "EnumerationContext") == "C2"


def test_search_maps_scope_and_builds_selection():
    t = FakeTransport([enum_response("C1"), pull_response(None, [], end=True)])
    list(AdwsClient(t, "dc01").search(
        "DC=x", "one", "(cn=a)", attributes=["sAMAccountName", "distinguishedName"]))
    enum = t.requests[0]
    assert text_of(enum, "Scope") == "onelevel"
    assert selection_props(enum) == ["addata:sAMAccountName", "ad:distinguishedName"]


def test_search_without_attributes_omits_selection():
    t = FakeTransport([enum_response("C1"), pull_response(None, [], end=True)])
    list(AdwsClient(t, "dc01").search("DC=x", "sub"))
    assert "Selection" not in names(t.requests[0])


def test_invalid_scope_raises():
    with pytest.raises(ValueError):
        list(AdwsClient(FakeTransport([]), "dc01").search("DC=x", "weird"))


# --- WS-Transfer Get: auto-detect + fallback ------------------------------

def get_response(single_item):
    return el("s", "Envelope", [el("s", "Body", [
        el("wxf", "GetResponse", [single_item])])])


def fault_response(subcode="wsa:ActionNotSupported", code="s:Sender", reason=None):
    """SOAP 1.2 Fault envelope with Code/Subcode and optional Reason/Text.

    Default subcode is ``wsa:ActionNotSupported`` -- the one subcode that
    legitimately means "endpoint does not accept WS-Transfer", so
    ``AdwsClient.get`` is allowed to try the next endpoint / fall back.
    """
    code_children = [el("s", "Value", text=code)]
    if subcode is not None:
        code_children.append(el("s", "Subcode", [el("s", "Value", text=subcode)]))
    fault_children = [el("s", "Code", code_children)]
    if reason is not None:
        fault_children.append(el("s", "Reason", [el("s", "Text", text=reason)]))
    return el("s", "Envelope", [el("s", "Body", [el("s", "Fault", fault_children)])])


def to_of(events):
    return text_of(events, "To")


def test_get_propagates_non_support_fault():
    from contextlib import nullcontext
    t = FakeTransport([fault_response(subcode="s:MustUnderstand")])
    client = AdwsClient(FakeTransport([]), "dc", resource_transport_factory=lambda: nullcontext(t))
    with pytest.raises(AdwsSoapFault):
        client.get("CN=a")


def test_get_fallback_logged_once_with_detail(caplog):
    from contextlib import nullcontext
    resource = FakeTransport([fault_response(reason="not supported")])
    search = FakeTransport([
        enum_response("C1"), pull_response(None, [item("user", {"cn": ["a"]})], end=True),
        enum_response("C2"), pull_response(None, [item("user", {"cn": ["b"]})], end=True),
    ])
    client = AdwsClient(search, "dc", resource_transport_factory=lambda: nullcontext(resource))
    with caplog.at_level(logging.INFO, logger="adwsearch.adws.client"):
        assert client.get("CN=a").attributes["cn"] == ["a"]
        assert client.get("CN=b").attributes["cn"] == ["b"]
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert len(messages) == 1
    assert "ActionNotSupported" in messages[0]
    assert "/Windows/Resource" in messages[0]
    assert len(resource.requests) == 1


def test_release_failure_is_logged_not_silent(caplog):
    """Release cleanup is best-effort but must not fail silently — leave a trail."""

    class TransportThatFailsOnRelease:
        def __init__(self):
            self.requests = []

        def request(self, events):
            self.requests.append(events)
            action = action_of(events)
            if action and action.endswith("/Release"):
                raise ConnectionError("transport dropped during release")
            if action and action.endswith("/Enumerate"):
                return enum_response("CTX-1")
            # Pull: return one item then EndOfSequence=False, so early size_limit
            # break drives the Release path.
            return pull_response("CTX-2", [item("user", {"sAMAccountName": ["a"]})])

    t = TransportThatFailsOnRelease()
    with caplog.at_level(logging.DEBUG, logger="adwsearch.adws.client"):
        list(AdwsClient(t, "dc01").search("DC=x", size_limit=1))
    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "release" in messages.lower()
