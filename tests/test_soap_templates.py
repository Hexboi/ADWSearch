# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from adwsearch.soap import templates as t
from adwsearch.transport import nbf
from adwsearch.transport.nbf.records import EndElement, StartElement, Text


def text_of(events, name, prefix=None):
    """Return the first Text value inside the first matching StartElement (skipping attrs)."""
    for i, e in enumerate(events):
        if isinstance(e, StartElement) and e.name == name and (prefix is None or e.prefix == prefix):
            for e2 in events[i + 1:]:
                if isinstance(e2, Text):
                    return e2.value
                if isinstance(e2, (StartElement, EndElement)):
                    return None
    return None


def names(events):
    return [e.name for e in events if isinstance(e, StartElement)]


MID = "urn:uuid:00000000-0000-0000-0000-000000000001"


def test_enumerate_request_core_fields():
    ev = t.enumerate_request(
        "dc01.corp.local", "DC=corp,DC=local", "subtree", "(objectClass=user)",
        selection=["addata:sAMAccountName", "ad:distinguishedName"], message_id=MID)
    assert text_of(ev, "Action") == t.ACTION_ENUMERATE
    assert text_of(ev, "To") == \
        "net.tcp://dc01.corp.local:9389/ActiveDirectoryWebServices/Windows/Enumeration"
    assert text_of(ev, "MessageID") == MID
    assert text_of(ev, "Filter", prefix="adlq") == "(objectClass=user)"
    assert text_of(ev, "BaseObject") == "DC=corp,DC=local"
    assert text_of(ev, "Scope") == "subtree"
    props = [ev[i + 1].value for i, e in enumerate(ev)
             if isinstance(e, StartElement) and e.name == "SelectionProperty"]
    assert props == ["addata:sAMAccountName", "ad:distinguishedName"]


def test_enumerate_without_selection_omits_selection_element():
    ev = t.enumerate_request(
        "dc01", "DC=corp,DC=local", "subtree", "(objectClass=*)", message_id=MID)
    assert "Selection" not in names(ev)
    assert "SelectionProperty" not in names(ev)


def test_enumerate_request_is_encodable_and_roundtrips():
    ev = t.enumerate_request(
        "dc01", "DC=corp,DC=local", "subtree", "(cn=x)", selection=["addata:cn"], message_id=MID)
    assert nbf.decode(nbf.encode(ev)) == ev  # every record is encodable


def test_pull_request():
    ev = t.pull_request("dc01", "CTX-123", 256, message_id=MID)
    assert text_of(ev, "Action") == t.ACTION_PULL
    assert text_of(ev, "EnumerationContext") == "CTX-123"
    assert text_of(ev, "MaxElements") == "256"


def test_release_request():
    ev = t.release_request("dc01", "CTX-123", message_id=MID)
    assert text_of(ev, "Action") == t.ACTION_RELEASE
    assert text_of(ev, "EnumerationContext") == "CTX-123"


def test_scope_map_translates_cli_scopes():
    assert t.SCOPE == {"base": "base", "one": "onelevel", "sub": "subtree"}


# --- WS-Transfer Get ------------------------------------------------------

def test_get_request_core_fields_use_resource_endpoint():
    ev = t.get_request("dc01.corp.local", "CN=alice,DC=corp,DC=local",
                       message_id=MID)
    assert text_of(ev, "Action") == t.ACTION_GET
    assert text_of(ev, "To") == \
        "net.tcp://dc01.corp.local:9389/ActiveDirectoryWebServices/Windows/Resource"
    assert text_of(ev, "MessageID") == MID
    # ad:instance is the ADWS routing header (always "ldap:389"); the DN
    # travels in ad:objectReferenceProperty per MS-ADDM.
    assert text_of(ev, "instance", prefix="ad") == "ldap:389"
    assert text_of(ev, "objectReferenceProperty", prefix="ad") == \
        "CN=alice,DC=corp,DC=local"
    # Per WS-Transfer + MS-ADDM 3.1 the Body of a Get is empty: no
    # <wxf:Get/> body child, and no Enumerate/Pull/Release elements
    # leaking in from a wrong template.
    assert "Get" not in names(ev)
    assert "Enumerate" not in names(ev)
    assert "Pull" not in names(ev)


def test_get_request_body_is_empty_per_ms_addm():
    """WS-Transfer Get MUST send an empty <s:Body/> (MS-ADDM 3.1 example).

    Regression: an earlier build emitted <s:Body><wxf:Get/></s:Body>, which
    Windows ADWS rejects with a SOAP Fault, triggering AdwsClient.get's
    silent fallback to search(scope=base).
    """
    ev = t.get_request("dc01", "CN=x,DC=y", message_id=MID)
    for i, e in enumerate(ev):
        if isinstance(e, StartElement) and e.prefix == "s" and e.name == "Body":
            j = i + 1
            while j < len(ev) and not isinstance(ev[j], (StartElement, EndElement)):
                j += 1
            assert isinstance(ev[j], EndElement), (
                f"Body must have no child elements; got {ev[j]!r} at index {j}")
            return
    raise AssertionError("get_request produced no <s:Body> element")


def test_get_request_object_reference_property_is_not_must_understand():
    """<ad:objectReferenceProperty> must not carry s:mustUnderstand.

    The MS-ADDM 3.1 example does not set the flag; some ADWS builds reject
    the message when it is present (unrecognised mandatory header).
    """
    from adwsearch.transport.nbf.records import Attribute
    ev = t.get_request("dc01", "CN=x,DC=y", message_id=MID)
    for i, e in enumerate(ev):
        if isinstance(e, StartElement) and e.prefix == "ad" and e.name == "objectReferenceProperty":
            j = i + 1
            while j < len(ev) and isinstance(ev[j], Attribute):
                assert not (ev[j].prefix == "s" and ev[j].name == "mustUnderstand"), \
                    "objectReferenceProperty must not be mustUnderstand"
                j += 1
            return
    raise AssertionError("get_request produced no <ad:objectReferenceProperty> header")


def test_get_request_falls_through_to_resource_factory_endpoint():
    ev = t.get_request("dc01", "CN=x,DC=y", message_id=MID,
                       endpoint=t.RESOURCE_FACTORY_ENDPOINT)
    assert text_of(ev, "To").endswith("/Windows/ResourceFactory")


def test_get_request_is_encodable_and_roundtrips():
    ev = t.get_request("dc01", "CN=x,DC=y", message_id=MID)
    assert nbf.decode(nbf.encode(ev)) == ev
