# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Preset query construction + post-processing (offline).

For each preset we drive it with a FakeTransport that captures the SOAP request
records (already decoded to NBF events by the AdwsClient) and verify the LDAP
filter / base / scope / attributes seen by ADWS.
"""

from contextlib import nullcontext
from dataclasses import dataclass

from adwsearch.adws.client import AdwsClient
from adwsearch.enum import PRESETS
from adwsearch.soap import templates
from adwsearch.soap.parser import AdObject
from adwsearch.transport.nbf.records import EndElement, StartElement, Text, Xmlns


# --- shared helpers -------------------------------------------------------

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


def enum_response(context):
    return el("s", "Envelope", [el("s", "Body", [
        el("wsen", "EnumerateResponse",
           [el("wsen", "EnumerationContext", text=context)])])])


def pull_response(items, end=True):
    inner = []
    if end:
        inner.append(el("wsen", "EndOfSequence"))
    inner.append(el("wsen", "Items", items))
    return el("s", "Envelope",
              [el("s", "Body", [el("wsen", "PullResponse", inner)])])


def item(object_class, attrs):
    children = [el("addata", n, [value(v) for v in vals]) for n, vals in attrs.items()]
    return el("addata", object_class, children)


def get_response(single_item):
    """Wrap a single ``item(...)`` payload inside a wxf:GetResponse envelope."""
    return el("s", "Envelope", [
        el("s", "Header", [el("wsa", "Action", text="http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse")]),
        el("s", "Body", [single_item])])


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


def selection_props(events):
    return [events[i + 1].value for i, e in enumerate(events)
            if isinstance(e, StartElement) and e.name == "SelectionProperty"]


@dataclass
class FakeArgs:
    base: str = "DC=corp,DC=local"
    sizelimit: int = 0
    page_size: int = 256
    writable_otype: str = "any"
    writable_partition: str = "domain"
    dns_include_glue: bool = False
    spn_class: str | None = None


def test_forest_level_formats_numeric_text_from_real_adws():
    from unittest.mock import Mock
    client = Mock()
    client.get.return_value = AdObject('domainDNS', {'msDS-Behavior-Version': ['7']})
    assert list(PRESETS['forest-level'].run(client, FakeArgs()))[0].attributes['msDS-Behavior-Version'] == [
        '7 (DS_BEHAVIOR_WIN2016)']


def test_writable_zero_numeric_text_does_not_claim_writable():
    from unittest.mock import Mock
    client = Mock()
    client.search.return_value = [AdObject('user', {'sDRightsEffective': ['0']})]
    assert list(PRESETS['writable'].run(client, FakeArgs())) == []


# --- forest-level ---------------------------------------------------------

def test_forest_level_uses_wstransfer_get():
    """forest-level reads a single object: one Transfer Get, no Enumerate/Pull."""
    from adwsearch.soap.templates import ACTION_GET
    t = FakeTransport([
        get_response(item("domainDNS", {"msDS-Behavior-Version": [7]})),
    ])
    client = resource_client(t, "dc01")
    out = list(PRESETS["forest-level"].run(client, FakeArgs()))
    assert len(t.requests) == 1
    assert text_of(t.requests[0], "Action") == ACTION_GET
    assert text_of(t.requests[0], "objectReferenceProperty", prefix="ad") == \
        "DC=corp,DC=local"
    # Decoder applied: integer 7 -> labelled release name.
    assert out[0].attributes["msDS-Behavior-Version"] == ["7 (DS_BEHAVIOR_WIN2016)"]


def test_forest_level_decoder_maps_int_to_release_name():
    from adwsearch.enum.constants import format_functional_level
    assert format_functional_level(7) == "7 (DS_BEHAVIOR_WIN2016)"
    assert format_functional_level(10) == "10 (DS_BEHAVIOR_WIN2025)"
    assert format_functional_level(99) == "99"


def test_forest_level_trims_to_single_attribute():
    """WS-Transfer Get returns the full XML view (no attribute selection in
    MS-ADDM) and the search fallback does the same with (objectClass=*).
    The preset must trim to msDS-Behavior-Version client-side so the LDIF
    writer doesn't dump the whole domain root (regression against the
    operator-observed "preset forest-level prints everything" bug)."""
    t = FakeTransport([
        get_response(item("domainDNS", {
            "msDS-Behavior-Version": [7],
            "name": ["corp"],
            "objectSid": [b"\x01\x05\x00"],
            "wellKnownObjects": ["X", "Y", "Z"],
            "gPLink": ["[LDAP://...]"],
        })),
    ])
    out = list(PRESETS["forest-level"].run(resource_client(t, "dc01"), FakeArgs()))
    assert list(out[0].attributes.keys()) == ["msDS-Behavior-Version"]
    assert out[0].attributes["msDS-Behavior-Version"] == ["7 (DS_BEHAVIOR_WIN2016)"]


def test_maq_trims_to_single_attribute():
    """Same trimming rationale as forest-level: single-attribute preset must
    not leak the full object into the LDIF output when the DC (or Transfer)
    returns every attribute."""
    t = FakeTransport([
        get_response(item("domainDNS", {
            "ms-DS-MachineAccountQuota": [10],
            "name": ["corp"],
            "subRefs": ["DC=X", "DC=Y"],
            "maxPwdAge": [-32141664000000000],
        })),
    ])
    out = list(PRESETS["maq"].run(resource_client(t, "dc01"), FakeArgs()))
    assert list(out[0].attributes.keys()) == ["ms-DS-MachineAccountQuota"]
    assert out[0].attributes["ms-DS-MachineAccountQuota"] == [10]


# --- maq ------------------------------------------------------------------

def test_maq_uses_wstransfer_get():
    """maq is a single-object read: one Transfer Get, no Enumerate/Pull."""
    from adwsearch.soap.templates import ACTION_GET
    t = FakeTransport([
        get_response(item("domainDNS", {"ms-DS-MachineAccountQuota": [10]})),
    ])
    client = resource_client(t, "dc01")
    out = list(PRESETS["maq"].run(client, FakeArgs()))
    assert len(t.requests) == 1
    assert text_of(t.requests[0], "Action") == ACTION_GET
    assert text_of(t.requests[0], "objectReferenceProperty", prefix="ad") == \
        "DC=corp,DC=local"
    assert out[0].attributes["ms-DS-MachineAccountQuota"] == [10]


# --- asrep ----------------------------------------------------------------

def test_asrep_query_shape():
    t = FakeTransport([enum_response("C1"), pull_response([], end=True)])
    client = resource_client(t, "dc01")
    list(PRESETS["asrep"].run(client, FakeArgs()))
    enum_req = t.requests[0]
    assert text_of(enum_req, "Scope") == "subtree"
    f = text_of(enum_req, "Filter", prefix="adlq")
    assert "(samAccountType=805306368)" in f
    assert "1.2.840.113556.1.4.803:=4194304" in f  # DONT_REQ_PREAUTH


# --- spn ------------------------------------------------------------------

def test_spn_default_matches_all_service_principal_names():
    t = FakeTransport([enum_response("C1"), pull_response([], end=True)])
    client = resource_client(t, "dc01")
    list(PRESETS["spn"].run(client, FakeArgs()))
    enum_req = t.requests[0]
    assert text_of(enum_req, "Scope") == "subtree"
    assert text_of(enum_req, "Filter", prefix="adlq") == "(servicePrincipalName=*)"
    props = selection_props(enum_req)
    assert "addata:sAMAccountName" in props
    assert "addata:servicePrincipalName" in props
    assert "addata:adminCount" in props
    # Base attrs only — no msDS-SupportedEncryptionTypes without kerberoastable class.
    assert "addata:msDS-SupportedEncryptionTypes" not in props


def test_spn_class_service_filter_restricts_to_service_class():
    t = FakeTransport([enum_response("C1"), pull_response([], end=True)])
    client = resource_client(t, "dc01")
    args = FakeArgs(spn_class="MSSQLSvc")
    list(PRESETS["spn"].run(client, args))
    f = text_of(t.requests[0], "Filter", prefix="adlq")
    assert f == "(servicePrincipalName=MSSQLSvc/*)"


def test_kerberoastable_preset_applies_full_roasting_filter():
    """kerberoastable is now a dedicated preset (was: --spn-class kerberoastable)."""
    t = FakeTransport([enum_response("C1"), pull_response([], end=True)])
    client = resource_client(t, "dc01")
    list(PRESETS["kerberoastable"].run(client, FakeArgs()))
    enum_req = t.requests[0]
    f = text_of(enum_req, "Filter", prefix="adlq")
    assert "(samAccountType=805306368)" in f
    assert "(servicePrincipalName=*)" in f
    assert "1.2.840.113556.1.4.803:=2" in f  # disabled-account exclusion
    props = selection_props(enum_req)
    assert "addata:msDS-SupportedEncryptionTypes" in props


def test_spn_preset_no_longer_special_cases_kerberoastable_class():
    """--spn-class is now a literal service-class filter: the string
    'kerberoastable' matches as an SPN class, not the former alias. The
    CLI layer rejects that value with a migration error; at the preset
    layer we just confirm the filter is literal."""
    t = FakeTransport([enum_response("C1"), pull_response([], end=True)])
    client = resource_client(t, "dc01")
    list(PRESETS["spn"].run(client, FakeArgs(spn_class="kerberoastable")))
    f = text_of(t.requests[0], "Filter", prefix="adlq")
    assert f == "(servicePrincipalName=kerberoastable/*)"
    props = selection_props(t.requests[0])
    assert "addata:msDS-SupportedEncryptionTypes" not in props


# --- writable -------------------------------------------------------------

def test_writable_default_partition_uses_domain_base():
    t = FakeTransport([enum_response("C1"), pull_response([], end=True)])
    client = resource_client(t, "dc01")
    list(PRESETS["writable"].run(client, FakeArgs()))
    assert text_of(t.requests[0], "BaseObject") == "DC=corp,DC=local"


def test_writable_all_partition_iterates_three_bases():
    responses = []
    for i in range(3):
        responses.append(enum_response(f"C-{i}"))
        responses.append(pull_response([], end=True))
    t = FakeTransport(responses)
    client = resource_client(t, "dc01")
    args = FakeArgs(writable_partition="all")
    list(PRESETS["writable"].run(client, args))
    bases = [text_of(r, "BaseObject") for r in t.requests if text_of(r, "BaseObject")]
    assert "DC=corp,DC=local" in bases
    assert "CN=Configuration,DC=corp,DC=local" in bases
    assert "CN=Schema,CN=Configuration,DC=corp,DC=local" in bases


def test_writable_otype_user_uses_saccounttype_filter():
    t = FakeTransport([enum_response("C1"), pull_response([], end=True)])
    client = resource_client(t, "dc01")
    args = FakeArgs(writable_otype="user")
    list(PRESETS["writable"].run(client, args))
    assert text_of(t.requests[0], "Filter", prefix="adlq") == "(sAMAccountType=805306368)"


def test_writable_skips_objects_with_no_effective_rights():
    t = FakeTransport([
        enum_response("C1"),
        pull_response([
            item("user", {}),  # no rights at all
            item("user", {"allowedAttributesEffective": ["description"]}),
        ], end=True),
    ])
    client = resource_client(t, "dc01")
    entries = list(PRESETS["writable"].run(client, FakeArgs()))
    assert len(entries) == 1
    assert entries[0].attributes["allowedAttributesEffective"] == ["description"]


# --- dns-dump -------------------------------------------------------------

def _dns_dump_two_empty_responses():
    responses = []
    for i in range(2):
        responses.append(enum_response(f"C-{i}"))
        responses.append(pull_response([], end=True))
    return responses


def test_dns_dump_iterates_modern_and_legacy_bases():
    t = FakeTransport(_dns_dump_two_empty_responses())
    client = resource_client(t, "dc01")
    list(PRESETS["dns-dump"].run(client, FakeArgs()))
    bases = [text_of(r, "BaseObject") for r in t.requests if text_of(r, "BaseObject")]
    assert "CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local" in bases
    assert "CN=MicrosoftDNS,CN=System,DC=corp,DC=local" in bases


def test_dns_dump_filter_blacklists_glue_by_default():
    t = FakeTransport(_dns_dump_two_empty_responses())
    client = resource_client(t, "dc01")
    list(PRESETS["dns-dump"].run(client, FakeArgs()))
    f = text_of(t.requests[0], "Filter", prefix="adlq")
    assert "(!(name=_kerberos.*))" in f
    assert "(!(name=DomainDnsZones))" in f


def test_dns_dump_include_glue_disables_blacklist():
    t = FakeTransport(_dns_dump_two_empty_responses())
    client = resource_client(t, "dc01")
    args = FakeArgs(dns_include_glue=True)
    list(PRESETS["dns-dump"].run(client, args))
    f = text_of(t.requests[0], "Filter", prefix="adlq")
    assert "_kerberos" not in f
    assert f == "(|(objectClass=dnsNode)(objectClass=dnsZone))"


def test_dns_dump_decodes_a_record_from_dnsrecord_bytes():
    """Feed a valid A record blob through the pipeline; expect a synthetic AdObject."""
    zone_entry = AdObject(
        object_class="dnsZone",
        attributes={"name": ["corp.local"], "objectClass": ["dnsZone"]},
    )
    a_record = bytes.fromhex(
        "0400010005f000000100000000000e1000000000000000000a000001")
    node_entry = AdObject(
        object_class="dnsNode",
        attributes={
            "name": ["dc01"],
            "objectClass": ["dnsNode"],
            "dnsRecord": [a_record],
        },
    )

    class DirectClient:
        def search(self, *a, **kw):
            zone_entry.attributes["distinguishedName"] = ["DC=corp.local," + kw["base"]]
            node_entry.attributes["distinguishedName"] = ["DC=dc01,DC=corp.local," + kw["base"]]
            yield zone_entry
            yield node_entry

    entries = list(PRESETS["dns-dump"].run(DirectClient(), FakeArgs()))
    a_records = [e for e in entries if e.attributes.get("type") == ["A"]]
    assert a_records, "no A record synthesized from the dnsRecord bytes"
    first = a_records[0]
    assert first.attributes["zone"] == ["corp.local"]
    assert first.attributes["name"] == ["dc01"]
    assert first.attributes["data"] == ["10.0.0.1"]
    assert first.attributes["ttl"] == ["3600"]


def test_dns_dump_reverse_lookup_name_reformatted():
    zone_entry = AdObject(
        object_class="dnsZone",
        attributes={"name": ["10.10.10.in-addr.arpa"], "objectClass": ["dnsZone"]},
    )
    ptr_record = bytes.fromhex(
        "13000c0005f00000010000000000012c00000000000000001103046463303104636f7270056c6f63616c00")
    ptr_entry = AdObject(
        object_class="dnsNode",
        attributes={
            "name": ["5"],
            "objectClass": ["dnsNode"],
            "dnsRecord": [ptr_record],
        },
    )

    class DirectClient:
        def search(self, *a, **kw):
            zone_entry.attributes["distinguishedName"] = ["DC=10.10.10.in-addr.arpa," + kw["base"]]
            ptr_entry.attributes["distinguishedName"] = ["DC=5,DC=10.10.10.in-addr.arpa," + kw["base"]]
            yield zone_entry
            yield ptr_entry

    entries = list(PRESETS["dns-dump"].run(DirectClient(), FakeArgs()))
    ptr = [e for e in entries if e.attributes.get("type") == ["PTR"]]
    assert ptr, "no PTR record synthesized"
    assert ptr[0].attributes["name"] == ["5.10.10.10"]  # reverse-lookup reformat


def test_dns_dump_skips_malformed_record_but_keeps_siblings(caplog):
    """A corrupt dnsRecord blob must not abort the whole container walk."""
    zone_entry = AdObject(
        object_class="dnsZone",
        attributes={"name": ["corp.local"], "objectClass": ["dnsZone"]},
    )
    good_a = bytes.fromhex(
        "0400010005f000000100000000000e1000000000000000000a000001")
    bad_record = b"\x04\x00"  # truncated header, parser will IndexError
    node_entry = AdObject(
        object_class="dnsNode",
        attributes={
            "name": ["dc01"],
            "objectClass": ["dnsNode"],
            "dnsRecord": [bad_record, good_a],
        },
    )

    class DirectClient:
        def search(self, *a, **kw):
            zone_entry.attributes["distinguishedName"] = ["DC=corp.local," + kw["base"]]
            node_entry.attributes["distinguishedName"] = ["DC=dc01,DC=corp.local," + kw["base"]]
            yield zone_entry
            yield node_entry

    with caplog.at_level("WARNING", logger="adwsearch.enum.presets"):
        entries = list(PRESETS["dns-dump"].run(DirectClient(), FakeArgs()))

    # _dns_dump_bases walks both the modern and legacy containers, so the
    # DirectClient fake replays its records once per base. The point of this
    # test isn't the count — it's that the good record survives at least once
    # and the bad one is logged rather than raised.
    a_records = [e for e in entries if e.attributes.get("type") == ["A"]]
    assert a_records, "the valid sibling record should still be yielded"
    assert all(r.attributes["data"] == ["10.0.0.1"] for r in a_records)
    assert any("malformed dnsRecord" in m for m in caplog.messages), \
        "the malformed record should produce a warning"

def resource_client(transport, host, port=9389):
    return AdwsClient(transport, host, port, resource_transport_factory=lambda: nullcontext(transport))
