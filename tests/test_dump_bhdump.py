# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""BloodHound v5 dump (Phase 10) — schema + dispatch + query shape."""

import json
import uuid

from impacket.ldap.ldaptypes import LDAP_SID

from adwsearch.adws.client import AdwsClient
from adwsearch.dump import Cache, bhdump
from adwsearch.dump.bhdump import SD_FLAGS_OID
from adwsearch.dump.labels import Label
from adwsearch.soap.parser import AdObject
from adwsearch.transport.nbf.records import Attribute, EndElement, StartElement, Text


def _el(prefix, name, children=(), text=None):
    ev = [StartElement(prefix, name)]
    if text is not None:
        ev.append(Text(text))
    for c in children:
        ev += c
    ev.append(EndElement())
    return ev


def _enum_response(context):
    return _el("s", "Envelope", [_el("s", "Body", [
        _el("wsen", "EnumerateResponse",
            [_el("wsen", "EnumerationContext", text=context)])])])


def _pull_response_empty():
    return _el("s", "Envelope", [_el("s", "Body", [
        _el("wsen", "PullResponse",
            [_el("wsen", "EndOfSequence"), _el("wsen", "Items", [])])])])


def _text_of(events, name, prefix=None):
    for i, e in enumerate(events):
        if (isinstance(e, StartElement) and e.name == name
                and (prefix is None or e.prefix == prefix)):
            for e2 in events[i + 1:]:
                if isinstance(e2, Text):
                    return e2.value
                if isinstance(e2, (StartElement, EndElement)):
                    return None
    return None


class _FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, events):
        self.requests.append(events)
        return self.responses.pop(0)


def _sid_bytes(canonical: str) -> bytes:
    sid = LDAP_SID()
    sid.fromCanonical(canonical)
    return sid.getData()


def test_bhdump_writes_seven_files_with_bh5_schema(tmp_path):
    user_sid = "S-1-5-21-1-2-3-1001"
    admins_sid = "S-1-5-21-1-2-3-512"
    ou_guid = "12345678-1234-1234-1234-123456789ABC"

    cache = Cache()
    cache.value_to_id = {
        "cn=alice,ou=sales,dc=corp,dc=local": user_sid,
        "cn=domain admins,cn=users,dc=corp,dc=local": admins_sid,
        "ou=sales,dc=corp,dc=local": ou_guid,
    }
    cache.id_to_type = {
        user_sid: Label.User,
        admins_sid: Label.Group,
        ou_guid: Label.OU,
    }

    class DirectClient:
        def search(self, **kw):
            yield AdObject(object_class="user", attributes={
                "objectSid": [_sid_bytes(user_sid)],
                "objectGUID": [uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")],
                "distinguishedName": ["CN=alice,OU=Sales,DC=corp,DC=local"],
                "sAMAccountName": ["alice"],
                "name": ["alice"],
                "userAccountControl": [0x0200],
                "primaryGroupID": [513],
                "servicePrincipalName": ["HTTP/web01"],
            })
            yield AdObject(object_class="group", attributes={
                "objectSid": [_sid_bytes(admins_sid)],
                "objectGUID": [uuid.UUID("11111111-2222-3333-4444-555555555555")],
                "distinguishedName": ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
                "sAMAccountName": ["Domain Admins"],
                "name": ["Domain Admins"],
                "member": ["CN=alice,OU=Sales,DC=corp,DC=local"],
                "adminCount": [1],
            })
            yield AdObject(object_class="organizationalunit", attributes={
                "objectSid": [],
                "objectGUID": [uuid.UUID(ou_guid)],
                "distinguishedName": ["OU=Sales,DC=corp,DC=local"],
                "name": ["Sales"],
            })

    counts = bhdump(DirectClient(), "DC=corp,DC=local", str(tmp_path), cache)

    assert counts["users"] == 1
    assert counts["groups"] == 1
    assert counts["ous"] == 1

    for kind in ("Users", "Computers", "Groups", "OUs", "GPOs", "Containers", "Domains"):
        assert (tmp_path / f"full_output{kind}.json").exists(), kind

    users = json.loads((tmp_path / "full_outputUsers.json").read_text(encoding="utf-8"))
    assert users["meta"]["version"] == 5
    assert users["meta"]["type"] == "users"
    assert users["meta"]["count"] == 1
    node = users["data"][0]
    assert node["ObjectIdentifier"] == user_sid
    assert node["Aces"] == []
    assert node["IsACLProtected"] is False
    assert node["PrimaryGroupSID"] == "S-1-5-21-1-2-3-513"
    assert node["Properties"]["hasspn"] is True
    assert node["Properties"]["enabled"] is True

    groups = json.loads((tmp_path / "full_outputGroups.json").read_text(encoding="utf-8"))
    g = groups["data"][0]
    assert g["Members"] == [{"ObjectIdentifier": user_sid, "ObjectType": "User"}]
    assert g["Properties"]["admincount"] is True

    ous = json.loads((tmp_path / "full_outputOUs.json").read_text(encoding="utf-8"))
    ou = ous["data"][0]
    assert ou["ObjectIdentifier"] == ou_guid
    child_ids = {c["ObjectIdentifier"] for c in ou["ChildObjects"]}
    assert user_sid in child_ids


def test_bhdump_sends_soaphound_filter_and_sd_flags_control(tmp_path):
    t = _FakeTransport([_enum_response("C1"), _pull_response_empty()])
    client = AdwsClient(t, "dc01")
    cache = Cache()
    bhdump(client, "DC=corp,DC=local", str(tmp_path), cache)

    # SOAPHound-style filter lives on the Enumerate request.
    enum_req = t.requests[0]
    assert _text_of(enum_req, "Filter", prefix="adlq") == "(!soaphound=*)"

    # ADWS requires LDAP controls on the Pull, not the Enumerate (verified
    # against a live DC): look for <ad:control type="..."/> there.
    pull_req = t.requests[1]
    control_types = []
    for i, e in enumerate(pull_req):
        if isinstance(e, StartElement) and e.name == "control" and e.prefix == "ad":
            for e2 in pull_req[i + 1: i + 5]:
                if isinstance(e2, Attribute) and e2.name == "type":
                    control_types.append(e2.value)
    assert SD_FLAGS_OID in control_types


def test_bhdump_ignores_unknown_object_classes(tmp_path):
    cache = Cache()

    class DirectClient:
        def search(self, **kw):
            yield AdObject(object_class="mssoledbsomething", attributes={
                "distinguishedName": ["CN=weird,DC=x"],
                "name": ["weird"],
            })

    counts = bhdump(DirectClient(), "DC=x", str(tmp_path), cache)
    assert sum(counts.values()) == 0


def test_bhdump_autosplit_iterates_per_letter(tmp_path):
    """Autosplit mode must fire 37 queries (26 letters + 10 digits + nonchars)."""
    class DirectClient:
        def __init__(self):
            self.filters = []

        def search(self, **kw):
            self.filters.append(kw["ldap_filter"])
            return iter([])

    client = DirectClient()
    counts = bhdump(client, "DC=x", str(tmp_path), Cache(), autosplit=True)

    # 26 letters + 10 digits + 1 nonchars = 37 total queries
    assert len(client.filters) == 37
    # Autosplit anchors on `name` (not `cn`) so OUs (ou=) and the domain
    # object (dc=) aren't silently dropped from the slices.
    assert "(name=a*)" in client.filters
    assert "(name=z*)" in client.filters
    assert "(name=0*)" in client.filters
    # The nonchars catch-all is one big excluder
    assert any("(!(name=a*))" in f and "(!(name=z*))" in f for f in client.filters)
    # No result entries → no per-slice output files (skip empty slices).
    assert sum(counts.values()) == 0
    # Only slices with data write files → no full_* files either.
    assert not any(p.name.startswith("full_") for p in tmp_path.iterdir())
