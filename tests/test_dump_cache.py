# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Cache build + serialize/deserialize (offline)."""

import json
import uuid

from impacket.ldap.ldaptypes import LDAP_SID

from adwsearch.adws.client import AdwsClient
from adwsearch.dump import Cache, build_cache
from adwsearch.dump.labels import Label
from adwsearch.soap.parser import AdObject
from adwsearch.transport.nbf.records import EndElement, StartElement, Text


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


def test_build_cache_maps_sid_when_present():
    """Users/computers/groups with objectSid -> mapped via SID + class-derived Label."""
    class DirectClient:
        def search(self, **kw):
            yield AdObject(object_class="user", attributes={
                "objectSid": [_sid_bytes("S-1-5-21-1-2-3-1001")],
                "objectGUID": [],
                "distinguishedName": ["CN=alice,DC=corp,DC=local"],
            })
            yield AdObject(object_class="organizationalunit", attributes={
                "objectSid": [],
                "objectGUID": [uuid.UUID("12345678-1234-1234-1234-123456789ABC")],
                "distinguishedName": ["OU=Sales,DC=corp,DC=local"],
            })
            yield AdObject(object_class="unknownthing", attributes={
                "objectSid": [],
                "objectGUID": [uuid.UUID("00000000-0000-0000-0000-000000000000")],
                "distinguishedName": ["CN=weird,DC=corp,DC=local"],
            })

    cache = build_cache(DirectClient(), "DC=corp,DC=local")

    assert cache.value_to_id["cn=alice,dc=corp,dc=local"] == "S-1-5-21-1-2-3-1001"
    assert cache.id_to_type["S-1-5-21-1-2-3-1001"] == Label.User
    assert cache.value_to_id["ou=sales,dc=corp,dc=local"] == "12345678-1234-1234-1234-123456789ABC"
    assert cache.id_to_type["12345678-1234-1234-1234-123456789ABC"] == Label.OU
    assert "cn=weird,dc=corp,dc=local" not in cache.value_to_id
    assert len(cache.value_to_id) == 2


def test_build_cache_uses_soaphound_negative_filter():
    """Verify the actual ADWS request carries `(!soaphound=*)`."""
    t = _FakeTransport([_enum_response("C1"), _pull_response_empty()])
    client = AdwsClient(t, "dc01")
    build_cache(client, "DC=corp,DC=local")

    enum_req = t.requests[0]
    assert _text_of(enum_req, "Filter", prefix="adlq") == "(!soaphound=*)"
    props = [enum_req[i + 1].value for i, e in enumerate(enum_req)
             if isinstance(e, StartElement) and e.name == "SelectionProperty"]
    assert "addata:objectSid" in props
    assert "addata:objectGUID" in props
    # distinguishedName is a system attribute — client serialises it under the
    # `ad:` namespace (not `addata:`) for ADWS to recognise it.
    assert "ad:distinguishedName" in props


def test_cache_serialize_roundtrip(tmp_path):
    cache = Cache()
    cache.value_to_id = {"cn=alice,dc=x": "S-1-5-21-1-1-1-1001",
                         "ou=sales,dc=x": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"}
    cache.id_to_type = {"S-1-5-21-1-1-1-1001": Label.User,
                        "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE": Label.OU}
    path = tmp_path / "cache.json"
    cache.serialize(str(path))

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert "ValueToIdCache" in raw
    assert "IdToTypeCache" in raw
    assert raw["IdToTypeCache"]["S-1-5-21-1-1-1-1001"] == "User"

    loaded = Cache.deserialize(str(path))
    assert loaded.value_to_id == cache.value_to_id
    assert loaded.id_to_type == cache.id_to_type


def test_cache_dn_lookup_is_case_insensitive():
    cache = Cache()
    cache.value_to_id = {"cn=alice,dc=corp,dc=local": "S-1-5-21-1-2-3-1001"}
    cache.id_to_type = {"S-1-5-21-1-2-3-1001": Label.User}

    assert cache.lookup_by_dn("CN=alice,DC=corp,DC=local") == (
        "S-1-5-21-1-2-3-1001", Label.User)
    assert cache.lookup_by_dn("cn=Alice,dc=CORP,dc=Local") == (
        "S-1-5-21-1-2-3-1001", Label.User)
    assert cache.lookup_by_dn("CN=unknown,DC=x") is None


def test_cache_children_index_groups_by_direct_parent():
    cache = Cache()
    cache.value_to_id = {
        "ou=sales,dc=corp,dc=local":        "GUID-OU-SALES",
        "cn=alice,ou=sales,dc=corp,dc=local": "SID-ALICE",
        "cn=bob,ou=sales,dc=corp,dc=local":   "SID-BOB",
        "ou=eng,dc=corp,dc=local":          "GUID-OU-ENG",
        "cn=carol,ou=eng,dc=corp,dc=local":   "SID-CAROL",
    }
    cache.id_to_type = {
        "GUID-OU-SALES": Label.OU,
        "GUID-OU-ENG":   Label.OU,
        "SID-ALICE":     Label.User,
        "SID-BOB":       Label.User,
        "SID-CAROL":     Label.User,
    }

    idx = cache.children_index()

    sales_children = idx["ou=sales,dc=corp,dc=local"]
    ids = {c["ObjectIdentifier"] for c in sales_children}
    assert ids == {"SID-ALICE", "SID-BOB"}
    assert all(c["ObjectType"] == Label.User.value for c in sales_children)

    eng_children = idx["ou=eng,dc=corp,dc=local"]
    assert [c["ObjectIdentifier"] for c in eng_children] == ["SID-CAROL"]

    # Direct children of the domain root include the two OUs but NOT the users
    # one level deeper.
    root_children = idx["dc=corp,dc=local"]
    root_ids = {c["ObjectIdentifier"] for c in root_children}
    assert root_ids == {"GUID-OU-SALES", "GUID-OU-ENG"}


def test_cache_children_index_returns_empty_for_unknown_parent():
    cache = Cache()
    cache.value_to_id = {"cn=alice,dc=corp,dc=local": "SID-ALICE"}
    cache.id_to_type = {"SID-ALICE": Label.User}
    assert cache.children_index().get("ou=ghost,dc=corp,dc=local") is None


def test_cache_children_index_memoizes_same_instance():
    cache = Cache()
    cache.value_to_id = {"cn=alice,dc=corp,dc=local": "SID-ALICE"}
    cache.id_to_type = {"SID-ALICE": Label.User}
    assert cache.children_index() is cache.children_index()


def test_cache_children_index_matches_linear_baseline():
    """The index must produce the same output a naive endswith/depth scan does."""
    cache = Cache()
    cache.value_to_id = {
        "dc=corp,dc=local":                   "GUID-DOMAIN",
        "ou=a,dc=corp,dc=local":              "GUID-OU-A",
        "ou=b,dc=corp,dc=local":              "GUID-OU-B",
        "cn=x,ou=a,dc=corp,dc=local":         "SID-X",
        "cn=y,ou=b,dc=corp,dc=local":         "SID-Y",
        "cn=deep,ou=sub,ou=a,dc=corp,dc=local": "SID-DEEP",
    }
    cache.id_to_type = {
        "GUID-DOMAIN": Label.Domain, "GUID-OU-A": Label.OU, "GUID-OU-B": Label.OU,
        "SID-X": Label.User, "SID-Y": Label.User, "SID-DEEP": Label.User,
    }

    def _linear(parent_dn):
        parent_lc = parent_dn.lower()
        depth_target = parent_lc.count(",") + 1
        out = []
        for dn_lc, obj_id in cache.value_to_id.items():
            if not dn_lc.endswith("," + parent_lc):
                continue
            if dn_lc.count(",") != depth_target:
                continue
            label = cache.id_to_type.get(obj_id, Label.Base)
            out.append({"ObjectIdentifier": obj_id, "ObjectType": label.value})
        return out

    idx = cache.children_index()
    for parent in ["DC=corp,DC=local", "OU=a,DC=corp,DC=local",
                   "OU=b,DC=corp,DC=local", "OU=sub,OU=a,DC=corp,DC=local",
                   "CN=nowhere,DC=x"]:
        expected = _linear(parent)
        got = idx.get(parent.lower(), [])
        assert sorted(got, key=lambda c: c["ObjectIdentifier"]) == \
               sorted(expected, key=lambda c: c["ObjectIdentifier"])
