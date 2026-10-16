# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from adwsearch.dump.common import rdn_value, split_dn
from adwsearch.dump.cache import Cache
from adwsearch.dump.labels import Label


def test_rdn_preserves_literal_unicode_and_decodes_hex_octets():
    assert rdn_value(r"DC=ni\c3\b1o.test") == "ni\u00f1o.test"
    assert rdn_value("DC=\u00c3\u00a9.test") == "\u00c3\u00a9.test"
    assert split_dn(r"CN=One\,Two,OU=People,DC=test") == [r"CN=One\,Two", "OU=People", "DC=test"]


def test_children_index_respects_escaped_comma():
    cache = Cache({r"cn=one\,two,ou=people,dc=test": "id"}, {"id": Label.User})
    assert cache.children_index()["ou=people,dc=test"] == [{"ObjectIdentifier": "id", "ObjectType": "User"}]
