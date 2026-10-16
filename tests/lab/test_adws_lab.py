# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import os
from types import SimpleNamespace

import pytest
from impacket.ntlm import compute_nthash

from adwsearch.adws.client import AdwsClient
from adwsearch.adws.factory import connect_adws
from adwsearch.auth.credentials import Credentials
from adwsearch.auth.ntlm import NtlmSecurityContext
from adwsearch.enum.presets import PRESETS
from tests.lab.reference import LdapReference, ldap_query, assert_same_dns

pytestmark = pytest.mark.lab


def test_domain_base_query_matches_signed_ldap(lab_client, lab_settings):
    entries = list(lab_client.search(lab_settings.base, scope="base",
                                     attributes=["distinguishedName"], page_size=1))
    assert len(entries) == 1
    assert entries[0].attributes["distinguishedName"][0].casefold() == lab_settings.base.casefold()
    assert_same_dns(entries, ldap_query(lab_settings.base, scope='base'))


@pytest.mark.parametrize('page_size', [1, 256])
def test_all_domain_dns_match_signed_ldap(lab_client, lab_settings, page_size):
    entries = list(lab_client.search(lab_settings.base, attributes=['distinguishedName'],
                                     page_size=page_size))
    reference = ldap_query(lab_settings.base, page_size=page_size)
    assert_same_dns(entries, reference)


def test_paging_and_transfer_match_search(lab_client, lab_settings):
    entries = list(lab_client.search(lab_settings.base, attributes=["distinguishedName"],
                                     size_limit=3, page_size=1))
    assert len(entries) == 3
    assert len({e.attributes["distinguishedName"][0] for e in entries}) == 3
    transferred = lab_client.get(lab_settings.base)
    searched = list(lab_client.search(lab_settings.base, scope="base",
                                      attributes=["distinguishedName"], page_size=1))[0]
    assert transferred.attributes["distinguishedName"] == searched.attributes["distinguishedName"]


@pytest.mark.parametrize("preset", sorted(PRESETS))
def test_enumeration_presets(lab_client, lab_settings, preset):
    args = SimpleNamespace(base=lab_settings.base, sizelimit=0, page_size=256,
                           spn_class=None, writable_partition="domain", writable_otype="any",
                           dns_include_glue=False)
    entries = list(PRESETS[preset].run(lab_client, args))
    reference = list(PRESETS[preset].run(LdapReference(), args))
    def normalized(rows):
        return sorted(repr(sorted((key.casefold(), sorted(str(v).casefold() for v in values))
                                  for key, values in row.attributes.items()
                                  if key.casefold() not in ('objectreferenceproperty', 'distinguishedname'))) for row in rows)
    assert normalized(entries) == normalized(reference)
    if preset in ("forest-level", "maq"):
        assert len(entries) == 1


def test_pass_the_hash_matches_password(lab_settings, lab_client):
    s = lab_settings
    credentials = Credentials(s.user, s.domain, nthash=compute_nthash(s.password))
    with connect_adws(s.ip, 9389, NtlmSecurityContext(credentials), timeout=s.timeout) as connection:
        entries = list(AdwsClient(connection, s.host).search(s.base, scope="base", page_size=1))
    assert len(entries) == 1
    password_entries = list(lab_client.search(s.base, scope="base", page_size=1))
    assert entries[0].attributes == password_entries[0].attributes


def test_socks_route_when_configured(lab_settings):
    proxy = os.environ.get("ADWSEARCH_LAB_SOCKS")
    if not proxy:
        pytest.skip("set ADWSEARCH_LAB_SOCKS for the optional proxy path")
    from adwsearch.cli import _build_socks5_factory
    s = lab_settings
    with connect_adws(s.ip, 9389, NtlmSecurityContext(s.credentials()), timeout=s.timeout,
                      socket_factory=_build_socks5_factory(proxy, s.timeout)) as connection:
        assert len(list(AdwsClient(connection, s.host).search(s.base, scope="base", page_size=1))) == 1
