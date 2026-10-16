# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import os
from contextlib import contextmanager

import pytest

from adwsearch.adws.factory import connect_adws
from adwsearch.adws.client import AdwsClient
from adwsearch.auth.kerberos import KerberosSecurityContext
from tests.lab.reference import ldap_query, assert_same_dns

pytestmark = pytest.mark.lab


@pytest.mark.parametrize('policy,expected', [('aes', (17, 18)), ('rc4', (23,)), ('auto', (17, 18))])
def test_aes_ccache_and_explicit_spn(lab_settings, policy, expected):
    if not os.environ.get("KRB5CCNAME"):
        pytest.skip("AES ccache required; no domain policy is changed by this test")
    s = lab_settings
    for spn in (None, os.environ.get("ADWSEARCH_LAB_SPN", "host/" + s.host)):
        security = KerberosSecurityContext(s.credentials(), s.host, s.ip, spn=spn, policy=policy)
        resources = []

        @contextmanager
        def resource():
            fresh = KerberosSecurityContext(s.credentials(), s.host, s.ip, spn=spn, policy=policy)
            resources.append(fresh)
            with connect_adws(s.ip, 9389, fresh, endpoint="Windows/Resource",
                              timeout=s.timeout) as resource_connection:
                yield resource_connection

        with connect_adws(s.ip, 9389, security, timeout=s.timeout) as connection:
            client = AdwsClient(connection, s.host, resource_transport_factory=resource)
            entries = list(client.search(s.base, scope="base", page_size=1))
            transferred = client.get(s.base)
            again = list(client.search(s.base, scope="base", page_size=1))
        assert len(entries) == 1
        assert entries == again
        assert transferred is not None
        assert transferred.attributes['distinguishedName'] == entries[0].attributes['distinguishedName']
        assert len(resources) == 1 and resources[0] is not security
        assert resources[0]._cipher.enctype in expected
        assert security._cipher.enctype in expected


@pytest.mark.parametrize('policy', ['aes', 'rc4', 'auto'])
@pytest.mark.parametrize('page_size', [1, 256])
def test_kerberos_inventory_matches_signed_ldap(lab_settings, policy, page_size):
    if not os.environ.get('KRB5CCNAME'):
        pytest.skip('Kerberos ccache required')
    s = lab_settings
    security = KerberosSecurityContext(s.credentials(), s.host, s.ip, policy=policy)
    with connect_adws(s.ip, 9389, security, timeout=s.timeout) as connection:
        client = AdwsClient(connection, s.host)
        entries = list(client.search(s.base, attributes=['distinguishedName'], page_size=page_size))
        assert len(list(client.search(s.base, scope='base', page_size=1))) == 1
    assert_same_dns(entries, ldap_query(s.base, page_size=page_size))
