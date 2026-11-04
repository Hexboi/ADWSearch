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


def test_rootdse_discovery_matches_configured_domain(lab_client, lab_settings):
    entry = lab_client.get_rootdse()
    assert entry is not None
    assert entry.attributes['defaultNamingContext'][0].casefold() == lab_settings.base.casefold()
    assert entry.attributes['configurationNamingContext']
    assert entry.attributes['schemaNamingContext']


@pytest.mark.parametrize('preset', [None, *sorted(PRESETS)])
def test_cli_automatic_base_matches_explicit_base(lab_settings, monkeypatch, tmp_path, preset):
    import json
    from adwsearch import cli

    s = lab_settings
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt: s.password)
    argv = ['-H', s.host, '--dc-ip', s.ip, '-u', s.user, '-d', s.domain,
            '-W', '-o', 'json', '--page-size', '2']
    if preset:
        argv += ['--preset', preset]
    else:
        argv += ['-s', 'base', '(objectClass=*)', 'distinguishedName']
    outputs = []
    for explicit in (False, True):
        path = tmp_path / f'{explicit}.json'
        args = [*argv, '--outfile', str(path)]
        if explicit:
            args += ['-b', s.base]
        assert cli.main(args) == 0
        entries = json.loads(path.read_text(encoding='utf-8'))
        outputs.append(sorted(json.dumps({
            'dn': entry['dn'], 'object_class': entry['object_class'],
            'attributes': {name: sorted(values) for name, values in entry['attributes'].items()},
        }, sort_keys=True) for entry in entries))
    assert outputs[0] == outputs[1]


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
    if preset in ("forest-level", "maq", "password-policy"):
        assert len(entries) == 1


def test_password_policy_raw_matches_independent_ldap(lab_client, lab_settings):
    names = ['minPwdLength', 'pwdHistoryLength', 'minPwdAge', 'maxPwdAge',
             'pwdProperties', 'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow', 'forceLogoff']
    reference = ldap_query(lab_settings.base, '(objectClass=domainDNS)', 'base',
                           ['distinguishedName', *names])
    args = SimpleNamespace(base=lab_settings.base, sizelimit=0, page_size=256, raw=True)
    actual = list(PRESETS['password-policy'].run(lab_client, args))
    assert len(actual) == len(reference) == 1

    def normalized(entry):
        return {name.casefold(): sorted(str(v) for v in values)
                for name, values in entry.attributes.items()}
    assert normalized(actual[0]) == normalized(reference[0])
    assert all(name in actual[0].attributes for name in names)
    args.raw = False
    readable = list(PRESETS['password-policy'].run(lab_client, args))[0].attributes
    assert readable['distinguishedName'] == [lab_settings.base]
    for name in names:
        assert str(readable[name][0]).startswith(str(actual[0].attributes[name][0]))
    assert ('DOMAIN_PASSWORD_COMPLEX' in readable['pwdProperties'][0]) == bool(
        int(actual[0].attributes['pwdProperties'][0]) & 1)


@pytest.mark.parametrize('fmt', ['ldif', 'json'])
@pytest.mark.parametrize('raw', [False, True])
def test_password_policy_cli_exports(lab_settings, monkeypatch, tmp_path, fmt, raw):
    import json
    from adwsearch import cli

    s = lab_settings
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt: s.password)
    destination = tmp_path / ('policy.' + fmt)
    argv = ['-H', s.host, '--dc-ip', s.ip, '-u', s.user, '-d', s.domain, '-W',
            '--preset', 'password-policy', '-o', fmt, '--outfile', str(destination)]
    if raw:
        argv += ['--raw']
    assert cli.main(argv) == 0
    text = destination.read_text(encoding='utf-8')
    if fmt == 'json':
        payload = json.loads(text)
        assert len(payload) == 1
        assert payload[0]['dn'] == s.base
        fields = payload[0]['attributes']
    else:
        fields = {line.split(': ', 1)[0]: [line.split(': ', 1)[1]]
                  for line in text.splitlines() if ': ' in line}
        assert fields['dn'] == [s.base]
    names = ['minPwdLength', 'pwdHistoryLength', 'minPwdAge', 'maxPwdAge',
             'pwdProperties', 'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow', 'forceLogoff']
    reference = ldap_query(s.base, '(objectClass=domainDNS)', 'base', names)[0]
    for name in names:
        expected = str(reference.attributes[name][0])
        if raw:
            assert fields[name] == [expected]
        else:
            assert fields[name][0].startswith(expected)
    if not raw:
        assert '(' in fields['maxPwdAge'][0]


@pytest.mark.parametrize('page_size', [2, 256])
def test_users_description_values_and_limit_match_ldap(lab_client, lab_settings, page_size):
    attrs = ['distinguishedName', 'sAMAccountName', 'description']
    reference = ldap_query(lab_settings.base, '(sAMAccountType=805306368)',
                           attributes=attrs, page_size=page_size)

    def normalized(entries):
        result = {}
        for entry in entries:
            fields = {k.casefold(): v for k, v in entry.attributes.items()}
            dn = fields['distinguishedname'][0].casefold()
            assert dn not in result, 'duplicate user DN'
            result[dn] = {k: sorted(str(v) for v in fields[k])
                          for k in ('samaccountname', 'description') if k in fields}
        return result

    args = SimpleNamespace(base=lab_settings.base, sizelimit=0, page_size=page_size)
    actual = list(PRESETS['users-description'].run(lab_client, args))
    expected = normalized(reference)
    assert normalized(actual) == expected
    args.sizelimit = 3
    limited = list(PRESETS['users-description'].run(lab_client, args))
    assert len(limited) == min(3, len(expected))
    assert normalized(limited).items() <= expected.items()


@pytest.mark.parametrize('fmt', ['table', 'json', 'ldif'])
def test_users_description_cli_exports(lab_settings, monkeypatch, tmp_path, fmt):
    import io
    import json
    from adwsearch import cli
    from adwsearch.output.writers import write_ldif, write_users_description

    s = lab_settings
    reference = ldap_query(s.base, '(sAMAccountType=805306368)',
                           attributes=['distinguishedName', 'sAMAccountName', 'description'])
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt: s.password)
    destination = tmp_path / ('users.' + fmt)
    argv = ['-H', s.host, '--dc-ip', s.ip, '-u', s.user, '-d', s.domain,
            '-W', '-b', s.base, '--preset', 'users-description',
            '--page-size', '2', '--outfile', str(destination)]
    if fmt != 'table':
        argv += ['-o', fmt]
    assert cli.main(argv) == 0
    text = destination.read_text(encoding='utf-8')
    if fmt == 'json':
        actual = json.loads(text)
        assert len(actual) == len(reference)
        by_dn = {entry['dn'].casefold(): entry['attributes'] for entry in actual}
        assert len(by_dn) == len(actual)
        for entry in reference:
            fields = by_dn[entry.attributes['distinguishedName'][0].casefold()]
            for name in ('sAMAccountName', 'description'):
                assert fields.get(name) == entry.attributes.get(name)
    else:
        expected = io.StringIO()
        writer = write_users_description if fmt == 'table' else write_ldif
        writer(reference, expected)
        if fmt == 'table':
            assert len(text.splitlines()) == len(reference) + 2
            assert sorted(text.splitlines()) == sorted(expected.getvalue().splitlines())
        else:
            def records(payload):
                return sorted(tuple(sorted(
                    line for line in block.splitlines()
                    if line.split(':', 1)[0] != 'objectReferenceProperty'
                )) for block in payload.strip().split('\n\n') if block)
            assert records(text) == records(expected.getvalue())


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
