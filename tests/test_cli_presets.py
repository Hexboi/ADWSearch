# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""CLI dispatch to enumeration presets (Phase 7).

Same monkeypatch pattern as test_cli.py: fake connect_adws + fake AdwsClient so
the tests exercise the full argparse → validation → preset → writer pipeline
without touching the network.
"""

from unittest.mock import MagicMock

import pytest

from adwsearch import cli
from adwsearch.soap.parser import AdObject
from adwsearch.transport.connection import AdwsConnection


def _fake_entry(dn, **attrs):
    fields = {"distinguishedName": [dn], **attrs}
    return AdObject(object_class="user", attributes=fields)


@pytest.fixture
def patched_backend(monkeypatch):
    captured = {"search_kwargs_list": [], "get_dns": []}

    class FakeClient:
        def __init__(self, transport, host, port, **kwargs):
            captured["client_args"] = (transport, host, port)

        def search(self, **kw):
            captured["search_kwargs_list"].append(kw)
            if kw['ldap_filter'] == '(objectClass=domainDNS)':
                yield AdObject('domainDNS', {'distinguishedName': [kw['base']],
                    'minPwdLength': [12], 'maxPwdAge': [0], 'pwdProperties': ['17'],
                    'forceLogoff': ['-9223372036854775808']})
                return
            if "MicrosoftDNS" in kw["base"]:
                yield AdObject("dnsZone", {"name": ["corp.local"],
                    "distinguishedName": ["DC=corp.local," + kw["base"]]})
                return
            yield _fake_entry("CN=svc-sql,OU=Services,DC=corp,DC=local",
                              sAMAccountName=["svc-sql"],
                              description=["SQL service", "Owner: Alice"],
                              servicePrincipalName=["MSSQLSvc/db1.corp.local:1433"])

        def get(self, dn):
            captured["get_dns"].append(dn)
            return _fake_entry(dn, **{"msDS-Behavior-Version": [7],
                                      "ms-DS-MachineAccountQuota": [10]})

    def fake_connect(host, port, security, *, endpoint=None, socket_factory=None, timeout=30):
        captured["connect_args"] = (host, port, security)
        conn = MagicMock(spec=AdwsConnection)
        captured["connection"] = conn
        return conn

    monkeypatch.setattr(cli, "connect_adws", fake_connect)
    monkeypatch.setattr(cli, "AdwsClient", FakeClient)
    return captured


# --- validation -----------------------------------------------------------


@pytest.mark.parametrize('fmt', ['json', 'ldif'])
@pytest.mark.parametrize('raw', [False, True])
def test_password_policy_cli_formats_and_raw(patched_backend, capsys, fmt, raw):
    import json
    argv = ['-H', 'dc01', '-u', 'a', '-w', 'pw', '-b', 'DC=x',
            '--preset', 'password-policy', '-o', fmt]
    if raw:
        argv += ['--raw']
    assert cli.main(argv) == 0
    text = capsys.readouterr().out
    expected = '0' if raw else '0 (never expires)'
    if fmt == 'json':
        entry = json.loads(text)[0]
        assert entry['dn'] == 'DC=x'
        assert entry['attributes']['maxPwdAge'] == [expected]
        assert entry['attributes']['forceLogoff'] == [
            '-9223372036854775808' if raw else '-9223372036854775808 (forced logoff disabled)']
    else:
        assert 'dn: DC=x' in text
        assert 'maxPwdAge: ' + expected + '\n' in text
        assert ('forceLogoff: -9223372036854775808' +
                ('' if raw else ' (forced logoff disabled)') + '\n') in text
    assert ('DOMAIN_PASSWORD_COMPLEX' in text) is not raw


def test_password_policy_dry_run_and_conflicts(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail('dry-run or invalid query must not connect')
    monkeypatch.setattr(cli, 'connect_adws', forbidden)
    argv = ['-H', 'dc01', '-u', 'a', '-w', 'pw', '--preset', 'password-policy']
    assert cli.main([*argv, '--dry-run']) == 0
    output = capsys.readouterr().out
    assert '(auto: defaultNamingContext)' in output
    assert '(objectClass=domainDNS)' in output
    assert 'lockOutObservationWindow' in output
    for extra in (['(cn=a)'], ['--dump', 'buildcache']):
        with pytest.raises(SystemExit):
            cli.main([*argv, *extra])


@pytest.mark.parametrize('fmt', [None, 'table', 'json', 'ldif'])
def test_users_description_output_formats(patched_backend, capsys, fmt):
    import json
    argv = ['-H', 'dc01', '-u', 'alice', '-w', 'pw', '-b', 'DC=x',
            '--preset', 'users-description']
    if fmt:
        argv += ['-o', fmt]
    assert cli.main(argv) == 0
    text = capsys.readouterr().out
    if fmt == 'json':
        entry = json.loads(text)[0]
        assert entry['attributes']['description'] == ['SQL service', 'Owner: Alice']
        assert entry['dn'] == 'CN=svc-sql,OU=Services,DC=corp,DC=local'
    elif fmt == 'ldif':
        assert 'dn: CN=svc-sql,' in text
        assert 'description: SQL service' in text
    else:
        assert len(text.splitlines()) == 3
        assert text.startswith('USER')
        assert 'SQL service ; Owner: Alice' in text


@pytest.mark.parametrize('selection', [[], ['--preset', 'spn'], ['--dump', 'showstats']])
def test_table_rejected_elsewhere_before_password_prompt(monkeypatch, selection, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail('invalid table invocation must not prompt or connect')
    monkeypatch.setattr(cli.getpass, 'getpass', forbidden)
    monkeypatch.setattr(cli, 'connect_adws', forbidden)
    with pytest.raises(SystemExit) as error:
        cli.main(['-H', 'dc01', '-u', 'alice', '-W', '-b', 'DC=x', '-o', 'table', *selection])
    assert error.value.code == 2
    assert '--preset users-description' in capsys.readouterr().err


def test_users_description_dry_run_resolves_table_without_connecting(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail('dry-run must not connect')
    monkeypatch.setattr(cli, 'connect_adws', forbidden)
    assert cli.main(['-H', 'dc01', '-u', 'a', '-w', 'pw', '-b', 'DC=x',
                     '--preset', 'users-description', '--dry-run']) == 0
    out = capsys.readouterr().out
    assert 'output:  table' in out
    assert '(sAMAccountType=805306368)' in out
    assert 'distinguishedName sAMAccountName description' in out


def test_users_description_raw_outfile_and_atomic_failure(patched_backend, tmp_path, monkeypatch):
    destination = tmp_path / 'users.txt'
    argv = ['-H', 'dc01', '-u', 'a', '-w', 'pw', '-b', 'DC=x',
            '--preset', 'users-description', '--raw', '--outfile', str(destination)]
    assert cli.main(argv) == 0
    text = destination.read_text(encoding='utf-8')
    assert 'SQL service ; Owner: Alice' in text

    def failing_writer(entries, stream, *, raw=False):
        stream.write('partial')
        raise OSError('simulated failure')
    monkeypatch.setattr(cli, 'write_users_description', failing_writer)
    assert cli.main(argv) == 1
    assert destination.read_text(encoding='utf-8') == text


@pytest.mark.parametrize('extra', [['(cn=someone)'], ['--dump', 'buildcache']])
def test_users_description_rejects_conflicting_query_options(capsys, extra):
    with pytest.raises(SystemExit) as error:
        cli.main(['-H', 'dc01', '-u', 'a', '-w', 'pw', '-b', 'DC=x',
                  '--preset', 'users-description', *extra])
    assert error.value.code == 2

def test_preset_with_positional_filter_errors(capsys):
    with pytest.raises(SystemExit):
        cli.main([
            "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=x",
            "--preset", "spn", "(cn=someone)",
        ])
    err = capsys.readouterr().err.lower()
    assert "preset" in err and "conflict" in err


def test_preset_with_positional_attributes_errors(capsys):
    with pytest.raises(SystemExit):
        cli.main([
            "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=x",
            "--preset", "maq", "(objectClass=*)", "sAMAccountName",
        ])
    assert "preset" in capsys.readouterr().err.lower()


# --- dispatch -------------------------------------------------------------

def test_preset_spn_service_class_dispatches(patched_backend):
    rc = cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
        "--preset", "spn", "--spn-class", "MSSQLSvc",
    ])
    assert rc == 0
    kws = patched_backend["search_kwargs_list"]
    assert len(kws) == 1
    assert kws[0]["ldap_filter"] == "(servicePrincipalName=MSSQLSvc/*)"


def test_preset_kerberoastable_applies_roasting_filter(patched_backend, capsys):
    """Dedicated preset replaces the former --spn-class kerberoastable alias."""
    rc = cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
        "--preset", "kerberoastable",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "sAMAccountName: svc-sql" in out
    kws = patched_backend["search_kwargs_list"]
    assert "(samAccountType=805306368)" in kws[0]["ldap_filter"]
    assert "1.2.840.113556.1.4.803:=2" in kws[0]["ldap_filter"]
    assert "msDS-SupportedEncryptionTypes" in kws[0]["attributes"]


def test_spn_class_kerberoastable_is_rejected_with_migration_message(capsys):
    """The former alias must give a clear error pointing at the new preset,
    not silently search for a service class literally named 'kerberoastable'."""
    import pytest
    with pytest.raises(SystemExit):
        cli.main([
            "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
            "--preset", "spn", "--spn-class", "kerberoastable",
        ])
    err = capsys.readouterr().err
    assert "--preset kerberoastable" in err


def test_preset_forest_level_uses_wstransfer_get(patched_backend):
    """forest-level is a single-object read; it must call client.get, not search."""
    cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
        "--preset", "forest-level",
    ])
    assert patched_backend["get_dns"] == ["DC=corp,DC=local"]
    assert patched_backend["search_kwargs_list"] == []


def test_preset_writable_iterates_all_partitions(patched_backend):
    cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
        "--preset", "writable", "--writable-partition", "all",
    ])
    bases = [kw["base"] for kw in patched_backend["search_kwargs_list"]]
    assert "DC=corp,DC=local" in bases
    assert "CN=Configuration,DC=corp,DC=local" in bases
    assert "CN=Schema,CN=Configuration,DC=corp,DC=local" in bases


def test_preset_dns_dump_include_glue_disables_blacklist(patched_backend):
    cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
        "--preset", "dns-dump", "--dns-include-glue",
    ])
    for kw in patched_backend["search_kwargs_list"]:
        assert "_kerberos" not in kw["ldap_filter"]


# --- dry-run --------------------------------------------------------------

def test_dry_run_preset_includes_resolved_filter(monkeypatch, capsys):
    monkeypatch.setattr(cli, "connect_adws",
                        MagicMock(side_effect=AssertionError("must not connect")))
    rc = cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
        "--preset", "asrep", "--dry-run",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "preset:" in out
    assert "asrep" in out
    assert "1.2.840.113556.1.4.803:=4194304" in out


def test_dry_run_preset_dns_dump_lists_both_bases(monkeypatch, capsys):
    monkeypatch.setattr(cli, "connect_adws",
                        MagicMock(side_effect=AssertionError("must not connect")))
    rc = cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
        "--preset", "dns-dump", "--dry-run",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local" in out
    assert "CN=MicrosoftDNS,CN=System,DC=corp,DC=local" in out
