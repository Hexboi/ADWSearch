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
            if "MicrosoftDNS" in kw["base"]:
                yield AdObject("dnsZone", {"name": ["corp.local"],
                    "distinguishedName": ["DC=corp.local," + kw["base"]]})
                return
            yield _fake_entry("CN=svc-sql,OU=Services,DC=corp,DC=local",
                              sAMAccountName=["svc-sql"],
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
