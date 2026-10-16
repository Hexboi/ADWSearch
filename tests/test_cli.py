# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""End-to-end CLI wiring (Phase 5).

We patch ``adwsearch.cli.connect_adws`` and ``adwsearch.cli.AdwsClient`` so the tests
exercise the full argparse → credentials → security context → search → writers pipeline
without hitting the network. Dry-run tests hit the summary path directly.
"""

from unittest.mock import MagicMock

import pytest

from adwsearch import cli
from adwsearch.auth.kerberos import KerberosSecurityContext
from adwsearch.auth.ntlm import NtlmSecurityContext
from adwsearch.soap.parser import AdObject
from adwsearch.transport.connection import AdwsConnection


# --- fixtures --------------------------------------------------------------

def _fake_entry(dn, **attrs):
    fields = {"distinguishedName": [dn], **attrs}
    return AdObject(object_class="user", attributes=fields)


@pytest.fixture
def patched_backend(monkeypatch):
    """Replace connect_adws + AdwsClient with recording fakes."""
    captured = {}

    class FakeClient:
        def __init__(self, transport, host, port, **kwargs):
            captured["client_args"] = (transport, host, port)
            captured["resource_factory"] = kwargs["resource_transport_factory"]

        def search(self, base, scope, ldap_filter, attributes, size_limit, page_size):
            captured["search_kwargs"] = dict(
                base=base, scope=scope, ldap_filter=ldap_filter,
                attributes=attributes, size_limit=size_limit, page_size=page_size,
            )
            yield _fake_entry("CN=Alice,DC=corp,DC=local", sAMAccountName=["alice"])
            yield _fake_entry("CN=Bob,DC=corp,DC=local", sAMAccountName=["bob"])

    def fake_connect(host, port, security, *, endpoint=None, socket_factory=None, timeout=30):
        captured["connect_args"] = dict(
            host=host, port=port, security=security,
            endpoint=endpoint, socket_factory=socket_factory,
        )
        # spec=AdwsConnection: any method not on AdwsConnection (e.g. a typo'd
        # close-alike) will fail loudly instead of being auto-created.
        conn = MagicMock(spec=AdwsConnection)
        captured["connection"] = conn
        return conn

    monkeypatch.setattr(cli, "connect_adws", fake_connect)
    monkeypatch.setattr(cli, "AdwsClient", FakeClient)
    return captured


# --- help / validation -----------------------------------------------------

def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "adwsearch" in out.lower()


def test_missing_host_errors(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["-u", "alice", "-w", "pw", "-b", "DC=x"])
    assert excinfo.value.code != 0
    assert "host" in capsys.readouterr().err.lower()


def test_missing_auth_errors(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["-H", "dc01", "-b", "DC=x", "-u", "alice"])
    assert excinfo.value.code != 0
    assert "auth" in capsys.readouterr().err.lower()


def test_missing_base_errors(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["-H", "dc01", "-u", "alice", "-w", "pw"])
    assert excinfo.value.code != 0
    assert "base" in capsys.readouterr().err.lower()


# --- dry run ---------------------------------------------------------------

def test_dry_run_kerberos_errors_when_no_ccache(monkeypatch, capsys):
    """--dry-run + --kerberos must catch a missing KRB5CCNAME before the operator
    thinks the engagement is ready to go."""
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    monkeypatch.setattr(cli, "connect_adws",
                        MagicMock(side_effect=AssertionError("must not connect")))
    rc = cli.main([
        "-H", "dc01.corp.local", "-u", "alice", "-d", "CORP.LOCAL",
        "-k", "-b", "DC=corp,DC=local", "--dry-run",
    ])
    assert rc != 0
    assert "KRB5CCNAME" in capsys.readouterr().err


def test_dry_run_kerberos_errors_when_ccache_file_missing(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("KRB5CCNAME", str(tmp_path / "does-not-exist.ccache"))
    monkeypatch.setattr(cli, "connect_adws",
                        MagicMock(side_effect=AssertionError("must not connect")))
    rc = cli.main([
        "-H", "dc01.corp.local", "-u", "alice", "-d", "CORP.LOCAL",
        "-k", "-b", "DC=corp,DC=local", "--dry-run",
    ])
    assert rc != 0
    err = capsys.readouterr().err.lower()
    assert "ccache" in err or "not found" in err or "does not exist" in err


def test_dry_run_prints_summary_without_connecting(capsys, monkeypatch):
    monkeypatch.setattr(cli, "connect_adws",
                        MagicMock(side_effect=AssertionError("must not connect in dry-run")))
    rc = cli.main([
        "-H", "dc01.corp.local", "-u", "alice@CORP", "-w", "pw",
        "-b", "DC=corp,DC=local", "-s", "sub", "(objectClass=user)",
        "sAMAccountName", "memberOf", "--dry-run",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dc01.corp.local" in out
    assert "DC=corp,DC=local" in out
    assert "(objectClass=user)" in out
    assert "sAMAccountName" in out


# --- full flows ------------------------------------------------------------

def test_ntlm_password_flow_produces_ldif_with_entries(patched_backend, capsys):
    rc = cli.main([
        "-H", "dc01.corp.local", "-u", "alice", "-d", "CORP", "-w", "S3cret!",
        "-b", "DC=corp,DC=local",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dn: CN=Alice,DC=corp,DC=local" in out
    assert "dn: CN=Bob,DC=corp,DC=local" in out
    assert "sAMAccountName: alice" in out

    sec = patched_backend["connect_args"]["security"]
    assert isinstance(sec, NtlmSecurityContext)
    assert sec.credentials.username == "alice"
    assert sec.credentials.domain == "CORP"
    assert sec.credentials.password == "S3cret!"
    assert patched_backend["connect_args"]["host"] == "dc01.corp.local"


def test_user_at_domain_syntax_is_split(patched_backend):
    cli.main(["-H", "dc01", "-u", "alice@CORP.LOCAL", "-w", "pw", "-b", "DC=x"])
    sec = patched_backend["connect_args"]["security"]
    assert sec.credentials.username == "alice"
    assert sec.credentials.domain == "CORP.LOCAL"


def test_hashes_flag_wires_pass_the_hash(patched_backend):
    cli.main([
        "-H", "dc01", "-u", "alice", "-d", "CORP",
        "--hashes", ":31d6cfe0d16ae931b73c59d7e0c089c0",
        "-b", "DC=x",
    ])
    sec = patched_backend["connect_args"]["security"]
    assert isinstance(sec, NtlmSecurityContext)
    assert sec.credentials.nthash == bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")
    assert sec.credentials.password == ""


def test_kerberos_flag_selects_kerberos_context(patched_backend, tmp_path, monkeypatch):
    cache = tmp_path / "test.ccache"
    cache.write_bytes(b"test")
    monkeypatch.setenv("KRB5CCNAME", str(cache))
    monkeypatch.setattr(cli, "validate_ccache", lambda *args: None)
    cli.main([
        "-H", "dc01.corp.local", "-u", "alice", "-d", "CORP.LOCAL",
        "-k", "-b", "DC=corp,DC=local",
    ])
    sec = patched_backend["connect_args"]["security"]
    assert isinstance(sec, KerberosSecurityContext)
    assert sec.target_host == "dc01.corp.local"


def test_json_output_option_emits_valid_json(patched_backend, capsys):
    cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=x",
        "-o", "json",
    ])
    import json
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 2
    assert data[0]["dn"] == "CN=Alice,DC=corp,DC=local"


def test_cli_closes_connection_on_happy_path(patched_backend):
    cli.main(["-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=x"])
    patched_backend["connection"].close.assert_called_once()


def test_cli_closes_connection_even_when_writer_fails(patched_backend, monkeypatch):
    def failing_writer(*a, **kw):
        raise RuntimeError("boom")
    monkeypatch.setattr(cli, "write_ldif", failing_writer)
    with pytest.raises(RuntimeError, match="boom"):
        cli.main(["-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=x"])
    patched_backend["connection"].close.assert_called_once()


def test_outfile_writes_to_file(patched_backend, tmp_path):
    out_file = tmp_path / "result.ldif"
    cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=x",
        "--outfile", str(out_file),
    ])
    content = out_file.read_text()
    assert "dn: CN=Alice,DC=corp,DC=local" in content


def test_search_args_pass_through(patched_backend):
    cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw",
        "-b", "DC=corp,DC=local", "-s", "one",
        "-z", "10", "--page-size", "5",
        "(sAMAccountName=alice)", "sAMAccountName", "memberOf",
    ])
    kw = patched_backend["search_kwargs"]
    assert kw["base"] == "DC=corp,DC=local"
    assert kw["scope"] == "one"
    assert kw["ldap_filter"] == "(sAMAccountName=alice)"
    assert kw["attributes"] == ["sAMAccountName", "memberOf"]
    assert kw["size_limit"] == 10
    assert kw["page_size"] == 5


def test_dc_ip_used_for_connection_when_provided(patched_backend):
    cli.main([
        "-H", "dc01.corp.local", "--dc-ip", "192.0.2.10",
        "-u", "alice", "-w", "pw", "-b", "DC=x",
    ])
    # DNS-less connect: use the IP for the socket, but the Kerberos SPN / SOAP wsa:To
    # target stays the FQDN.
    assert patched_backend["connect_args"]["host"] == "192.0.2.10"
    assert patched_backend["client_args"][1] == "dc01.corp.local"


# --- SOCKS -----------------------------------------------------------------

def test_socks_arg_accepts_ipv6_literal(monkeypatch, patched_backend):
    fake_sock_instance = MagicMock(name="FakeSocksSocket")

    class FakeSocksModule:
        SOCKS5 = "SOCKS5_CONST"
        socksocket = MagicMock(return_value=fake_sock_instance)

    import sys
    monkeypatch.setitem(sys.modules, "socks", FakeSocksModule())

    cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=x",
        "--socks", "[::1]:1080",
    ])
    factory = patched_backend["connect_args"]["socket_factory"]
    factory("dc01", 9389)
    # IPv6 literal must be stripped of brackets on the proxy side.
    fake_sock_instance.set_proxy.assert_called_once_with(
        "SOCKS5_CONST", "::1", 1080)


def test_socks_arg_builds_socks5_socket_factory(monkeypatch, patched_backend):
    fake_sock_instance = MagicMock(name="FakeSocksSocket")

    class FakeSocksModule:
        SOCKS5 = "SOCKS5_CONST"
        socksocket = MagicMock(return_value=fake_sock_instance)

    import sys
    monkeypatch.setitem(sys.modules, "socks", FakeSocksModule())

    cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=x",
        "--socks", "127.0.0.1:1080",
    ])

    factory = patched_backend["connect_args"]["socket_factory"]
    assert factory is not None
    factory("dc01", 9389)
    fake_sock_instance.set_proxy.assert_called_once_with(
        "SOCKS5_CONST", "127.0.0.1", 1080)
    fake_sock_instance.connect.assert_called_once_with(("dc01", 9389))


# --- OPSEC rate-limit ------------------------------------------------------

def test_cli_sleep_and_jitter_wrap_transport(patched_backend):
    from adwsearch.adws.rate_limit import RateLimitedTransport
    cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
        "--sleep", "0.5", "--jitter", "0.1",
    ])
    transport = patched_backend["client_args"][0]
    assert isinstance(transport, RateLimitedTransport)
    assert transport._inner is patched_backend["connection"]


def test_cli_default_no_sleep_no_jitter_no_wrap(patched_backend):
    cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
    ])
    transport = patched_backend["client_args"][0]
    assert transport is patched_backend["connection"]


def test_cli_negative_sleep_errors(capsys):
    with pytest.raises(SystemExit):
        cli.main([
            "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=x",
            "--sleep", "-1",
        ])
    err = capsys.readouterr().err.lower()
    assert "sleep" in err and ">= 0" in err


def test_cli_dry_run_prints_rate_limit_line(capsys):
    cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
        "--sleep", "1", "--jitter", "2", "--dry-run",
    ])
    out = capsys.readouterr().out
    assert "rate-limit" in out
    assert "sleep=1.0s" in out
    assert "jitter=2.0s" in out


def test_cli_socks_bad_port_errors_cleanly(capsys):
    """A non-integer port in --socks must surface as a clean parser.error, not
    a bare ValueError traceback."""
    with pytest.raises(SystemExit) as excinfo:
        cli.main([
            "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
            "--socks", "proxy:notaport",
        ])
    assert excinfo.value.code == 2
    err = capsys.readouterr().err.lower()
    assert "--socks" in err
    assert "notaport" in err
