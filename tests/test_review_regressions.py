# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Failures identified in the independent whole-change review."""

from unittest.mock import Mock
import io
import logging

import pytest

from adwsearch import cli
from adwsearch.auth import kerberos_ticket
from adwsearch.auth.credentials import Credentials
from adwsearch.dump.cache import Cache
from adwsearch.soap.parser import AdObject


@pytest.mark.parametrize("kind", ["pKIEnrollmentService", "pKICertificateTemplate"])
def test_adcs_spool_io_error_aborts_without_replacing_output(monkeypatch, tmp_path, kind):
    import importlib
    module = importlib.import_module("adwsearch.dump.certdump")
    class Client:
        def search(self, **kwargs):
            if kind in kwargs["ldap_filter"]:
                yield AdObject(kind.lower(), {"name": ["test"], "distinguishedName": ["CN=test,DC=example"]})
                yield AdObject(kind.lower(), {"name": ["test2"], "distinguishedName": ["CN=test2,DC=example"]})
    previous = tmp_path / "CA.json"
    previous.write_text("previous", encoding="utf-8")
    original_append = module.JsonSpool.append
    calls = 0
    def failed_append(self, node):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("disk full")
        original_append(self, node)
    monkeypatch.setattr(module.JsonSpool, "append", failed_append)
    with pytest.raises(OSError, match="disk full"):
        module.certdump(Client(), "DC=example", str(tmp_path), Cache())
    assert previous.read_text() == "previous"
    assert list(tmp_path.iterdir()) == [previous]


def test_invalid_existing_ccache_is_rejected_before_tcp(monkeypatch, tmp_path, capsys):
    cache = tmp_path / "invalid.ccache"
    cache.write_bytes(b"not a ccache")
    monkeypatch.setenv("KRB5CCNAME", str(cache))
    monkeypatch.setattr(cli, "connect_adws", lambda *a, **kw: pytest.fail("TCP opened before cache parsing"))
    assert cli.main(["-H", "dc.example", "-b", "DC=example", "-k"]) == 2
    assert "cache" in capsys.readouterr().err


@pytest.mark.parametrize("user,domain", [("", ""), ("alice", ""), ("", "EXAMPLE")])
def test_missing_kerberos_identity_is_inferred_from_valid_cache(monkeypatch, tmp_path, user, domain):
    path = tmp_path / "valid.ccache"
    path.touch()
    monkeypatch.setenv("KRB5CCNAME", str(path))
    cache = Mock()
    cache.principal.prettyPrint.return_value = b"alice@EXAMPLE"
    class Ticket(dict):
        def toTGS(self, spn):
            return {"KDC_REP": b"ticket", "cipher": Mock(enctype=18), "sessionKey": None}
    ticket = Ticket(server=Mock())
    ticket["server"].prettyPrint.return_value = b"host/dc.example@EXAMPLE"
    cache.getCredential.return_value = ticket
    cache.credentials = [ticket]
    monkeypatch.setattr(kerberos_ticket.CCache, "loadFile", Mock(return_value=cache))
    credentials = Credentials(user, domain)
    kerberos_ticket.load_service_ticket(credentials, "host/dc.example", None)
    assert credentials.username == "alice"
    assert credentials.domain == "EXAMPLE"


def test_exact_realm_ticket_is_selected_independently_of_cache_order(monkeypatch, tmp_path):
    path = tmp_path / "valid.ccache"
    path.touch()
    monkeypatch.setenv("KRB5CCNAME", str(path))
    cache = Mock()
    cache.principal.prettyPrint.return_value = b"alice@EXAMPLE"
    class Ticket(dict):
        def toTGS(self, spn):
            return {"KDC_REP": self["server"].prettyPrint(), "cipher": Mock(enctype=18)}
    wrong, right = Ticket(server=Mock()), Ticket(server=Mock())
    wrong["server"].prettyPrint.return_value = b"host/dc@OTHER"
    right["server"].prettyPrint.return_value = b"host/dc@EXAMPLE"
    cache.getCredential.return_value = wrong
    monkeypatch.setattr(kerberos_ticket.CCache, "loadFile", Mock(return_value=cache))
    for order in ([wrong, right], [right, wrong]):
        cache.credentials = order
        assert kerberos_ticket.load_service_ticket(Credentials("alice", "EXAMPLE"), "host/dc@EXAMPLE", None)["KDC_REP"] == b"host/dc@EXAMPLE"


@pytest.mark.parametrize("extra", [["--hashes", ":invalid"], ["--socks", "invalid"], ["-k"]])
def test_offline_stats_validates_supplied_options(tmp_path, extra, monkeypatch):
    cache = tmp_path / "cache.json"
    Cache().serialize(str(cache))
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    try:
        result = cli.main(["--dump", "showstats", "--cachefile", str(cache), *extra])
    except SystemExit as exc:
        result = exc.code
    assert result == 2


def test_cli_logging_does_not_propagate_to_root_stdout():
    from adwsearch.logging_config import configure_logging
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        configure_logging(1)
        logging.getLogger("adwsearch.review").info("diagnostic")
    finally:
        root.removeHandler(handler)
    assert output.getvalue() == ""


def test_dns_transport_failure_after_first_page_is_not_swallowed():
    from types import SimpleNamespace
    from adwsearch.enum.presets import PRESETS
    class Client:
        def search(self, **kwargs):
            yield AdObject("dnsZone", {"name": ["example"], "distinguishedName": ["DC=example," + kwargs["base"]]})
            raise TimeoutError("second page failed")
    args = SimpleNamespace(base="DC=example", dns_include_glue=True, sizelimit=0, page_size=1)
    entries = PRESETS["dns-dump"].run(Client(), args)
    assert next(entries).attributes["zone"] == ["example"]
    with pytest.raises(TimeoutError):
        next(entries)
