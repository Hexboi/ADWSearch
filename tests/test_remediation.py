# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Regression contracts for the operational issues in the remediation plan."""

import json
import logging
from unittest.mock import Mock

import pytest

from adwsearch import cli
from adwsearch.adws import factory
from adwsearch.auth.credentials import parse_hashes


def test_direct_timeout_is_applied_before_handshake(monkeypatch):
    sock = Mock()
    dial = Mock(return_value=sock)
    monkeypatch.setattr(factory.socket, "create_connection", dial)
    monkeypatch.setattr(factory.AdwsConnection, "connect", lambda self: None)
    factory.connect_adws("dc", 9389, object(), timeout=7)
    assert dial.call_args.kwargs["timeout"] == 7
    sock.settimeout.assert_called_once_with(7)


def test_timeout_configuration_failure_closes_socket(monkeypatch):
    sock = Mock()
    sock.settimeout.side_effect = OSError("closed")
    with pytest.raises(OSError):
        factory.connect_adws("dc", 9389, object(),
                             socket_factory=lambda h, p: sock, timeout=7)
    sock.close.assert_called_once()


@pytest.mark.parametrize("value", [":", ":00", ":" + "00" * 17,
                                    "00:" + "11" * 16, ":zz", "a:b:c", ": " + "00" * 15 + " "])
def test_invalid_hashes_are_rejected(value):
    with pytest.raises(ValueError):
        parse_hashes(value)


@pytest.mark.parametrize("extra", [
    ["--hashes", ":invalid-secret"], ["--timeout", "0"],
    ["--page-size", "0"], ["-z", "-1"], ["--port", "65536"],
    ["--sleep", "nan"], ["--jitter", "inf"], ["--socks", ":1080"],
    ["--spn", "host/alias"],
])
def test_bad_cli_input_fails_before_connect(extra, monkeypatch, capsys):
    def forbidden(*a, **kw):
        pytest.fail("input validation opened a connection")
    monkeypatch.setattr(cli, "connect_adws", forbidden)
    with pytest.raises(SystemExit) as exc:
        cli.main(["-H", "dc", "-b", "DC=test", "-w", "secret", *extra])
    assert exc.value.code == 2
    assert "invalid-secret" not in capsys.readouterr().err


def test_missing_cache_is_validated_before_connect(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "connect_adws", lambda *a, **kw: pytest.fail("network"))
    with pytest.raises(SystemExit) as exc:
        cli.main(["-H", "dc", "-b", "DC=test", "-w", "secret", "--dump",
                  "certdump", "--cachefile", str(tmp_path / "absent.json")])
    assert exc.value.code == 2


def test_spn_default_and_override():
    from adwsearch.auth.kerberos_ticket import resolve_spn
    assert resolve_spn("dc.example", None) == "host/dc.example"
    assert resolve_spn("dc.example", "ldap/alias.example@EXAMPLE") == "ldap/alias.example@EXAMPLE"
    with pytest.raises(ValueError):
        resolve_spn("dc", "alias")


def test_logging_is_idempotent_and_keeps_stdout_clean(capsys):
    from adwsearch.logging_config import configure_logging
    configure_logging(1)
    configure_logging(1)
    logging.getLogger("adwsearch.test").info("fallback activated")
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err.count("fallback activated") == 1


def test_enumeration_fault_preserves_directory_error():
    from adwsearch.soap.parser import AdwsSoapFault, parse_enumerate_response
    from adwsearch.transport.nbf.records import EndElement, StartElement, Text
    events = [StartElement("s", "Fault"), StartElement("ad", "Win32ErrorCode"),
              Text(8240), EndElement(), EndElement()]
    with pytest.raises(AdwsSoapFault) as exc:
        parse_enumerate_response(events)
    assert exc.value.win32_error_code == 8240


def test_fault_classification_uses_codes_not_reason():
    from adwsearch.adws.errors import is_missing_object_fault
    from adwsearch.soap.parser import AdwsSoapFault
    assert is_missing_object_fault(AdwsSoapFault(None, None, None, ldap_result_code=32))
    assert not is_missing_object_fault(AdwsSoapFault(None, None, "not found"))


def test_atomic_output_keeps_previous_file_on_failure(tmp_path):
    from adwsearch.output.atomic import atomic_text_file
    path = tmp_path / "output.json"
    path.write_text("previous", encoding="utf-8")
    with pytest.raises(RuntimeError):
        with atomic_text_file(str(path)) as stream:
            stream.write("partial")
            raise RuntimeError("interrupted")
    assert path.read_text(encoding="utf-8") == "previous"
    assert list(tmp_path.iterdir()) == [path]


def test_bucket_spool_produces_valid_bloodhound_json(tmp_path):
    from adwsearch.dump.spool import JsonBucketSpool
    with JsonBucketSpool(str(tmp_path)) as spool:
        spool.append("users", {"ObjectIdentifier": "S-1-5-21-1"})
        counts = spool.publish("full")
    payload = json.loads((tmp_path / "full_outputUsers.json").read_text())
    assert counts["users"] == 1
    assert payload["data"] == [{"ObjectIdentifier": "S-1-5-21-1"}]
    assert payload["meta"]["version"] == 5


def test_bad_cache_schema_does_not_look_empty(tmp_path):
    from adwsearch.dump.cache import Cache
    path = tmp_path / "cache.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        Cache.deserialize(str(path))


def test_dns_stream_does_not_hide_network_failure():
    from types import SimpleNamespace
    from adwsearch.enum.presets import PRESETS
    class Client:
        def search(self, **kwargs):
            raise TimeoutError("lost response")
    args = SimpleNamespace(base="DC=test", dns_include_glue=False, sizelimit=0, page_size=1)
    with pytest.raises(TimeoutError):
        list(PRESETS["dns-dump"].run(Client(), args))


def test_dns_zone_is_derived_from_dn_not_response_order():
    from types import SimpleNamespace
    from adwsearch.enum.presets import PRESETS
    from adwsearch.soap.parser import AdObject
    class Client:
        def search(self, **kwargs):
            if "DomainDnsZones" not in kwargs["base"]:
                return iter(())
            raw = bytes.fromhex("0400010005f000000100000000000e1000000000000000000a000001")
            return iter([AdObject("dnsNode", {"name": ["early"], "dnsRecord": [raw],
                         "distinguishedName": [r"DC=early,DC=first\,zone.test," + kwargs["base"]]}),
                         AdObject("dnsZone", {"name": ["second.test"],
                         "objectClass": ["dnsZone"],
                         "distinguishedName": ["DC=second.test," + kwargs["base"]]}),
                         AdObject("dnsZone", {"name": ["first.test"],
                         "objectClass": ["dnsZone"],
                         "distinguishedName": ["DC=first.test," + kwargs["base"]]})])
    args = SimpleNamespace(base="DC=test", dns_include_glue=True, sizelimit=0, page_size=1)
    assert [e.attributes["zone"] for e in PRESETS["dns-dump"].run(Client(), args)] == [["first,zone.test"], ["second.test"], ["first.test"]]


def test_bhdump_interruption_keeps_old_final_file(tmp_path):
    from adwsearch.dump.bhdump import bhdump
    from adwsearch.dump.cache import Cache
    class Client:
        def search(self, **kwargs):
            raise TimeoutError("query interrupted")
            yield
    final = tmp_path / "full_outputUsers.json"
    final.write_text("old", encoding="utf-8")
    with pytest.raises(TimeoutError):
        bhdump(Client(), "DC=test", str(tmp_path), Cache())
    assert final.read_text() == "old"
