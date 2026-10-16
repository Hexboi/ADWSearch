# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from types import SimpleNamespace

import pytest
from impacket.krb5.kerberosv5 import KerberosError

from adwsearch.auth import kerberos_ticket as tickets
from adwsearch.auth.credentials import Credentials
from adwsearch import cli


def backend():
    from adwsearch.auth import kerberos_tgs

    return kerberos_tgs


@pytest.mark.parametrize(
    "policy,expected", [("aes", [(18, 17)]), ("rc4", [(23,)]), ("auto", [(18, 17)])]
)
def test_policy_requests_expected_enctypes(monkeypatch, policy, expected):
    calls = []

    class Tgt:
        def toTGT(self):
            return {"fixture": True}

    monkeypatch.setattr(
        tickets, "_cache_material", lambda *a: ("host/dc", "REALM", None, Tgt())
    )

    def request(*args, enctypes, **kwargs):
        calls.append(tuple(enctypes))
        return {"cipher": SimpleNamespace(enctype=enctypes[0])}

    monkeypatch.setattr(tickets, "request_service_ticket", request, raising=False)
    result = tickets.load_service_ticket(
        Credentials("a", "REALM"), "host/dc", "192.0.2.1", policy=policy
    )
    assert result["cipher"].enctype == expected[0][0]
    assert calls == expected


@pytest.mark.parametrize(
    "error,fallback",
    [
        (KerberosError(14), True),
        (KerberosError(7), False),
        (TimeoutError(), False),
        (ValueError("bad reply"), False),
    ],
)
def test_auto_falls_back_only_for_etype_nosupp(monkeypatch, error, fallback):
    calls = []

    class Tgt:
        def toTGT(self):
            return {}

    monkeypatch.setattr(
        tickets, "_cache_material", lambda *a: ("host/dc", "REALM", None, Tgt())
    )

    def request(*args, enctypes, **kwargs):
        calls.append(tuple(enctypes))
        if len(calls) == 1:
            raise error
        return {"cipher": SimpleNamespace(enctype=23)}

    monkeypatch.setattr(tickets, "request_service_ticket", request, raising=False)
    if fallback:
        assert (
            tickets.load_service_ticket(
                Credentials(""), "host/dc", None, policy="auto"
            )["cipher"].enctype
            == 23
        )
        assert calls == [(18, 17), (23,)]
    else:
        with pytest.raises(type(error)):
            tickets.load_service_ticket(Credentials(""), "host/dc", None, policy="auto")
        assert calls == [(18, 17)]


def test_rc4_cached_ticket_is_incompatible_with_default_before_network(monkeypatch):
    class Ticket:
        def toTGS(self, service):
            return {"cipher": SimpleNamespace(enctype=23)}

    monkeypatch.setattr(
        tickets, "_cache_material", lambda *a: ("host/dc", "REALM", Ticket(), None)
    )
    with pytest.raises(ValueError):
        tickets.validate_ccache(Credentials(""), "host/dc")


def test_enctype_requires_kerberos(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--kerberos-enctype", "rc4", "--dump", "showstats"])
    assert "requires --kerberos" in capsys.readouterr().err


def test_cache_prefers_policy_compatible_duplicate(monkeypatch, tmp_path):
    from unittest.mock import Mock

    path = tmp_path / "cache"
    path.touch()
    monkeypatch.setenv("KRB5CCNAME", str(path))

    class Ticket(dict):
        def toTGS(self, service):
            return {"cipher": SimpleNamespace(enctype=self["enctype"])}

    entries = []
    for enctype in (23, 18):
        server = Mock()
        server.prettyPrint.return_value = b"host/dc@REALM"
        entries.append(Ticket(server=server, enctype=enctype))
    cache = Mock(credentials=entries)
    cache.principal.prettyPrint.return_value = b"a@REALM"
    monkeypatch.setattr(tickets.CCache, "loadFile", lambda path: cache)
    assert (
        tickets.load_service_ticket(Credentials("a"), "host/dc", None)["cipher"].enctype
        == 18
    )
