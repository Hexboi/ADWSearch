# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from unittest.mock import Mock

import pytest

from adwsearch.auth.credentials import Credentials
from adwsearch.auth import kerberos, kerberos_ticket


@pytest.fixture(autouse=True)
def initial_metadata(monkeypatch):
    monkeypatch.setattr(kerberos, '_initial_timestamp', lambda *args: ('fixture', 0))


def test_explicit_spn_ticket_is_used_without_host_prefix_rewrite(monkeypatch):
    creds = Credentials("alice", "EXAMPLE")
    ticket = {"KDC_REP": b"ticket", "cipher": Mock(enctype=17), "sessionKey": b"key"}
    loader = Mock(return_value=ticket)
    initial = Mock(return_value=(Mock(enctype=17), b"key", b"spnego"))
    monkeypatch.setattr(kerberos, "load_service_ticket", loader)
    monkeypatch.setattr(kerberos._krb5, "getKerberosType1", initial)
    context = kerberos.KerberosSecurityContext(creds, "dc.example", "192.0.2.10",
                                               spn="ldap/alias.example")
    assert context.step(None) == b"spnego"
    loader.assert_called_once_with(creds, "ldap/alias.example", "192.0.2.10", policy="aes", timeout=30)
    assert initial.call_args.kwargs["TGS"] is ticket
    assert initial.call_args.kwargs["useCache"] is False


def test_default_spn_also_requires_ticket_from_cache(monkeypatch):
    monkeypatch.setattr(kerberos, "load_service_ticket", Mock(side_effect=ValueError("missing cache")))
    initial = Mock()
    monkeypatch.setattr(kerberos._krb5, "getKerberosType1", initial)
    with pytest.raises(RuntimeError, match="cache"):
        kerberos.KerberosSecurityContext(Credentials("alice"), "dc.example").step(None)
    initial.assert_not_called()


def test_service_ticket_exact_lookup_rejects_different_cached_service(monkeypatch, tmp_path):
    path = tmp_path / "cache"
    path.write_bytes(b"cache fixture")
    monkeypatch.setenv("KRB5CCNAME", "FILE:" + str(path))
    cache = Mock()
    cache.principal.prettyPrint.return_value = b"alice@EXAMPLE"
    # A credential for another service must never be selected by anySPN fallback.
    cache.credentials = []
    monkeypatch.setattr(kerberos_ticket.CCache, "loadFile", Mock(return_value=cache))
    with pytest.raises(ValueError, match="neither"):
        kerberos_ticket.load_service_ticket(Credentials("alice", "EXAMPLE"),
                                             "ldap/alias", "192.0.2.10")
    cache.getCredential.assert_not_called()


@pytest.mark.parametrize("credentials", [Credentials("bob", "EXAMPLE"), Credentials("alice", "OTHER")])
def test_cache_principal_mismatch_is_rejected(monkeypatch, tmp_path, credentials):
    path = tmp_path / "cache"
    path.touch()
    monkeypatch.setenv("KRB5CCNAME", str(path))
    cache = Mock()
    cache.principal.prettyPrint.return_value = b"alice@EXAMPLE"
    monkeypatch.setattr(kerberos_ticket.CCache, "loadFile", Mock(return_value=cache))
    with pytest.raises(ValueError, match="does not match"):
        kerberos_ticket.load_service_ticket(credentials, "host/dc", None)
    cache.getCredential.assert_not_called()


def test_cached_ticket_realm_must_match_exactly(monkeypatch, tmp_path):
    path = tmp_path / "cache"
    path.touch()
    monkeypatch.setenv("KRB5CCNAME", str(path))
    cache = Mock()
    cache.principal.prettyPrint.return_value = b"alice@EXAMPLE"
    wrong_ticket = {"server": Mock()}
    wrong_ticket["server"].prettyPrint.return_value = b"host/dc@OTHER"
    cache.getCredential.return_value = wrong_ticket
    cache.credentials = [wrong_ticket]
    monkeypatch.setattr(kerberos_ticket.CCache, "loadFile", Mock(return_value=cache))
    with pytest.raises(ValueError, match="realm"):
        kerberos_ticket.load_service_ticket(Credentials("alice", "EXAMPLE"), "host/dc@EXAMPLE", None)
