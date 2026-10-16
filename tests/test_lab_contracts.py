# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.lab import conftest


def test_each_lab_client_owns_a_fresh_connection(monkeypatch):
    marker = getattr(conftest.lab_client, '_fixture_function_marker',
                     getattr(conftest.lab_client, '_pytestfixturefunction', None))
    assert marker.scope == 'function'
    connections = [Mock(), Mock()]
    monkeypatch.setattr(conftest, 'connect_adws', Mock(side_effect=connections))
    settings = SimpleNamespace(ip='192.0.2.1', host='dc', timeout=1, credentials=lambda: None)
    first = conftest.lab_client.__wrapped__(settings)
    next(first)
    first.close()
    second = conftest.lab_client.__wrapped__(settings)
    next(second)
    connections[0].close.assert_called_once()
    connections[1].close.assert_not_called()
    second.close()


def test_lab_setup_failure_is_not_a_skip(monkeypatch):
    monkeypatch.setattr(conftest, 'connect_adws', Mock(side_effect=TimeoutError()))
    settings = SimpleNamespace(ip='192.0.2.1', host='dc', timeout=1, credentials=lambda: None)
    with pytest.raises(pytest.fail.Exception):
        next(conftest.lab_client.__wrapped__(settings))


def test_ldap_oracle_detects_missing_page_and_duplicates():
    from tests.lab.reference import assert_same_dns
    from adwsearch.soap.parser import AdObject
    entries = [AdObject('x', {'distinguishedName': [dn]}) for dn in ('DC=x', 'CN=a,DC=x')]
    with pytest.raises(AssertionError, match='missing page'):
        assert_same_dns(entries[:1], entries)
    with pytest.raises(AssertionError, match='duplicate'):
        assert_same_dns(entries + entries[:1], entries)
