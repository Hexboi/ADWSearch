# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from contextlib import contextmanager

import pytest

from adwsearch.adws.client import AdwsClient
from adwsearch.soap import parser, templates
from test_adws_client import el, enum_response, fault_response, item, pull_response, action_of, text_of


def direct_response(children=(), action=templates.ACTION_GET + 'Response'):
    return el('s', 'Envelope', [el('s', 'Header', [el('wsa', 'Action', text=action)]),
                               el('s', 'Body', children)])


class Transport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.actions = []
        self.closed = False

    def request(self, events):
        self.actions.append(action_of(events))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        self.closed = True


def resource_factory(transport):
    @contextmanager
    def open_resource():
        try:
            yield transport
        finally:
            transport.close()
    return open_resource


def test_parse_get_response_direct_body():
    obj = parser.parse_get_response(direct_response([item('domainDNS', {'distinguishedName': ['DC=x']})]))
    assert obj.object_class == 'domainDNS'
    assert obj.attributes['distinguishedName'] == ['DC=x']


def test_parse_get_response_direct_empty_body():
    assert parser.parse_get_response(direct_response()) is None


def test_parse_get_response_wrong_action_rejected():
    with pytest.raises(ValueError):
        parser.parse_get_response(direct_response([item('domainDNS', {})], templates.ACTION_PULL))


def test_get_uses_resource_without_poisoning_enumeration():
    search = Transport([enum_response('C'), pull_response(None, [item('domainDNS', {'cn': ['x']})], end=True)])
    resource = Transport([direct_response([item('domainDNS', {'cn': ['x']})])])
    client = AdwsClient(search, 'dc', resource_transport_factory=resource_factory(resource))
    assert client.get('DC=x').attributes['cn'] == ['x']
    assert list(client.search('DC=x'))[0].attributes['cn'] == ['x']
    assert resource.actions == [templates.ACTION_GET]
    assert resource.closed and not search.closed
    assert templates.ACTION_GET not in search.actions


def test_get_without_factory_uses_base_search():
    transport = Transport([enum_response('C'), pull_response(None, [item('user', {'cn': ['a']})], end=True)])
    assert AdwsClient(transport, 'dc').get('CN=a').attributes['cn'] == ['a']
    assert transport.actions == [templates.ACTION_ENUMERATE, templates.ACTION_PULL]


def test_rootdse_get_uses_reserved_guid_and_leaves_enumeration_untouched():
    attrs = {'defaultNamingContext': ['DC=server,DC=test']}
    resource = Transport([direct_response([item('top', attrs)])])
    search = Transport([])
    client = AdwsClient(search, 'dc', resource_transport_factory=resource_factory(resource))
    original = resource.request
    requests = []

    def capture(events):
        requests.append(events)
        return original(events)
    resource.request = capture
    assert client.get_rootdse().attributes == attrs
    assert text_of(requests[0], 'objectReferenceProperty') == '11111111-1111-1111-1111-111111111111'
    assert resource.closed
    assert not search.actions


@pytest.mark.parametrize('factory_present', [False, True])
def test_rootdse_unavailable_never_uses_empty_base_enumeration(factory_present):
    search = Transport([])
    resource = Transport([fault_response()])
    factory = resource_factory(resource) if factory_present else None
    client = AdwsClient(search, 'dc', resource_transport_factory=factory)
    with pytest.raises(ValueError, match='RootDSE'):
        client.get_rootdse()
    assert not search.actions


def test_get_unsupported_falls_back_on_healthy_enumeration():
    search = Transport([enum_response('C'), pull_response(None, [item('user', {'cn': ['a']})], end=True)])
    resource = Transport([fault_response()])
    client = AdwsClient(search, 'dc', resource_transport_factory=resource_factory(resource))
    assert client.get('CN=a').attributes['cn'] == ['a']
    assert resource.closed
    assert resource.actions == [templates.ACTION_GET]


@pytest.mark.parametrize('error', [ValueError('bad signature'), TimeoutError(), ConnectionResetError()])
def test_get_transport_errors_propagate(error):
    resource = Transport([error])
    search = Transport([])
    client = AdwsClient(search, 'dc', resource_transport_factory=resource_factory(resource))
    with pytest.raises(type(error)):
        client.get('CN=a')
    assert resource.closed
    assert not search.actions


def test_resource_and_enumeration_share_pacing():
    from adwsearch.adws import rate_limit
    assert hasattr(rate_limit, 'RequestPacer')
    sleeps = []
    pacer = rate_limit.RequestPacer(2, 0, sleeper=sleeps.append)
    a = rate_limit.RateLimitedTransport(Transport([[], []]), pacer=pacer)
    b = rate_limit.RateLimitedTransport(Transport([[]]), pacer=pacer)
    a.request([])
    b.request([])
    a.request([])
    assert sleeps == [2.0, 2.0]
