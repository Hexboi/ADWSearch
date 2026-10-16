# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import json
import hashlib
import uuid

import pytest

from adwsearch.dump import build_cache, bhdump, certdump, showstats
from tests.lab.reference import ldap_query

pytestmark = pytest.mark.lab


def test_cache_and_bloodhound_autosplit_agree(lab_client, lab_settings, tmp_path):
    cache = build_cache(lab_client, lab_settings.base)
    from impacket.ldap.ldaptypes import LDAP_SID
    reference = ldap_query(lab_settings.base, attributes=['objectGUID', 'objectSid', 'objectClass'])
    for entry in reference:
        sid = entry.attributes.get('objectSid') or []
        if not sid and entry.object_class.casefold() not in (
                'domain', 'domaindns', 'organizationalunit', 'grouppolicycontainer',
                'container', 'rpccontainer', 'msimaging-psps', 'msexchconfigurationcontainer'):
            continue
        expected = (LDAP_SID(data=sid[0]).formatCanonical() if sid else
                    str(uuid.UUID(bytes_le=entry.attributes['objectGUID'][0])).upper())
        assert cache.lookup_by_dn(entry.attributes['distinguishedName'][0])[0] == expected
    assert cache.lookup_by_dn(lab_settings.base)
    cache.serialize(str(tmp_path / "cache.json"))
    assert showstats(cache)["total_objects"] > 0
    full, split = tmp_path / "full", tmp_path / "split"
    bhdump(lab_client, lab_settings.base, str(full), cache)
    bhdump(lab_client, lab_settings.base, str(split), cache, autosplit=True)
    def ids(directory):
        results = {}
        for path in directory.glob("*.json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            assert payload["meta"]["count"] == len(payload["data"])
            assert payload['meta']['version'] == 5
            for node in payload['data']:
                assert node['ObjectIdentifier']
                properties = node['Properties']
                assert properties.get('name') and properties.get('domain')
                dn = properties.get('distinguishedname')
                if dn:
                    assert cache.lookup_by_dn(dn)[0] == node['ObjectIdentifier']
                for relation in node.get('Aces', []):
                    assert relation['PrincipalSID'] and relation['RightName']
            results.setdefault(payload["meta"]["type"], set()).update(n["ObjectIdentifier"] for n in payload["data"])
        return results
    assert ids(full) == ids(split)


def test_adcs_dump_when_ca_is_present(lab_client, lab_settings, tmp_path):
    config = "CN=Configuration," + lab_settings.base
    ca = ldap_query(config, '(objectClass=pKIEnrollmentService)', attributes=['objectGUID', 'cACertificate'])
    if not ca:
        pytest.skip("no Enterprise CA in this lab; positive ADCS collection unavailable")
    counts = certdump(lab_client, lab_settings.base, str(tmp_path), build_cache(lab_client, lab_settings.base))
    assert counts["cas"] >= 1
    assert json.loads((tmp_path / "CA.json").read_text())["meta"]["type"] == "enterprisecas"
    templates = ldap_query(config, '(objectClass=pKICertificateTemplate)', attributes=['objectGUID'])
    for filename, reference in [('CA.json', ca), ('CATemplate.json', templates)]:
        payload = json.loads((tmp_path / filename).read_text())
        assert payload['meta']['count'] == len(reference) == len(payload['data'])
        expected = {str(uuid.UUID(bytes_le=e.attributes['objectGUID'][0])).upper() for e in reference}
        assert {n['ObjectIdentifier'] for n in payload['data']} == expected
    ntauth = ldap_query('CN=NTAuthCertificates,CN=Public Key Services,CN=Services,' + config,
                       scope='base', attributes=['cACertificate'])
    expected = {hashlib.sha1(cert).hexdigest().upper() for e in ntauth for cert in e.attributes.get('cACertificate', [])}
    payload = json.loads((tmp_path / 'NTAuthCertificates.json').read_text())
    actual = {value.upper() for node in payload['data'] for value in node['Properties']['certthumbprints']}
    assert actual == expected
    assert counts['ntauth'] == len(expected)
