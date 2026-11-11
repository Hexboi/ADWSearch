# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import json
import hashlib
import uuid

import pytest

from adwsearch.dump import build_cache, bhdump, certdump, showstats
from tests.lab.reference import ldap_query

pytestmark = pytest.mark.lab


@pytest.mark.parametrize('page_size,autosplit,sleep,jitter', [
    (1, False, 0, 0), (32, False, 0, 0), (1000, False, 0, 0),
    (2, True, 0, 0), (1000, False, 5, 2),
])
def test_dump_cli_page_size_on_wire(lab_client, lab_settings, monkeypatch, tmp_path,
                                    record_property, page_size, autosplit, sleep, jitter):
    from adwsearch import cli
    from adwsearch.dump import Cache
    from adwsearch.soap import templates

    s = lab_settings
    cache = build_cache(lab_client, s.base)
    baseline = tmp_path / 'baseline'
    bhdump(lab_client, s.base, str(baseline), cache)

    def nodes(directory):
        result = {}
        for path in directory.glob('*.json'):
            payload = json.loads(path.read_text(encoding='utf-8'))
            assert payload['meta']['count'] == len(payload['data'])
            for node in payload['data']:
                if 'ChildObjects' in node:
                    node['ChildObjects'].sort(key=lambda child: child['ObjectIdentifier'])
                key = (payload['meta']['type'], node['ObjectIdentifier'])
                assert key not in result
                result[key] = node
        return result

    pull_sizes = []
    original_pull = templates.pull_request

    def measured_pull(host, context, max_elements, *args, **kwargs):
        pull_sizes.append(max_elements)
        return original_pull(host, context, max_elements, *args, **kwargs)

    monkeypatch.setattr(templates, 'pull_request', measured_pull)
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt: s.password)
    cache_path = tmp_path / 'cache.json'
    argv = ['-H', s.host, '--dc-ip', s.ip, '-u', s.user, '-d', s.domain, '-W',
            '--page-size', str(page_size), '-z', '3', '--cachefile', str(cache_path),
            '--sleep', str(sleep), '--jitter', str(jitter)]
    assert cli.main([*argv, '--dump', 'buildcache']) == 0
    actual_cache = Cache.deserialize(str(cache_path))
    assert actual_cache.value_to_id == cache.value_to_id
    assert actual_cache.id_to_type == cache.id_to_type
    assert pull_sizes and set(pull_sizes) == {page_size}
    record_property('buildcache_pull_count', len(pull_sizes))
    record_property('buildcache_max_elements', page_size)
    pull_sizes.clear()

    output = tmp_path / 'actual'
    assert cli.main([*argv, '--dump', 'bhdump', '--outdir', str(output),
                     *(['--autosplit'] if autosplit else [])]) == 0
    assert pull_sizes and set(pull_sizes) == {page_size}
    assert nodes(output) == nodes(baseline)
    record_property('bhdump_pull_count', len(pull_sizes))
    record_property('bhdump_max_elements', page_size)
    record_property('nodes', len(nodes(output)))


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


@pytest.mark.parametrize('page_size,sleep,jitter', [(1, 0, 0), (7, 0, 0), (256, 5, 2)])
def test_certdump_cli_paging_and_analysis_match_ldap(
        lab_client, lab_settings, monkeypatch, tmp_path, record_property, page_size, sleep, jitter):
    from adwsearch import cli
    import socket
    from adwsearch.soap import templates
    from tests.test_dump_adcs_flags import NAME_FLAGS_MS_CRTD_2_28

    s = lab_settings
    config = 'CN=Configuration,' + s.base
    cas = ldap_query(config, '(objectClass=pKIEnrollmentService)',
                     attributes=['name', 'certificateTemplates'])
    if not cas:
        pytest.skip('no Enterprise CA in this lab')
    attrs = ['name', 'objectGUID', 'msPKI-Certificate-Name-Flag',
             'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'pKIExtendedKeyUsage',
             'msPKI-Certificate-Policy']
    reference = ldap_query(config, '(objectClass=pKICertificateTemplate)', attributes=attrs)
    oid_reference = ldap_query(config, '(objectClass=msPKI-Enterprise-Oid)',
                               attributes=['msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink'])
    group_links = {r.attributes['msPKI-Cert-Template-OID'][0]: r.attributes['msDS-OIDToGroupLink'][0]
                   for r in oid_reference if r.attributes.get('msPKI-Cert-Template-OID')
                   and r.attributes.get('msDS-OIDToGroupLink')}
    cache = build_cache(lab_client, s.base)
    cache_path = tmp_path / 'cache.json'
    cache.serialize(str(cache_path))
    wire_sizes = []
    destinations = []
    original_socket = socket.socket.connect

    def dc_adws_only(sock, address):
        assert address == (s.ip, 9389)
        destinations.append(address)
        return original_socket(sock, address)

    monkeypatch.setattr(socket.socket, 'connect', dc_adws_only)
    original = templates.pull_request

    def measured_pull(host, context, max_elements, *args, **kwargs):
        wire_sizes.append(max_elements)
        return original(host, context, max_elements, *args, **kwargs)

    monkeypatch.setattr(templates, 'pull_request', measured_pull)
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt: s.password)
    assert cli.main(['-H', s.host, '--dc-ip', s.ip, '-u', s.user, '-d', s.domain, '-W',
                     '-b', s.base, '--dump', 'certdump', '--cachefile', str(cache_path),
                     '--outdir', str(tmp_path), '--page-size', str(page_size),
                     '--sleep', str(sleep), '--jitter', str(jitter)]) == 0
    assert wire_sizes and set(wire_sizes) == {page_size}
    assert destinations
    payload = json.loads((tmp_path / 'CATemplate.json').read_text())
    by_id = {n['ObjectIdentifier']: n for n in payload['data']}
    assert len(by_id) == len(reference) == payload['meta']['count']
    published = {str(name).upper() for ca in cas for name in ca.attributes.get('certificateTemplates', [])}
    expected_findings = {'ESC1': set(), 'ESC13': set(), 'ESC17': set()}
    low_priv_sids = {'S-1-1-0', 'S-1-5-11', cache.lookup_by_dn(s.base)[0] + '-513'}
    for entry in reference:
        a = entry.attributes
        pki_id = str(uuid.UUID(bytes_le=a['objectGUID'][0])).upper()
        node = by_id[pki_id]
        props = node['Properties']
        name_flag = int(a['msPKI-Certificate-Name-Flag'][0]) & 0xffffffff
        enrollment_flag = int(a['msPKI-Enrollment-Flag'][0]) & 0xffffffff
        signatures = int((a.get('msPKI-RA-Signature') or [0])[0])
        ekus = set(a.get('pKIExtendedKeyUsage') or [])
        assert props['certificatenameflag'] == name_flag
        assert set(props['certificatenameflags']) == {name for bit, name in NAME_FLAGS_MS_CRTD_2_28 if name_flag & bit}
        assert props['enabled'] == (a['name'][0].upper() in published)
        assert props['requiresmanagerapproval'] == bool(enrollment_flag & 2)
        assert props['authorizedsignatures'] == signatures
        assert set(props['extendedkeyusage']) == ekus
        policies = sorted(set(a.get('msPKI-Certificate-Policy') or []))
        groups = sorted({group_links[oid] for oid in policies if oid in group_links})
        assert props['issuancepolicies'] == policies
        assert props['esc13_group_dns'] == groups
        can_enroll = any(ace['PrincipalSID'] in low_priv_sids and ace['RightName'] in
                         ('Enroll', 'AllExtendedRights', 'GenericAll') for ace in node['Aces'])
        auth_capable = not ekus or bool(ekus & {'1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4',
                                             '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0'})
        if props['enabled'] and not enrollment_flag & 2 and not signatures and can_enroll:
            if name_flag & 1 and auth_capable:
                expected_findings['ESC1'].add(a['name'][0])
            if groups and auth_capable:
                expected_findings['ESC13'].add(a['name'][0])
            server_auth = not ekus or bool(ekus & {'1.3.6.1.5.5.7.3.1', '2.5.29.37.0'})
            if name_flag & 1 and server_auth:
                expected_findings['ESC17'].add(a['name'][0])
    findings = json.loads((tmp_path / 'ADCSFindings.json').read_text())
    for esc, expected in expected_findings.items():
        actual = {row['template'] for row in findings['data'] if row['kind'] == 'template' and esc in row['findings']}
        assert expected <= actual
    record_property('max_elements', page_size)
    record_property('pull_count', len(wire_sizes))
    record_property('templates_checked', len(reference))
    record_property('low_priv_templates', {esc: sorted(names) for esc, names in expected_findings.items()})
    record_property('adws_destinations', destinations)
