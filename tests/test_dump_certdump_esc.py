# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""ADCS ESCx classifier -- fixture templates that must light up specific findings."""

import json
import uuid

import pytest

from adwsearch.dump import Cache, certdump
from adwsearch.soap.parser import AdObject

DOMAIN_USERS_SID = "S-1-5-21-1-2-3-513"


def _ca_entry(name="corp-CA", templates=("ESC1-vuln", "User", "SmartcardLogon")):
    return AdObject(
        object_class="pkienrollmentservice",
        attributes={
            "name": [name],
            "displayName": [f"{name} Issuing CA"],
            "distinguishedName": [
                f"CN={name},CN=Enrollment Services,CN=Public Key Services,"
                "CN=Services,CN=Configuration,DC=corp,DC=local"
            ],
            "objectGUID": [uuid.UUID("11111111-2222-3333-4444-555555555555")],
            "dNSHostName": [f"{name}.corp.local"],
            "certificateTemplates": list(templates),
        },
    )


def _mk_sd_bytes_single_ace(
    trustee_sid: str, access_mask: int, object_guid: str | None = None
) -> bytes:
    """Minimal nTSecurityDescriptor granting one object-ACE to ``trustee_sid``.

    Pattern lifted verbatim from tests/test_dump_acl.py:_build_sd so the ACL
    layout stays in sync with the impacket version we use elsewhere.
    """
    from impacket.ldap.ldaptypes import (
        ACCESS_ALLOWED_OBJECT_ACE,
        ACCESS_MASK,
        ACE,
        ACL,
        LDAP_SID,
        SR_SECURITY_DESCRIPTOR,
    )

    def _sid(c):
        s = LDAP_SID()
        s.fromCanonical(c)
        return s

    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    sd["OffsetOwner"] = 0
    sd["OffsetGroup"] = 0
    sd["OffsetSacl"] = 0
    sd["OffsetDacl"] = 0
    sd["OwnerSid"] = _sid("S-1-5-21-1-2-3-500")
    sd["GroupSid"] = _sid("S-1-5-21-1-2-3-500")
    sd["Sacl"] = b""

    body = ACCESS_ALLOWED_OBJECT_ACE()
    m = ACCESS_MASK()
    m["Mask"] = access_mask
    body["Mask"] = m
    body["Sid"] = _sid(trustee_sid)
    if object_guid:
        body["Flags"] = 0x01  # ACE_OBJECT_TYPE_PRESENT
        body["ObjectType"] = uuid.UUID(object_guid).bytes_le
    else:
        body["Flags"] = 0
        body["ObjectType"] = b""
    body["InheritedObjectType"] = b""

    ace = ACE()
    ace["AceType"] = 0x05
    ace["AceFlags"] = 0
    ace["Ace"] = body

    acl = ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = [ace]
    sd["Dacl"] = acl
    return sd.getData()


_PKI_ENROLL_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"


def _esc1_template():
    return AdObject(
        object_class="pkicertificatetemplate",
        attributes={
            "name": ["ESC1-vuln"],
            "displayName": ["ESC1 Vulnerable"],
            "distinguishedName": [
                "CN=ESC1-vuln,CN=Certificate Templates,CN=Public Key Services,"
                "CN=Services,CN=Configuration,DC=corp,DC=local"
            ],
            "objectGUID": [uuid.UUID("66666666-7777-8888-9999-aaaaaaaaaaaa")],
            "msPKI-Minimal-Key-Size": [2048],
            "msPKI-Certificate-Name-Flag": [1],
            "msPKI-Enrollment-Flag": [0],
            "msPKI-Private-Key-Flag": [0x10],
            "msPKI-RA-Signature": [0],
            "msPKI-Template-Schema-Version": [2],
            "msPKI-Cert-Template-OID": ["1.3.6.1.4.1.311.21.8.1.1.1.1.1"],
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
            "nTSecurityDescriptor": [
                _mk_sd_bytes_single_ace(DOMAIN_USERS_SID, 0x100, _PKI_ENROLL_GUID)
            ],
        },
    )


class _StubClient:
    def __init__(self, entries):
        self.entries = entries
        self.calls = []

    def search(self, **kw):
        self.calls.append(kw)
        f = kw["ldap_filter"]
        if "pKIEnrollmentService" in f:
            yield from (
                e for e in self.entries if e.object_class == "pkienrollmentservice"
            )
        elif "pKICertificateTemplate" in f:
            yield from (
                e for e in self.entries if e.object_class == "pkicertificatetemplate"
            )
        elif "msPKI-Enterprise-Oid" in f:
            yield from (e for e in self.entries if e.object_class == 'mspki-enterprise-oid')

    def get(self, dn):
        return None


def test_classifier_flags_esc1_template(tmp_path):
    client = _StubClient([_ca_entry(), _esc1_template()])
    counts = certdump(client, "DC=corp,DC=local", str(tmp_path), Cache())
    assert counts["templates"] == 1

    findings = json.loads((tmp_path / "ADCSFindings.json").read_text(encoding="utf-8"))
    assert findings["meta"]["out_of_scope"] == ["ESC6", "ESC8", "ESC11"]

    rows = findings["data"]
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["template"] == "ESC1-vuln"
    assert row["enabled"] is True
    assert row["published_on"] == ["corp-CA"]
    assert "ESC1" in row["findings"]
    assert row["principals_by_finding"]["ESC1"] == [DOMAIN_USERS_SID]


def test_classifier_skips_unpublished_templates(tmp_path):
    client = _StubClient([_ca_entry(templates=("Other",)), _esc1_template()])
    certdump(client, "DC=corp,DC=local", str(tmp_path), Cache())
    findings = json.loads((tmp_path / "ADCSFindings.json").read_text(encoding="utf-8"))
    assert findings["data"] == []


def test_template_properties_decoded_for_bloodhound(tmp_path):
    client = _StubClient([_ca_entry(), _esc1_template()])
    certdump(client, "DC=corp,DC=local", str(tmp_path), Cache())
    tpl = json.loads((tmp_path / "CATemplate.json").read_text(encoding="utf-8"))
    props = tpl["data"][0]["Properties"]
    assert props["enrolleesuppliessubject"] is True
    assert props["requiresmanagerapproval"] is False
    assert props["authenticationenabled"] is True
    assert props["enabled"] is True
    assert "Client Authentication" in props["effectiveekus"]
    assert "ENROLLEE_SUPPLIES_SUBJECT" in props["certificatenameflags"]


@pytest.mark.parametrize('enrollment_flag,signatures,expected', [
    (0, 0, True), (2, 0, False), (0, 1, False),
])
def test_esc1_all_extended_rights_respects_issuance_requirements(
        tmp_path, enrollment_flag, signatures, expected):
    template = _esc1_template()
    template.attributes['nTSecurityDescriptor'] = [
        _mk_sd_bytes_single_ace(DOMAIN_USERS_SID, 0x100)]
    template.attributes['msPKI-Enrollment-Flag'] = [enrollment_flag]
    template.attributes['msPKI-RA-Signature'] = [signatures]
    certdump(_StubClient([_ca_entry(), template]), 'DC=corp,DC=local', str(tmp_path), Cache())
    rows = json.loads((tmp_path / 'ADCSFindings.json').read_text())['data']
    esc1 = [row for row in rows if 'ESC1' in row['findings']]
    assert bool(esc1) is expected
    if expected:
        assert esc1[0]['principals_by_finding']['ESC1'] == [DOMAIN_USERS_SID]


def test_domain_dns_subject_flag_does_not_create_esc1(tmp_path):
    template = _esc1_template()
    template.attributes['msPKI-Certificate-Name-Flag'] = [0x00400000]
    certdump(_StubClient([_ca_entry(), template]), 'DC=corp,DC=local', str(tmp_path), Cache())
    node = json.loads((tmp_path / 'CATemplate.json').read_text())['data'][0]
    assert node['Properties']['enrolleesuppliessubject'] is False
    assert node['Properties']['certificatenameflags'] == ['SUBJECT_ALT_REQUIRE_DOMAIN_DNS']
    assert 'ESC1' not in node['Properties']['esc_findings']


@pytest.mark.parametrize('policy_oids,expected_groups', [
    ([], []),
    (['1.2.3.99'], []),
    (['1.2.3.10'], ['CN=GroupA,DC=corp,DC=local']),
    (['1.2.3.99', '1.2.3.10'], ['CN=GroupA,DC=corp,DC=local']),
    (['1.2.3.10', '1.2.3.11'], ['CN=GroupA,DC=corp,DC=local', 'CN=GroupB,DC=corp,DC=local']),
])
def test_esc13_joins_all_issuance_policies_not_template_oid(tmp_path, policy_oids, expected_groups):
    template = _esc1_template()
    template.attributes['msPKI-Certificate-Name-Flag'] = [0]
    template.attributes['msPKI-Certificate-Policy'] = policy_oids
    template_oid = template.attributes['msPKI-Cert-Template-OID'][0]
    policies = [AdObject('mspki-enterprise-oid', {
        'msPKI-Cert-Template-OID': [oid], 'msDS-OIDToGroupLink': [group],
    }) for oid, group in [
        ('1.2.3.10', 'CN=GroupA,DC=corp,DC=local'),
        ('1.2.3.11', 'CN=GroupB,DC=corp,DC=local'),
        (template_oid, 'CN=WrongJoin,DC=corp,DC=local'),
    ]]
    client = _StubClient([_ca_entry(), template, *policies])
    certdump(client, 'DC=corp,DC=local', str(tmp_path), Cache())
    props = json.loads((tmp_path / 'CATemplate.json').read_text())['data'][0]['Properties']
    assert ('ESC13' in props['esc_findings']) is bool(expected_groups)
    assert props['issuancepolicies'] == sorted(set(policy_oids))
    assert props['esc13_group_dns'] == expected_groups
    assert props['esc13_group_dn'] == (expected_groups[0] if expected_groups else None)
    assert props['certificate_oid'] == template_oid
    template_call = next(c for c in client.calls if c['ldap_filter'] == '(objectClass=pKICertificateTemplate)')
    assert 'msPKI-Certificate-Policy' in template_call['attributes']
    if expected_groups:
        finding = json.loads((tmp_path / 'ADCSFindings.json').read_text())['data'][0]
        assert finding['esc13_group_dns'] == expected_groups
        assert finding['issuance_policies'] == sorted(set(policy_oids))


@pytest.mark.parametrize('enrollment_flag,signatures,published,has_enroll,eku,expected', [
    (0, 0, True, True, '1.3.6.1.5.5.7.3.2', True),
    (2, 0, True, True, '1.3.6.1.5.5.7.3.2', False),
    (0, 1, True, True, '1.3.6.1.5.5.7.3.2', False),
    (0, 0, False, True, '1.3.6.1.5.5.7.3.2', False),
    (0, 0, True, False, '1.3.6.1.5.5.7.3.2', False),
    (0, 0, True, True, '1.3.6.1.5.5.7.3.1', False),
])
def test_esc13_requires_enrollment_authentication_and_issuance(
        tmp_path, enrollment_flag, signatures, published, has_enroll, eku, expected):
    template = _esc1_template()
    template.attributes.update({
        'msPKI-Certificate-Policy': ['1.2.3.10'],
        'msPKI-Enrollment-Flag': [enrollment_flag], 'msPKI-RA-Signature': [signatures],
        'pKIExtendedKeyUsage': [eku],
    })
    if not has_enroll:
        template.attributes.pop('nTSecurityDescriptor')
    policy = AdObject('mspki-enterprise-oid', {
        'msPKI-Cert-Template-OID': ['1.2.3.10'],
        'msDS-OIDToGroupLink': ['CN=GroupA,DC=corp,DC=local'],
    })
    ca = _ca_entry(templates=('ESC1-vuln',) if published else ())
    certdump(_StubClient([ca, template, policy]), 'DC=corp,DC=local', str(tmp_path), Cache())
    props = json.loads((tmp_path / 'CATemplate.json').read_text())['data'][0]['Properties']
    assert ('ESC13' in props['esc_findings']) is expected


@pytest.mark.parametrize('ekus,expected', [
    (['1.3.6.1.5.5.7.3.1'], True),
    (['1.3.6.1.5.5.7.3.2'], False),
    (['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'], True),
    (['2.5.29.37.0'], True), ([], True),
    (['1.3.6.1.4.1.311.20.2.1'], False),
])
def test_esc17_requires_server_authentication(tmp_path, ekus, expected):
    template = _esc1_template()
    template.attributes['pKIExtendedKeyUsage'] = ekus
    certdump(_StubClient([_ca_entry(), template]), 'DC=corp,DC=local', str(tmp_path), Cache())
    props = json.loads((tmp_path / 'CATemplate.json').read_text())['data'][0]['Properties']
    assert ('ESC17' in props['esc_findings']) is expected
    if expected:
        row = json.loads((tmp_path / 'ADCSFindings.json').read_text())['data'][0]
        assert row['principals_by_finding']['ESC17'] == [DOMAIN_USERS_SID]


@pytest.mark.parametrize('flag,approval,signatures,published,has_enroll', [
    (0, 0, 0, True, True), (0x10000, 0, 0, True, True),
    (1, 2, 0, True, True), (1, 0, 1, True, True),
    (1, 0, 0, False, True), (1, 0, 0, True, False),
])
def test_esc17_respects_subject_and_enrollment_requirements(
        tmp_path, flag, approval, signatures, published, has_enroll):
    template = _esc1_template()
    template.attributes.update({'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.1'],
        'msPKI-Certificate-Name-Flag': [flag], 'msPKI-Enrollment-Flag': [approval],
        'msPKI-RA-Signature': [signatures]})
    if not has_enroll:
        template.attributes.pop('nTSecurityDescriptor')
    ca = _ca_entry(templates=('ESC1-vuln',) if published else ())
    certdump(_StubClient([ca, template]), 'DC=corp,DC=local', str(tmp_path), Cache())
    props = json.loads((tmp_path / 'CATemplate.json').read_text())['data'][0]['Properties']
    assert 'ESC17' not in props['esc_findings']
