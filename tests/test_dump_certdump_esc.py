# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""ADCS ESCx classifier -- fixture templates that must light up specific findings."""

import json
import uuid

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
