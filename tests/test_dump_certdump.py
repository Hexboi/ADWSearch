# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""ADCS certdump (Phase 12) — CAs + templates output shape + query."""

import json
import uuid

from adwsearch.dump import Cache, certdump
from adwsearch.soap.parser import AdObject


def test_certdump_writes_ca_and_template_files_with_v5_schema(tmp_path):
    ca_guid = uuid.UUID("aaaaaaaa-1111-2222-3333-444444444444")
    tpl_guid = uuid.UUID("bbbbbbbb-5555-6666-7777-888888888888")

    class DirectClient:
        def __init__(self):
            self.calls = []

        def search(self, **kw):
            self.calls.append(kw)
            f = kw["ldap_filter"]
            if "pKIEnrollmentService" in f:
                yield AdObject(object_class="pkienrollmentservice", attributes={
                    "name": ["corp-CA"],
                    "displayName": ["Corp Root CA"],
                    "distinguishedName": ["CN=corp-CA,CN=Enrollment Services,"
                                          "CN=Public Key Services,CN=Services,"
                                          "CN=Configuration,DC=corp,DC=local"],
                    "objectGUID": [ca_guid],
                    "dNSHostName": ["ca01.corp.local"],
                    "certificateTemplates": ["User", "Machine"],
                    "cACertificate": [b"\x30\x82\x00\x01"],
                })
            elif "pKICertificateTemplate" in f:
                yield AdObject(object_class="pkicertificatetemplate", attributes={
                    "name": ["User"],
                    "displayName": ["User Template"],
                    "distinguishedName": ["CN=User,CN=Certificate Templates,"
                                          "CN=Public Key Services,CN=Services,"
                                          "CN=Configuration,DC=corp,DC=local"],
                    "objectGUID": [tpl_guid],
                    "msPKI-Minimal-Key-Size": [2048],
                    "msPKI-Certificate-Name-Flag": [1],
                    "msPKI-Enrollment-Flag": [8],
                    "msPKI-Private-Key-Flag": [16],
                    "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
                })

    client = DirectClient()
    cache = Cache()
    counts = certdump(client, "DC=corp,DC=local", str(tmp_path), cache)

    assert counts["cas"] == 1
    assert counts["templates"] == 1
    assert (tmp_path / "CA.json").exists()
    assert (tmp_path / "CATemplate.json").exists()
    assert (tmp_path / "NTAuthCertificates.json").exists()
    assert (tmp_path / "ADCSFindings.json").exists()

    bh_calls = [c for c in client.calls
                if "pKIEnrollmentService" in c["ldap_filter"]
                or "pKICertificateTemplate" in c["ldap_filter"]]
    assert len(bh_calls) == 2
    for c in bh_calls:
        assert c["base"] == "CN=Configuration,DC=corp,DC=local"

    ca = json.loads((tmp_path / "CA.json").read_text(encoding="utf-8"))
    assert ca["meta"]["version"] == 5
    # SharpHound v5 ingest tag required by BH CE (was "cas", rejected as
    # "no valid meta tag found" on the /api/v2/file-upload endpoint).
    assert ca["meta"]["type"] == "enterprisecas"
    assert ca["meta"]["count"] == 1
    node = ca["data"][0]
    assert node["ObjectIdentifier"] == str(ca_guid).upper()
    assert node["Properties"]["dnshostname"] == "ca01.corp.local"
    # Template names are uppercased to match CertTemplate.name as stored by
    # BH-CE during ingest; without this PostADCS cannot wire PublishedTo.
    assert node["Properties"]["certificatetemplates"] == ["USER", "MACHINE"]
    assert node["Properties"]["cacertificate"] == ["30820001"]

    tpl = json.loads((tmp_path / "CATemplate.json").read_text(encoding="utf-8"))
    assert tpl["meta"]["type"] == "certtemplates"
    assert tpl["data"][0]["ObjectIdentifier"] == str(tpl_guid).upper()
    assert tpl["data"][0]["Properties"]["minimalkeysize"] == 2048
    assert tpl["data"][0]["Properties"]["enrollmentflag"] == 8


def test_certdump_uses_sd_flags_control_and_specific_filters(tmp_path):
    class DirectClient:
        def __init__(self):
            self.calls = []

        def search(self, **kw):
            self.calls.append(kw)
            return iter([])

    client = DirectClient()
    certdump(client, "DC=x", str(tmp_path), Cache())

    filters = [c["ldap_filter"] for c in client.calls]
    assert "(objectClass=pKIEnrollmentService)" in filters
    assert "(objectClass=pKICertificateTemplate)" in filters
    # SD_FLAGS control must ride on the BH queries (CA + template). The ESC13
    # OID container scan is a plain enum, no SD_FLAGS needed.
    bh_calls = [c for c in client.calls
                if "pKIEnrollmentService" in c["ldap_filter"]
                or "pKICertificateTemplate" in c["ldap_filter"]]
    for c in bh_calls:
        assert c.get("ldap_controls"), "SD_FLAGS control missing on BH query"
        oids = [oid for oid, _ in c["ldap_controls"]]
        assert "1.2.840.113556.1.4.801" in oids
