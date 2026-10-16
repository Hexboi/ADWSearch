# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""ADCS certdump: CAs + certificate templates + NTAuthCertificates via ADWS.

Produces BloodHound-CE v5 compatible JSON for CAs and templates, enriched with
the boolean properties (``enrolleesuppliessubject``, ``nosecurityextension``,
``effectiveekus`` ...) that BHCE's cypher queries need to materialise the
``ADCSESC1..15`` edges. Also writes two operator-oriented files:

* ``NTAuthCertificates.json`` -- parsed CA certs trusted for client auth.
* ``ADCSFindings.json`` -- flat list of templates with the ESCx verdicts.

Everything runs over the existing ADWS :9389 channel: no DCOM/RPC to the CA,
no enrollment, no writes. ESC6, ESC8 and ESC11 are explicitly out of scope
because they require RPC/HTTP introspection on the CA itself.
"""

import json
import logging
import os
from contextlib import ExitStack
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from adwsearch.dump._coerce import guid_to_canonical
from adwsearch.dump.acl import parse_aces
from adwsearch.dump.adcs_flags import (
    ANY_PURPOSE_OID,
    CERTIFICATE_NAME_FLAG,
    CERTIFICATE_REQUEST_AGENT_OID,
    ENROLLMENT_FLAG,
    PRIVATE_KEY_FLAG,
    _as_u32,
    decode_eku,
    decode_flag,
    eku_contains,
    eku_grants_authentication,
)
from adwsearch.dump.common import (
    SD_FLAGS_OWNER_GROUP_DACL as SD_FLAGS_ALL,
    SD_FLAGS_OID,
    datetime_to_unix as _datetime_to_unix,
    domain_from_dn as _domain_from_dn,
    first_value as _first,
)
from adwsearch.adws.errors import is_missing_object_fault
from adwsearch.soap.parser import AdwsSoapFault
from adwsearch.output.atomic import atomic_text_file
from adwsearch.dump.spool import JsonSpool

_log = logging.getLogger(__name__)


_CA_ATTRS = [
    "name",
    "displayName",
    "distinguishedName",
    "objectGUID",
    "nTSecurityDescriptor",
    "dNSHostName",
    "cACertificate",
    "certificateTemplates",
    "msPKI-Enrollment-Servers",
    "flags",
]

_TEMPLATE_ATTRS = [
    "name",
    "displayName",
    "distinguishedName",
    "objectGUID",
    "nTSecurityDescriptor",
    "msPKI-Minimal-Key-Size",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-Private-Key-Flag",
    "msPKI-RA-Signature",
    "msPKI-Template-Schema-Version",
    "msPKI-Cert-Template-OID",
    "pKIExtendedKeyUsage",
    "pKIOverlapPeriod",
    "pKIExpirationPeriod",
    "pKIMaxIssuingDepth",
    "whenCreated",
]

# ESC6/8/11 need non-LDAP channels (CA registry, HTTP endpoints, RPC signing).
_OUT_OF_SCOPE_ESC = ["ESC6", "ESC8", "ESC11"]

# Baseline "privileged" SIDs: findings only matter when a *non*-privileged
# principal has the right. Mirrors Certipy's filter.
_PRIVILEGED_SID_SUFFIXES = (
    "-500",  # Administrator
    "-512",  # Domain Admins
    "-516",  # Domain Controllers
    "-518",  # Schema Admins
    "-519",  # Enterprise Admins
    "-520",  # Group Policy Creator Owners
    "-521",  # Read-only Domain Controllers
    "-498",  # Enterprise Read-only Domain Controllers
    "-553",  # RAS and IAS Servers (schema-privileged)
)
_PRIVILEGED_WELL_KNOWN = {
    "S-1-5-18",
    "S-1-5-19",
    "S-1-5-20",
    "S-1-5-32-544",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
    "S-1-5-32-552",
    "S-1-5-9",
}


def _is_non_priv_sid(sid: str, dc_sids: set[str] | None = None) -> bool:
    if not sid:
        return False
    if sid in _PRIVILEGED_WELL_KNOWN:
        return False
    if any(sid.endswith(suffix) for suffix in _PRIVILEGED_SID_SUFFIXES):
        return False
    # DC machine accounts (SIDs that resolve to a DN under ``OU=Domain
    # Controllers``) are infrastructure, not realistic attackers. Treat them
    # the same as the DOMAIN CONTROLLERS group (``-516``).
    if dc_sids is not None and sid in dc_sids:
        return False
    return True


def _non_priv_principals(
    aces: list[dict], right_names: set[str], dc_sids: set[str] | None = None
) -> list[str]:
    out = []
    for ace in aces:
        if ace.get("RightName") not in right_names:
            continue
        sid = ace.get("PrincipalSID") or ""
        if _is_non_priv_sid(sid, dc_sids):
            out.append(sid)
    return sorted(set(out))


def _dc_machine_sids(cache) -> set[str]:
    """Return the set of SIDs whose cached DN sits under ``OU=Domain Controllers``.

    Lets the classifier treat DC machine accounts as infrastructure instead of
    "a non-privileged principal with WriteDacl on the CA". Case-insensitive
    match on the DN substring, which is how the DNs are stored in the cache.
    """
    marker = "ou=domain controllers,"
    out: set[str] = set()
    for dn_lc, obj_id in getattr(cache, "value_to_id", {}).items():
        if marker in dn_lc:
            out.add(obj_id)
    return out


def _guid_str(raw) -> str:
    return guid_to_canonical(raw) or ""


def _bytes_to_hex_list(values) -> list[str]:
    out = []
    for v in values or []:
        if isinstance(v, (bytes, bytearray)):
            out.append(bytes(v).hex())
        elif isinstance(v, str):
            out.append(v)
    return out


def _parse_cert_blob(raw) -> dict | None:
    """Parse one DER-encoded X.509 cert blob into a summary dict; ``None`` on fail."""
    if isinstance(raw, str):
        try:
            raw = bytes.fromhex(raw)
        except ValueError:
            return None
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        return None
    try:
        cert = x509.load_der_x509_certificate(bytes(raw))
    except Exception:
        return None
    try:
        sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()
        sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
    except Exception:
        sha1 = sha256 = ""
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial_number": format(cert.serial_number, "X"),
        "thumbprint_sha1": sha1,
        "thumbprint_sha256": sha256,
    }


def _parse_ca_certs(values) -> list[dict]:
    out = []
    for v in values or []:
        parsed = _parse_cert_blob(v)
        if parsed is not None:
            out.append(parsed)
    return out


def _classify_ca(
    aces: list[dict], dc_sids: set[str]
) -> tuple[list[str], dict[str, list[str]]]:
    """ESC7 (LDAP-visible subset): non-priv write control over the AD CA object.

    Does NOT cover the CA-side ``ManageCA`` / ``ManageCertificates`` officer
    rights (those live in the CA registry, reachable only via RRP/DCOM).
    """
    findings: list[str] = []
    principals: dict[str, list[str]] = {}
    esc7_principals = _non_priv_principals(
        aces, {"Owns", "GenericAll", "WriteDacl", "WriteOwner", "GenericWrite"}, dc_sids
    )
    if esc7_principals:
        findings.append("ESC7")
        principals["ESC7"] = esc7_principals
    return findings, principals


def _make_ca_node(entry, cache, dc_sids: set[str]) -> dict:
    aces, is_protected = parse_aces(
        _first(entry.attributes.get("nTSecurityDescriptor") or []), cache
    )
    attrs = entry.attributes
    guid = _guid_str(_first(attrs.get("objectGUID") or []))
    dn = _first(attrs.get("distinguishedName") or []) or ""
    name = _first(attrs.get("name") or []) or ""
    dns_hostname = _first(attrs.get("dNSHostName") or []) or ""
    hostname = dns_hostname.split(".", 1)[0] if dns_hostname else ""
    enrollment_servers = [str(s) for s in (attrs.get("msPKI-Enrollment-Servers") or [])]
    ca_findings, ca_principals = _classify_ca(aces, dc_sids)
    # Pre-parse the certificate chain so Properties can carry the SHA1
    # thumbprints BH-CE needs for TrustedForNTAuth post-processing. The
    # list-of-dict ``cacertificates_parsed`` is kept out of the file sent
    # to BH (stripped in the writer) but the thumbprint array itself is
    # a flat ``array of string`` which Neo4j accepts as a node property.
    parsed = _parse_ca_certs(attrs.get("cACertificate"))
    thumbprints = [c.get("thumbprint_sha1") for c in parsed if c.get("thumbprint_sha1")]
    return {
        "ObjectIdentifier": guid,
        "Properties": {
            "name": name,
            # ``caname`` and ``hostname`` are the SharpHound-v5 field names
            # BH-CE's PostADCS wiring reads to materialise PublishedTo /
            # HostsCAService / TrustedForNTAuth edges. Without them the
            # ADCSESC* chain never fires even though every input is present.
            "caname": name,
            "displayname": _first(attrs.get("displayName") or []),
            "distinguishedname": dn.upper(),
            "domain": _domain_from_dn(dn),
            "domainsid": _domain_sid(cache, _domain_from_dn(dn)),
            "hostname": hostname,
            "dnshostname": dns_hostname,
            # Uppercased to match the ``CertTemplate.name`` BH stores (BH
            # normalises template names to upper-case during ingest). Without
            # this, PostADCS's ``ct.name IN eca.certificatetemplates`` miss
            # fires and no PublishedTo / ADCSESC* edges are produced.
            "certificatetemplates": [
                str(s).upper() for s in (attrs.get("certificateTemplates") or [])
            ],
            "cacertificate": _bytes_to_hex_list(attrs.get("cACertificate")),
            "cacertificates_parsed": parsed,
            # Flat primitives for BH post-processing:
            "certthumbprint": thumbprints[0] if thumbprints else "",
            "certthumbprints": thumbprints,
            "casecuritycollected": False,
            "enrollment_servers": enrollment_servers,
            "esc_findings": ca_findings,
            # ESC6/8/11 live outside LDAP; expose placeholders so operators
            # see the gap rather than assuming "false = safe".
            "isuserspecifiessanenabled": None,
            "hasbasicconstraints": None,
            "unresolvedpublishers": [],
        },
        "Aces": aces,
        "IsACLProtected": is_protected,
        "IsDeleted": False,
        "FindingsPrincipals": ca_principals,
    }


def _resolve_hosting_computer(cache, dns_hostname: str | None) -> str:
    """Return the Computer object's SID whose DN has ``CN=<hostname>,...``.

    The CA's ``dNSHostName`` is the only link we have to the hosting
    machine in the ADWS/LDAP data; the SOAPHound-style cache is keyed by
    DN, so scan it for a DN that starts with ``cn=<shortname>,`` and whose
    label is Computer. Returns ``""`` when the host hasn't been collected
    (e.g. ``certdump`` run without a prior ``buildcache``), which keeps
    the writer safe at the cost of BH falling back to its own
    hostname-match post-processing.
    """
    if not dns_hostname:
        return ""
    short = dns_hostname.split(".", 1)[0].lower()
    v2i = getattr(cache, "value_to_id", None)
    i2t = getattr(cache, "id_to_type", None)
    if not isinstance(v2i, dict) or not isinstance(i2t, dict):
        return ""
    prefix = f"cn={short},"
    for dn, obj_id in v2i.items():
        if dn.startswith(prefix):
            label = i2t.get(obj_id)
            if label is not None and getattr(label, "value", None) == "Computer":
                return str(obj_id)
    return ""


def _domain_sid(cache, domain_fqdn: str) -> str:
    """Best-effort lookup of the domain SID via the SOAPHound-style cache.

    Converts ``CORP.EXAMPLE`` -> ``DC=corp,DC=example`` and
    reads ``value_to_id`` (which the buildcache step populates with every
    object's DN -> objectId mapping). The domain object itself maps to the
    domain SID. Returns empty string when the cache is thin or the base DN
    was never collected (``--dump certdump`` without a prior buildcache),
    which keeps the writer safe at the cost of BH not materialising a few
    ADCS-adjacent edges that need ``domainsid``.
    """
    if not domain_fqdn:
        return ""
    v2i = getattr(cache, "value_to_id", None)
    if not isinstance(v2i, dict):
        return ""
    domain_dn = ",".join(f"dc={part.lower()}" for part in domain_fqdn.split("."))
    sid = v2i.get(domain_dn, "")
    return str(sid) if sid else ""


def _classify_template(
    name_flags: list[str],
    enroll_flags: list[str],
    ekus: list[dict],
    aces: list[dict],
    schema_version: int,
    ra_signature: int,
    enabled: bool,
    esc13_group_dn: str | None,
    dc_sids: set[str],
) -> tuple[list[str], dict[str, list[str]]]:
    """Compute ESCx verdicts for a template.

    Note: the "non-privileged principal" filter is intentionally stricter than
    Certify / Certipy. We only count ACEs whose principal is neither a
    well-known administrator SID nor a DC machine account; Certipy flags any
    ``WriteProperty`` by any non-admin as ESC4, which produces one ESC4 per
    template on default GOAD. Operators who want the aggressive view should
    cross-check with Certipy; this tool prioritises signal over coverage.
    """
    findings: list[str] = []
    principals: dict[str, list[str]] = {}

    enroll_principals = _non_priv_principals(
        aces, {"Enroll", "AutoEnroll", "GenericAll", "GenericWrite"}, dc_sids
    )
    full_control_principals = _non_priv_principals(
        aces, {"Owns", "GenericAll", "WriteDacl", "WriteOwner", "GenericWrite"}, dc_sids
    )

    enrollee_supplies_subject = (
        "ENROLLEE_SUPPLIES_SUBJECT" in name_flags
        or "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME" in name_flags
    )
    requires_manager_approval = "PEND_ALL_REQUESTS" in enroll_flags
    no_security_extension = "NO_SECURITY_EXTENSION" in enroll_flags
    auth_capable = eku_grants_authentication(ekus)
    has_any_purpose = eku_contains(ekus, ANY_PURPOSE_OID)
    has_cert_request_agent = eku_contains(ekus, CERTIFICATE_REQUEST_AGENT_OID)

    if not enabled:
        return findings, principals

    if (
        enroll_principals
        and enrollee_supplies_subject
        and auth_capable
        and not requires_manager_approval
        and ra_signature == 0
    ):
        findings.append("ESC1")
        principals["ESC1"] = enroll_principals

    if (
        enroll_principals
        and (has_any_purpose or not ekus)
        and not requires_manager_approval
        and ra_signature == 0
    ):
        findings.append("ESC2")
        principals["ESC2"] = enroll_principals

    if enroll_principals and has_cert_request_agent and not requires_manager_approval:
        findings.append("ESC3")
        principals["ESC3"] = enroll_principals

    if full_control_principals:
        findings.append("ESC4")
        principals["ESC4"] = full_control_principals

    if enroll_principals and no_security_extension and auth_capable:
        findings.append("ESC9")
        principals["ESC9"] = enroll_principals

    if enroll_principals and esc13_group_dn and auth_capable:
        findings.append("ESC13")
        principals["ESC13"] = enroll_principals

    if (
        schema_version == 1
        and enrollee_supplies_subject
        and enroll_principals
        and not requires_manager_approval
    ):
        findings.append("ESC15")
        principals["ESC15"] = enroll_principals

    return findings, principals


def _make_template_node(
    entry,
    cache,
    published_on: dict[str, list[str]],
    oid_group_links: dict[str, str],
    dc_sids: set[str],
) -> dict:
    aces, is_protected = parse_aces(
        _first(entry.attributes.get("nTSecurityDescriptor") or []), cache
    )
    attrs = entry.attributes
    guid = _guid_str(_first(attrs.get("objectGUID") or []))
    dn = _first(attrs.get("distinguishedName") or []) or ""
    name = _first(attrs.get("name") or []) or ""

    def _int(name_):
        v = _first(attrs.get(name_) or [])
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    raw_enroll = _int("msPKI-Enrollment-Flag")
    raw_name = _int("msPKI-Certificate-Name-Flag")
    raw_pkey = _int("msPKI-Private-Key-Flag")
    schema_v = _int("msPKI-Template-Schema-Version")
    ra_sig = _int("msPKI-RA-Signature")

    enroll_flags = decode_flag(ENROLLMENT_FLAG, raw_enroll)
    name_flags = decode_flag(CERTIFICATE_NAME_FLAG, raw_name)
    pkey_flags = decode_flag(PRIVATE_KEY_FLAG, raw_pkey)
    ekus = decode_eku(attrs.get("pKIExtendedKeyUsage") or [])

    cas_publishing = sorted(published_on.get(name.lower(), []))
    enabled = bool(cas_publishing)

    template_oid = _first(attrs.get("msPKI-Cert-Template-OID") or []) or ""
    esc13_group_dn = (
        oid_group_links.get(str(template_oid).strip()) if template_oid else None
    )

    findings, principals = _classify_template(
        name_flags,
        enroll_flags,
        ekus,
        aces,
        schema_v,
        ra_sig,
        enabled,
        esc13_group_dn,
        dc_sids,
    )

    return {
        "ObjectIdentifier": guid,
        "Properties": {
            "name": name,
            "displayname": _first(attrs.get("displayName") or []),
            "distinguishedname": dn.upper(),
            "domain": _domain_from_dn(dn),
            # BH-CE's PostADCS BuildCache links CertTemplate -> Domain via
            # ``domainsid``; without it ``CertTemplateDomainLinkage`` runs
            # against an empty set and PublishedTo / ADCSESC* never fire.
            "domainsid": _domain_sid(cache, _domain_from_dn(dn)),
            "whencreated": _datetime_to_unix(_first(attrs.get("whenCreated") or [])),
            # Raw ints preserved for backwards compat (as u32 to drop sign bit).
            "minimalkeysize": _int("msPKI-Minimal-Key-Size"),
            "certificatenameflag": _as_u32(raw_name),
            "enrollmentflag": _as_u32(raw_enroll),
            "privatekeyflag": _as_u32(raw_pkey),
            "extendedkeyusage": [
                str(s) for s in (attrs.get("pKIExtendedKeyUsage") or [])
            ],
            # Decoded data BloodHound-CE consumes.
            "schemaversion": schema_v,
            "authorizedsignatures": ra_sig,
            "enrollmentflags": enroll_flags,
            "certificatenameflags": name_flags,
            "privatekeyflags": pkey_flags,
            "effectiveekus": [e["name"] for e in ekus],
            "ekus_detail": ekus,
            "enrolleesuppliessubject": "ENROLLEE_SUPPLIES_SUBJECT" in name_flags
            or "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME" in name_flags,
            "requiresmanagerapproval": "PEND_ALL_REQUESTS" in enroll_flags,
            "nosecurityextension": "NO_SECURITY_EXTENSION" in enroll_flags,
            "authenticationenabled": eku_grants_authentication(ekus),
            "enabled": enabled,
            "published_on": cas_publishing,
            "certificate_oid": str(template_oid),
            "esc13_group_dn": esc13_group_dn,
            "esc_findings": findings,
        },
        "Aces": aces,
        "IsACLProtected": is_protected,
        "IsDeleted": False,
        "FindingsPrincipals": principals,
    }


def _run_query(client, base: str, ldap_filter: str, attrs: list[str]):
    yield from client.search(
        base=base,
        scope="sub",
        ldap_filter=ldap_filter,
        attributes=attrs,
        size_limit=0,
        page_size=500,
        ldap_controls=[(SD_FLAGS_OID, SD_FLAGS_ALL)],
    )


def _fetch_ntauth(client, base: str) -> list[dict]:
    """Fetch CN=NTAuthCertificates and parse the trust-root certs.

    Prefers WS-Transfer Get (single round-trip); on wire-level failure (seen
    on a few DCs where the Transfer response desyncs the NMF stream) falls
    back to a ``search(scope="base")``, which always works because that path
    is already proven live by every other preset.
    """
    dn = f"CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,{base}"
    obj = None
    if hasattr(client, "get"):
        try:
            obj = client.get(dn)
        except AdwsSoapFault as exc:
            if not is_missing_object_fault(exc):
                raise
            return []
    if obj is None:
        try:
            obj = next(
                iter(
                    client.search(
                        base=dn,
                        scope="base",
                        ldap_filter="(objectClass=*)",
                        attributes=["cACertificate"],
                        size_limit=1,
                        page_size=1,
                    )
                ),
                None,
            )
        except AdwsSoapFault as exc:
            if not is_missing_object_fault(exc):
                raise
            return []
    if obj is None:
        return []
    return _parse_ca_certs(obj.attributes.get("cACertificate") or [])


def _build_ntauth_store(certs: list[dict], cas: list[dict], base: str) -> list[dict]:
    """Package parsed NTAuth root certs into a BH-CE NTAuthStore node.

    SharpHound v5 ships a single ``NTAuthStore`` object per domain carrying
    the SHA1 thumbprints of every trust-root certificate; BH post-processing
    reads ``certthumbprints`` to build the ``TrustedForNTAuth`` edge from
    each CA whose chain is anchored there. Our ``certs`` list comes from
    ``_fetch_ntauth``'s raw parse; collapse the SHA1 thumbprints into the
    SharpHound shape so the ingest pipeline can wire everything up.

    Returns a one-element list (so the caller's ``len()`` + ``meta.count``
    stay consistent) or an empty list if the NTAuth container was absent.
    """
    if not certs:
        return []
    domain = ""
    domainsid = ""
    for ca in cas:
        p = ca.get("Properties") or {}
        domain = domain or p.get("domain") or ""
        domainsid = domainsid or p.get("domainsid") or ""
    if not domain:
        # Fall back to deriving the domain FQDN from the base DN.
        domain = _domain_from_dn(base)
    thumbprints = [c["thumbprint_sha1"] for c in certs if c.get("thumbprint_sha1")]
    dn = f"CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,{base}"
    # ObjectIdentifier mirrors SharpHound: a stable per-domain pseudo-GUID
    # keyed off the domain name so re-ingests merge into the same node.
    return [
        {
            "ObjectIdentifier": f"{domain.upper()}-NTAUTHSTORE",
            "Properties": {
                "name": f"NTAUTHSTORE@{domain.upper()}",
                "domain": domain.upper(),
                "domainsid": domainsid,
                "distinguishedname": dn.upper(),
                "certthumbprints": thumbprints,
            },
            "Aces": [],
            "IsACLProtected": False,
            "IsDeleted": False,
        }
    ]


def _fetch_oid_group_links(client, base: str) -> dict[str, str]:
    """ESC13 ground truth: map msPKI-Cert-Template-OID -> linked group DN."""
    oid_base = f"CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,{base}"
    links: dict[str, str] = {}
    try:
        entries = client.search(
            base=oid_base,
            scope="one",
            ldap_filter="(objectClass=msPKI-Enterprise-Oid)",
            attributes=[
                "msDS-OIDToGroupLink",
                "msPKI-Cert-Template-OID",
                "cn",
                "displayName",
            ],
            size_limit=0,
            page_size=500,
        )
        # Consume within this try: generators can fail after returning a page.
        for e in entries:
            oid = _first(e.attributes.get("msPKI-Cert-Template-OID") or [])
            group_dn = _first(e.attributes.get("msDS-OIDToGroupLink") or [])
            if oid and group_dn:
                links[str(oid).strip()] = str(group_dn)
    except AdwsSoapFault as exc:
        if not is_missing_object_fault(exc):
            raise
        return links
    return links


def _build_published_map(cas: list[dict]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for ca in cas:
        ca_name = ca["Properties"].get("name") or ""
        for tmpl in ca["Properties"].get("certificatetemplates") or []:
            out.setdefault(str(tmpl).lower(), []).append(ca_name)
    return out


def _findings_summary(cas: list[dict], templates: list[dict]) -> list[dict]:
    out = []
    for c in cas:
        props = c["Properties"]
        if not props.get("esc_findings"):
            continue
        out.append(
            {
                "kind": "ca",
                "name": props.get("name"),
                "dn": props.get("distinguishedname"),
                "findings": props.get("esc_findings"),
                "principals_by_finding": c.get("FindingsPrincipals") or {},
            }
        )
    for t in templates:
        props = t["Properties"]
        if not props.get("esc_findings"):
            continue
        out.append(
            {
                "kind": "template",
                "template": props.get("name"),
                "dn": props.get("distinguishedname"),
                "oid": props.get("certificate_oid"),
                "published_on": props.get("published_on") or [],
                "findings": props.get("esc_findings"),
                "principals_by_finding": t.get("FindingsPrincipals") or {},
                "enabled": props.get("enabled"),
                "schemaversion": props.get("schemaversion"),
                "effectiveekus": props.get("effectiveekus") or [],
                "esc13_group_dn": props.get("esc13_group_dn"),
            }
        )
    return out


def _write_json(outdir: str, filename: str, data: Any, meta: dict | None = None):
    if isinstance(data, JsonSpool):
        data.publish(os.path.join(outdir, filename), meta)
        return
    payload: dict[str, Any] = {"data": data}
    if meta is not None:
        payload["meta"] = meta
    with atomic_text_file(os.path.join(outdir, filename)) as stream:
        json.dump(payload, stream, indent=2, sort_keys=False, default=str)


def _collect_certdump(client, base: str, outdir: str, cache, stack) -> dict[str, int]:
    """Enumerate ADCS CAs + templates and write BH-CE compatible JSON.

    Produces: ``CA.json``, ``CATemplate.json``, ``NTAuthCertificates.json``,
    ``ADCSFindings.json``.
    """
    os.makedirs(outdir, exist_ok=True)
    config_base = f"CN=Configuration,{base}"
    dc_sids = _dc_machine_sids(cache)

    # Fetch NTAuthCertificates FIRST, while the ADWS connection is fresh:
    # some DCs tear down the socket after a long template enumeration, and
    # a WS-Transfer Get afterwards fails with "connection reset by peer".
    ntauth_certs = _fetch_ntauth(client, base)

    cas = stack.enter_context(JsonSpool(outdir))
    for entry in _run_query(
        client, config_base, "(objectClass=pKIEnrollmentService)", _CA_ATTRS
    ):
        try:
            node = _make_ca_node(entry, cache, dc_sids)
        except Exception:
            _log.warning(
                "failed to build CA node for %r",
                _first(entry.attributes.get("distinguishedName") or []),
                exc_info=True,
            )
            continue
        cas.append(node)

    published_on = _build_published_map(cas)
    oid_group_links = _fetch_oid_group_links(client, base)

    templates = stack.enter_context(JsonSpool(outdir))
    for entry in _run_query(
        client, config_base, "(objectClass=pKICertificateTemplate)", _TEMPLATE_ATTRS
    ):
        try:
            node = _make_template_node(entry, cache, published_on, oid_group_links, dc_sids)
        except Exception:
            _log.warning(
                "failed to build template node for %r",
                _first(entry.attributes.get("distinguishedName") or []),
                exc_info=True,
            )
            continue
        templates.append(node)

    findings = stack.enter_context(JsonSpool(outdir))
    for ca in cas:
        for finding in _findings_summary([ca], []):
            findings.append(finding)
    for template in templates:
        for finding in _findings_summary([], [template]):
            findings.append(finding)

    # Strip operator-only / BH-incompatible keys before writing the BH files.
    # Neo4j node properties must be primitives or arrays-of-primitives: the
    # list-of-dict fields (``cacertificates_parsed``, ``ekus_detail``) break
    # ingest with ``Property values can only be of primitive types or arrays
    # thereof``, so they stay out of the BH payload. ``FindingsPrincipals``
    # is an operator-only decoration kept outside Properties.
    def _bh_props(props: dict, drop_keys: set[str]) -> dict:
        return {k: v for k, v in props.items() if k not in drop_keys}

    # Pre-build template-name -> {ObjectIdentifier, Type} index. BH-CE's
    # SharpHound v5 ingest creates PublishedTo (CertTemplate -> EnterpriseCA)
    # from the EnterpriseCA node's TOP-LEVEL ``EnabledCertTemplates`` field
    # (a list of TypedPrincipal), not from the ``Properties.certificatetemplates``
    # list -- without this the edges never materialise. Build the index from
    # the templates we just enumerated, keyed by upper-case name.
    template_by_name = {}
    for t in templates:
        tn = (t.get("Properties") or {}).get("name") or ""
        if tn:
            template_by_name[str(tn).upper()] = {
                "ObjectIdentifier": t.get("ObjectIdentifier"),
                "ObjectType": "CertTemplate",
            }

    def _enabled_cert_templates(ca):
        names = (ca.get("Properties") or {}).get("certificatetemplates") or []
        return [template_by_name[n] for n in names if n in template_by_name]

    bh_cas = stack.enter_context(JsonSpool(outdir))
    for c in cas:
        bh_cas.append(
            {
                **{
                    k: v
                    for k, v in c.items()
                    if k not in ("FindingsPrincipals", "Properties")
                },
                "Properties": _bh_props(c["Properties"], {"cacertificates_parsed"}),
                # Top-level fields BH-CE's PostADCS wiring reads directly:
                "EnabledCertTemplates": _enabled_cert_templates(c),
                # HostingComputer SID can be resolved via the DN lookup cache: the
                # cache is keyed by DN but we only have ``dnshostname``, which has
                # no DN form in the cache. Leave empty when unresolved -- BH will
                # fall back to the Cypher match on ``dnshostname`` during analysis.
                "HostingComputer": _resolve_hosting_computer(
                    cache, (c.get("Properties") or {}).get("dnshostname")
                ),
            }
        )
    bh_templates = stack.enter_context(JsonSpool(outdir))
    for t in templates:
        bh_templates.append(
            {
                **{
                    k: v
                    for k, v in t.items()
                    if k not in ("FindingsPrincipals", "Properties")
                },
                "Properties": _bh_props(t["Properties"], {"ekus_detail"}),
            }
        )

    # BloodHound CE's SharpHound v5 ingest expects specific ``meta.type``
    # values and rejects anything else with ``no valid meta tag found``.
    # The ADCS trio must be: enterprisecas / certtemplates / ntauthstores.
    for filename, meta_type, data in (
        ("CA.json", "enterprisecas", bh_cas),
        ("CATemplate.json", "certtemplates", bh_templates),
    ):
        _write_json(
            outdir,
            filename,
            data,
            meta={
                "count": len(data),
                "type": meta_type,
                "methods": 0,
                "version": 5,
            },
        )

    # BH CE expects a single NTAuthStore wrapper node, not raw per-cert dicts:
    # the required ``certthumbprints`` array feeds the TrustedForNTAuth
    # post-processing edge. Flatten the parsed trust-root certs into that
    # shape. ObjectIdentifier is a stable per-domain pseudo-GUID.
    ntauth_bh = _build_ntauth_store(ntauth_certs, cas, base)
    _write_json(
        outdir,
        "NTAuthCertificates.json",
        ntauth_bh,
        meta={
            "count": len(ntauth_bh),
            "type": "ntauthstores",
            "methods": 0,
            "version": 5,
        },
    )
    _write_json(
        outdir,
        "ADCSFindings.json",
        findings,
        meta={
            "count": len(findings),
            "type": "adcs_findings",
            "out_of_scope": _OUT_OF_SCOPE_ESC,
            "out_of_scope_reason": "requires non-LDAP channel (CA registry / RPC / HTTP enrollment endpoint)",
            "version": 1,
        },
    )

    counts = {
        "cas": len(cas),
        "templates": len(templates),
        "ntauth": len(ntauth_certs),
        "findings": len(findings),
    }
    _log.info("certdump written to %s: %s", outdir, counts)
    return counts


def certdump(client, base: str, outdir: str, cache) -> dict[str, int]:
    """Collect ADCS nodes into disk-backed spools, then publish complete files."""
    os.makedirs(outdir, exist_ok=True)
    with ExitStack() as stack:
        return _collect_certdump(client, base, outdir, cache, stack)
