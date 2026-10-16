# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""BloodHound v5 mass dump (Phase 10) via ADWS.

One WS-Enumeration sweep of the domain NC pulls every object with the full BH
attribute set + ``nTSecurityDescriptor`` (via SD_FLAGS LDAP control 801). Each
object is dispatched by its LocalName (objectClass) into a per-kind builder
that produces a BloodHound v5 node. Seven JSON files are written to ``outdir``:

    <header>_outputUsers.json      meta.type = "users"
    <header>_outputComputers.json  meta.type = "computers"
    <header>_outputGroups.json     meta.type = "groups"
    <header>_outputOUs.json        meta.type = "ous"
    <header>_outputGPOs.json       meta.type = "gpos"
    <header>_outputContainers.json meta.type = "containers"
    <header>_outputDomains.json    meta.type = "domains"

Aces are left empty in Phase 10; Phase 11 populates them from the
nTSecurityDescriptor bytes already returned by the same query.
"""

import logging
import os

from adwsearch.dump._coerce import (
    filetime_to_unix as _filetime_to_unix,
    guid_to_canonical as _guid_str,
    sid_to_canonical as _sid_str,
)
from adwsearch.dump.acl import parse_aces
from adwsearch.dump.labels import Label, class_to_label
from adwsearch.dump.common import (
    SD_FLAGS_OID, SD_FLAGS_OWNER_GROUP_DACL as SD_FLAGS_ALL,
    first_value as _first, datetime_to_unix as _datetime_to_unix,
    domain_from_dn as _domain_from_dn,
)
from adwsearch.dump.spool import JsonBucketSpool

_log = logging.getLogger(__name__)


BH_ATTRS = [
    "name", "sAMAccountName", "cn", "dNSHostName",
    "objectSid", "objectGUID", "primaryGroupID", "distinguishedName",
    "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "description",
    "operatingSystem", "sIDHistory", "nTSecurityDescriptor", "userAccountControl",
    "whenCreated", "lastLogon", "displayName", "title", "homeDirectory",
    "userPassword", "unixUserPassword", "scriptPath", "adminCount", "member",
    "msDS-Behavior-Version", "msDS-AllowedToDelegateTo",
    "gPCFileSysPath", "gPLink", "gPOptions",
    # ``ms-Mcs-AdmPwdExpirationTime`` was the legacy-LAPS attribute: it does not
    # exist in the AD schema unless legacy LAPS has been installed, and asking
    # for it makes ADWS fault the whole Enumerate with InvalidPropertyFault.
    # ms-LAPS attributes (msLAPS-*) are modern; we don't request them explicitly
    # here either, as they too may be absent on vanilla DCs.
    "trustAttributes", "trustDirection", "securityIdentifier",
]


_UAC_ACCOUNTDISABLE = 0x0002
_UAC_PASSWD_NOTREQD = 0x0020
_UAC_DONT_EXPIRE_PWD = 0x10000
_UAC_TRUSTED_FOR_DELEGATION = 0x80000
_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
_UAC_DONT_REQ_PREAUTH = 0x400000
_UAC_SERVER_TRUST_ACCOUNT = 0x2000

def _domain_sid_from_object_sid(sid: str) -> str:
    if not sid:
        return ""
    idx = sid.rfind("-")
    return sid[:idx] if idx > 0 else sid


def _typed_principal(cache, dn: str) -> dict | None:
    found = cache.lookup_by_dn(dn)
    if not found:
        return None
    obj_id, label = found
    return {"ObjectIdentifier": obj_id, "ObjectType": label.value}


def _uac(entry) -> int:
    v = _first(entry.attributes.get("userAccountControl") or [])
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _sid_history(entry) -> list[str]:
    return [s for s in (_sid_str(v) for v in (entry.attributes.get("sIDHistory") or [])) if s]


def _extract_aces(entry, cache) -> tuple[list[dict], bool]:
    """Read nTSecurityDescriptor from an entry and parse it into BH Aces."""
    raw = _first(entry.attributes.get("nTSecurityDescriptor") or [])
    return parse_aces(raw, cache)


def _common_properties(entry, sid: str | None, guid: str | None) -> dict:
    attrs = entry.attributes
    dn = _first(attrs.get("distinguishedName") or []) or ""
    name = _first(attrs.get("name") or []) or _first(attrs.get("cn") or []) or ""
    domain = _domain_from_dn(dn)

    return {
        "domain": domain,
        "name": (name + "@" + domain).upper() if name and domain else (name or dn).upper(),
        "distinguishedname": dn.upper(),
        "domainsid": _domain_sid_from_object_sid(sid) if sid else "",
        "highvalue": False,
        "description": _first(attrs.get("description") or []),
        "whencreated": _datetime_to_unix(_first(attrs.get("whenCreated") or [])),
    }


def _make_user_node(entry, cache) -> dict:
    aces, is_protected = _extract_aces(entry, cache)
    sid = _sid_str(_first(entry.attributes.get("objectSid") or []))
    guid = _guid_str(_first(entry.attributes.get("objectGUID") or []))
    uac = _uac(entry)
    props = _common_properties(entry, sid, guid)
    attrs = entry.attributes

    props.update({
        "sensitive": False,
        "dontreqpreauth": bool(uac & _UAC_DONT_REQ_PREAUTH),
        "passwordnotreqd": bool(uac & _UAC_PASSWD_NOTREQD),
        "unconstraineddelegation": bool(uac & _UAC_TRUSTED_FOR_DELEGATION),
        "pwdneverexpires": bool(uac & _UAC_DONT_EXPIRE_PWD),
        "enabled": not (uac & _UAC_ACCOUNTDISABLE),
        "trustedtoauth": bool(uac & _UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
        "lastlogon": _filetime_to_unix(_first(attrs.get("lastLogon") or [])),
        "lastlogontimestamp": _filetime_to_unix(_first(attrs.get("lastLogonTimestamp") or [])),
        "pwdlastset": _filetime_to_unix(_first(attrs.get("pwdLastSet") or [])),
        "serviceprincipalnames": [str(s) for s in (attrs.get("servicePrincipalName") or [])],
        "hasspn": bool(attrs.get("servicePrincipalName") or []),
        "displayname": _first(attrs.get("displayName") or []),
        "title": _first(attrs.get("title") or []),
        "homedirectory": _first(attrs.get("homeDirectory") or []),
        "userpassword": _first(attrs.get("userPassword") or []),
        "unixpassword": _first(attrs.get("unixUserPassword") or []),
        "logonscript": _first(attrs.get("scriptPath") or []),
        "admincount": bool(int(_first(attrs.get("adminCount") or [0]) or 0)),
        "sidhistory": _sid_history(entry),
        "samaccountname": _first(attrs.get("sAMAccountName") or []),
    })

    primary_group_rid = _first(entry.attributes.get("primaryGroupID") or [])
    primary_group_sid = ""
    if sid and primary_group_rid:
        primary_group_sid = f"{_domain_sid_from_object_sid(sid)}-{primary_group_rid}"

    allowed = [d for d in (str(v) for v in (attrs.get("msDS-AllowedToDelegateTo") or [])) if d]

    return {
        "ObjectIdentifier": sid or "",
        "Properties": props,
        "Aces": aces,
        "IsACLProtected": is_protected,
        "IsDeleted": False,
        "PrimaryGroupSID": primary_group_sid,
        "HasSIDHistory": _sid_history(entry),
        "AllowedToDelegate": allowed,
        "AllowedToAct": [],
        "SPNTargets": [],
    }


def _make_computer_node(entry, cache) -> dict:
    aces, is_protected = _extract_aces(entry, cache)
    sid = _sid_str(_first(entry.attributes.get("objectSid") or []))
    guid = _guid_str(_first(entry.attributes.get("objectGUID") or []))
    uac = _uac(entry)
    props = _common_properties(entry, sid, guid)
    attrs = entry.attributes

    props.update({
        "operatingsystem": _first(attrs.get("operatingSystem") or []),
        "haslaps": bool(attrs.get("ms-Mcs-AdmPwdExpirationTime") or []),
        "enabled": not (uac & _UAC_ACCOUNTDISABLE),
        "unconstraineddelegation": bool(uac & _UAC_TRUSTED_FOR_DELEGATION),
        "trustedtoauth": bool(uac & _UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
        "isdc": bool(uac & _UAC_SERVER_TRUST_ACCOUNT),
        "lastlogon": _filetime_to_unix(_first(attrs.get("lastLogon") or [])),
        "lastlogontimestamp": _filetime_to_unix(_first(attrs.get("lastLogonTimestamp") or [])),
        "pwdlastset": _filetime_to_unix(_first(attrs.get("pwdLastSet") or [])),
        "serviceprincipalnames": [str(s) for s in (attrs.get("servicePrincipalName") or [])],
        "sidhistory": _sid_history(entry),
        "samaccountname": _first(attrs.get("sAMAccountName") or []),
        "dnshostname": _first(attrs.get("dNSHostName") or []),
    })

    primary_group_rid = _first(entry.attributes.get("primaryGroupID") or [])
    primary_group_sid = ""
    if sid and primary_group_rid:
        primary_group_sid = f"{_domain_sid_from_object_sid(sid)}-{primary_group_rid}"

    allowed = [d for d in (str(v) for v in (attrs.get("msDS-AllowedToDelegateTo") or [])) if d]

    return {
        "ObjectIdentifier": sid or "",
        "Properties": props,
        "Aces": aces,
        "IsACLProtected": is_protected,
        "IsDeleted": False,
        "PrimaryGroupSID": primary_group_sid,
        "AllowedToDelegate": allowed,
        "AllowedToAct": [],
        "HasSIDHistory": _sid_history(entry),
        "Sessions": {"Results": [], "Collected": False, "FailureReason": None},
        "PrivilegedSessions": {"Results": [], "Collected": False, "FailureReason": None},
        "RegistrySessions": {"Results": [], "Collected": False, "FailureReason": None},
        "LocalGroups": [],
        "UserRights": [],
        "DcomUsers": {"Results": [], "Collected": False, "FailureReason": None},
        "RdpUsers": {"Results": [], "Collected": False, "FailureReason": None},
        "PSRemoteUsers": {"Results": [], "Collected": False, "FailureReason": None},
        "Status": None,
    }


def _make_group_node(entry, cache) -> dict:
    aces, is_protected = _extract_aces(entry, cache)
    sid = _sid_str(_first(entry.attributes.get("objectSid") or []))
    guid = _guid_str(_first(entry.attributes.get("objectGUID") or []))
    props = _common_properties(entry, sid, guid)
    attrs = entry.attributes

    props.update({
        "admincount": bool(int(_first(attrs.get("adminCount") or [0]) or 0)),
        "samaccountname": _first(attrs.get("sAMAccountName") or []),
    })

    members = []
    for member_dn in (attrs.get("member") or []):
        if not isinstance(member_dn, str):
            continue
        tp = _typed_principal(cache, member_dn)
        if tp:
            members.append(tp)

    return {
        "ObjectIdentifier": sid or "",
        "Properties": props,
        "Aces": aces,
        "IsACLProtected": is_protected,
        "IsDeleted": False,
        "Members": members,
    }


def _make_ou_node(entry, cache) -> dict:
    aces, is_protected = _extract_aces(entry, cache)
    guid = _guid_str(_first(entry.attributes.get("objectGUID") or []))
    props = _common_properties(entry, None, guid)
    attrs = entry.attributes

    props["blocksinheritance"] = False
    dn = _first(attrs.get("distinguishedName") or []) or ""

    return {
        "ObjectIdentifier": guid or "",
        "Properties": props,
        "Aces": aces,
        "IsACLProtected": is_protected,
        "IsDeleted": False,
        "ChildObjects": _child_objects(cache, dn),
        "Links": _gplink_to_links(cache, _first(attrs.get("gPLink") or [])),
        "GPOChanges": {"LocalAdmins": [], "RemoteDesktopUsers": [],
                       "DcomUsers": [], "PSRemoteUsers": [], "AffectedComputers": []},
    }


def _make_gpo_node(entry, cache) -> dict:
    aces, is_protected = _extract_aces(entry, cache)
    guid = _guid_str(_first(entry.attributes.get("objectGUID") or []))
    props = _common_properties(entry, None, guid)
    attrs = entry.attributes
    props["gpcpath"] = (_first(attrs.get("gPCFileSysPath") or []) or "").upper()
    return {
        "ObjectIdentifier": guid or "",
        "Properties": props,
        "Aces": aces,
        "IsACLProtected": is_protected,
        "IsDeleted": False,
    }


def _make_container_node(entry, cache) -> dict:
    aces, is_protected = _extract_aces(entry, cache)
    guid = _guid_str(_first(entry.attributes.get("objectGUID") or []))
    props = _common_properties(entry, None, guid)
    dn = _first(entry.attributes.get("distinguishedName") or []) or ""
    return {
        "ObjectIdentifier": guid or "",
        "Properties": props,
        "Aces": aces,
        "IsACLProtected": is_protected,
        "IsDeleted": False,
        "ChildObjects": _child_objects(cache, dn),
    }


def _make_domain_node(entry, cache) -> dict:
    aces, is_protected = _extract_aces(entry, cache)
    sid = _sid_str(_first(entry.attributes.get("objectSid") or []))
    guid = _guid_str(_first(entry.attributes.get("objectGUID") or []))
    props = _common_properties(entry, sid, guid)
    attrs = entry.attributes
    props["functionallevel"] = str(_first(attrs.get("msDS-Behavior-Version") or []) or "")
    dn = _first(attrs.get("distinguishedName") or []) or ""
    props["name"] = _domain_from_dn(dn)
    # The Domain object's own SID IS the domain SID (no RID to strip).
    # ``_common_properties`` runs the generic "last chunk off" transform which
    # on this one object type truncates the SID by one authority, breaking
    # BH's PostADCS BuildCache (CertTemplateDomainLinkage matches templates
    # to Domain via ``domainsid``). Set it back to the full SID here.
    if sid:
        props["domainsid"] = sid

    return {
        "ObjectIdentifier": sid or guid or "",
        "Properties": props,
        "Aces": aces,
        "IsACLProtected": is_protected,
        "IsDeleted": False,
        "ChildObjects": _child_objects(cache, dn),
        "Trusts": [],
        "Links": _gplink_to_links(cache, _first(attrs.get("gPLink") or [])),
        "GPOChanges": {"LocalAdmins": [], "RemoteDesktopUsers": [],
                       "DcomUsers": [], "PSRemoteUsers": [], "AffectedComputers": []},
    }


def _child_objects(cache, parent_dn: str) -> list[dict]:
    """Direct children of ``parent_dn`` as typed principals, using the cache.

    O(1) per parent via ``Cache.children_index``; the index itself is built
    once per cache on first access.
    """
    if not parent_dn:
        return []
    return cache.children_index().get(parent_dn.lower(), [])


def _gplink_to_links(cache, gplink) -> list[dict]:
    """Parse ``gPLink`` (``[LDAP://cn={GUID},...;N]...``) into BH Links."""
    if not gplink or not isinstance(gplink, str):
        return []
    links = []
    for seg in gplink.split("]"):
        seg = seg.strip()
        if not seg.startswith("["):
            continue
        body = seg[1:]
        if ";" not in body:
            continue
        raw_dn, flags = body.rsplit(";", 1)
        if raw_dn.lower().startswith("ldap://"):
            raw_dn = raw_dn[7:]
        tp = _typed_principal(cache, raw_dn)
        if not tp:
            continue
        try:
            enforced = bool(int(flags) & 2)
        except ValueError:
            enforced = False
        links.append({"IsEnforced": enforced, "GUID": tp["ObjectIdentifier"]})
    return links


_BUILDERS = {
    Label.User: ("users", _make_user_node),
    Label.Computer: ("computers", _make_computer_node),
    Label.Group: ("groups", _make_group_node),
    Label.OU: ("ous", _make_ou_node),
    Label.GPO: ("gpos", _make_gpo_node),
    Label.Container: ("containers", _make_container_node),
    Label.Domain: ("domains", _make_domain_node),
}

def _run_one_query(client, base: str, ldap_filter: str, cache, buckets):
    """Execute one bhdump-scoped query and return the buckets."""
    for entry in client.search(
        base=base, scope="sub", ldap_filter=ldap_filter,
        attributes=BH_ATTRS, size_limit=0, page_size=1000,
        ldap_controls=[(SD_FLAGS_OID, SD_FLAGS_ALL)],
    ):
        label = class_to_label(entry.object_class)
        builder_pair = _BUILDERS.get(label)
        if builder_pair is None:
            continue
        kind, builder = builder_pair
        try:
            node = builder(entry, cache)
        except Exception:
            _log.warning("failed to build %s node for %r", kind,
                         _first(entry.attributes.get("distinguishedName") or []),
                         exc_info=True)
            continue
        buckets.append(kind, node)
    return buckets


# SOAPHound autosplit: iterate one query per leading name letter, plus one
# "nonchars" query that excludes every alphanumeric prefix. This lets large
# domains sidestep DC-side paging limits on the single (!soaphound=*) query.
#
# We anchor on ``name`` rather than ``cn``: ``cn`` is populated only for
# objects whose RDN uses ``CN=`` (users, computers, groups, containers,
# GPOs). OUs use ``OU=`` and the domain partition uses ``DC=``, so a
# ``(cn=X*)`` filter silently drops every OU and the domain object itself.
# ``name`` is a synthetic AD attribute that carries the RDN value for every
# object class, so the slices stay collectively exhaustive.
_AUTOSPLIT_LETTERS = "abcdefghijklmnopqrstuvwxyz0123456789"


def _autosplit_filters():
    """Yield ``(header, ldap_filter)`` tuples covering every name prefix + nonchars."""
    for c in _AUTOSPLIT_LETTERS:
        yield (c, f"(name={c}*)")
    nonchar_excludes = "".join(f"(!(name={c}*))" for c in _AUTOSPLIT_LETTERS)
    yield ("nonchars", f"(&(name=*){nonchar_excludes})")


def bhdump(client, base: str, outdir: str, cache, header: str = "full",
           autosplit: bool = False) -> dict[str, int]:
    """Run the BloodHound-style dump. Returns per-kind counts.

    When ``autosplit`` is True, iterate one query per leading CN letter (plus
    a nonchars catch-all) instead of a single ``(!soaphound=*)`` query. Each
    slice writes its own ``<letter>_output<Kind>.json`` files so operators can
    process a large domain in bounded chunks. Counts returned aggregate all
    slices per kind.
    """
    os.makedirs(outdir, exist_ok=True)

    if not autosplit:
        with JsonBucketSpool(outdir) as buckets:
            _run_one_query(client, base, "(!soaphound=*)", cache, buckets)
            counts = buckets.publish(header)
        _log.info("bhdump written to %s: %s", outdir, counts)
        return counts

    total_counts: dict[str, int] = {kind: 0 for kind, _ in _BUILDERS.values()}
    for slice_header, ldap_filter in _autosplit_filters():
        with JsonBucketSpool(outdir) as buckets:
            _run_one_query(client, base, ldap_filter, cache, buckets)
            if not buckets:
                continue
            slice_counts = buckets.publish(slice_header)
        for kind, n in slice_counts.items():
            total_counts[kind] += n
    _log.info("bhdump (autosplit) written to %s: %s", outdir, total_counts)
    return total_counts
