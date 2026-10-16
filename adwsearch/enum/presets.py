# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""The 6 read-only enumeration presets.

Each preset is a small recipe on top of ``AdwsClient.search`` — same SOAP
WS-Enumeration path (ADWS on TCP 9389). No LDAP protocol / no ldap3.

Simple presets (``forest-level``, ``maq``, ``asrep``, ``spn``) run a single
search with a preset base/scope/filter/attrs and, optionally, decode one attribute
before yielding. ``writable`` iterates one or more partitions. ``dns-dump`` walks the
two AD-integrated DNS containers and decodes the binary ``dnsRecord`` blob into a
synthetic ``AdObject`` per record.

Portions of the ``forest-level`` decoding table and the ``dns-dump`` binary parser
were ported from bloodyAD — see NOTICE.
"""

import logging
from dataclasses import dataclass
from typing import Callable, Iterator

from adwsearch.enum.constants import (
    format_functional_level,
    format_sd_rights_effective,
)
from adwsearch.enum.dns_record import parse_dns_record
from adwsearch.soap.parser import AdObject
from adwsearch.soap.parser import AdwsSoapFault
from adwsearch.adws.errors import is_missing_object_fault
from adwsearch.dump.common import split_dn, rdn_value

_log = logging.getLogger(__name__)


def _numeric(value):
    """ADWS can encode integer attributes as decimal XML text."""
    if isinstance(value, str):
        try:
            return int(value, 10)
        except ValueError:
            pass
    return value


@dataclass
class Preset:
    name: str
    description: str
    run: Callable[..., Iterator[AdObject]]
    # For --dry-run summary; simple presets fill (base, scope, filter, attributes),
    # composite presets (writable, dns-dump) return a shape with "bases" instead.
    resolve: Callable[..., dict] | None = None


# --- forest-level ---------------------------------------------------------

_FOREST_LEVEL_ATTRS = ["msDS-Behavior-Version"]


def _forest_level_run(client, args) -> Iterator[AdObject]:
    # WS-Transfer Get -> 1 round-trip, with automatic fallback to
    # search(scope=base) if the DC does not expose WS-Transfer.
    #
    # Both paths return the full XML view of the object (Transfer by spec:
    # no attribute selection; search fallback via (objectClass=*) with no
    # projection). Trim client-side to the attribute the preset promises,
    # so the LDIF writer prints only msDS-Behavior-Version (decoded).
    entry = client.get(args.base)
    if entry is None:
        return
    vals = entry.attributes.get("msDS-Behavior-Version") or []
    trimmed = {
        "msDS-Behavior-Version": [
            format_functional_level(_numeric(v)) if isinstance(_numeric(v), int) else v for v in vals
        ],
    }
    # Preserve the server-synthesised distinguishedName (MS-ADDM 2.3.3.3)
    # so the LDIF writer still emits a `dn:` line; without it the output
    # would be a bare attribute value with no header.
    dn_vals = entry.attributes.get("distinguishedName")
    if dn_vals:
        trimmed["distinguishedName"] = dn_vals
    entry.attributes = trimmed
    yield entry


def _forest_level_resolve(args) -> dict:
    return {"base": args.base, "scope": "base",
            "filter": "(objectClass=*)", "attributes": _FOREST_LEVEL_ATTRS}


# --- maq ------------------------------------------------------------------

_MAQ_ATTRS = ["ms-DS-MachineAccountQuota"]


def _maq_run(client, args) -> Iterator[AdObject]:
    # WS-Transfer Get -> 1 round-trip, with automatic fallback to
    # search(scope=base) if the DC does not expose WS-Transfer.
    #
    # Same trimming rationale as forest-level: WS-Transfer returns the full
    # XML view with no selection, so the preset trims to the single attr it
    # promises instead of dumping the whole domain-root object.
    entry = client.get(args.base)
    if entry is None:
        return
    trimmed = {
        "ms-DS-MachineAccountQuota":
            entry.attributes.get("ms-DS-MachineAccountQuota") or [],
    }
    dn_vals = entry.attributes.get("distinguishedName")
    if dn_vals:
        trimmed["distinguishedName"] = dn_vals
    entry.attributes = trimmed
    yield entry


def _maq_resolve(args) -> dict:
    return {"base": args.base, "scope": "base",
            "filter": "(objectClass=*)", "attributes": _MAQ_ATTRS}


# --- asrep ----------------------------------------------------------------

_ASREP_FILTER = ("(&(samAccountType=805306368)"
                 "(userAccountControl:1.2.840.113556.1.4.803:=4194304))")
_ASREP_ATTRS = ["sAMAccountName", "userAccountControl"]


def _asrep_run(client, args) -> Iterator[AdObject]:
    yield from client.search(
        base=args.base, scope="sub", ldap_filter=_ASREP_FILTER,
        attributes=_ASREP_ATTRS,
        size_limit=args.sizelimit, page_size=args.page_size,
    )


def _asrep_resolve(args) -> dict:
    return {"base": args.base, "scope": "sub",
            "filter": _ASREP_FILTER, "attributes": _ASREP_ATTRS}


# --- spn ------------------------------------------------------------------

_SPN_FILTER_ANY = "(servicePrincipalName=*)"
_SPN_FILTER_ROASTABLE = (
    "(&(samAccountType=805306368)(servicePrincipalName=*)"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
)
_SPN_ATTRS_BASE = [
    "sAMAccountName", "servicePrincipalName", "objectClass",
    "userAccountControl", "adminCount",
]


def _spn_filter(args) -> str:
    spn_class = getattr(args, "spn_class", None)
    if not spn_class:
        return _SPN_FILTER_ANY
    return f"(servicePrincipalName={spn_class}/*)"


def _spn_attrs(args) -> list[str]:
    return list(_SPN_ATTRS_BASE)


def _spn_run(client, args) -> Iterator[AdObject]:
    yield from client.search(
        base=args.base, scope="sub", ldap_filter=_spn_filter(args),
        attributes=_spn_attrs(args),
        size_limit=args.sizelimit, page_size=args.page_size,
    )


def _spn_resolve(args) -> dict:
    return {"base": args.base, "scope": "sub",
            "filter": _spn_filter(args), "attributes": _spn_attrs(args)}


# --- kerberoastable ------------------------------------------------------
#
# Standalone preset: equivalent to the former
# ``--preset spn --spn-class kerberoastable``. Lifted out of ``spn`` so the
# attack-focused invocation is a single flag and discoverable in --help.
# Reuses the filter/attrs constants from spn's kerberoastable branch to
# keep the two outputs byte-identical.

_KERBEROASTABLE_ATTRS = [*_SPN_ATTRS_BASE, "msDS-SupportedEncryptionTypes"]


def _kerberoastable_run(client, args) -> Iterator[AdObject]:
    yield from client.search(
        base=args.base, scope="sub", ldap_filter=_SPN_FILTER_ROASTABLE,
        attributes=_KERBEROASTABLE_ATTRS,
        size_limit=args.sizelimit, page_size=args.page_size,
    )


def _kerberoastable_resolve(args) -> dict:
    return {"base": args.base, "scope": "sub",
            "filter": _SPN_FILTER_ROASTABLE,
            "attributes": _KERBEROASTABLE_ATTRS}


# --- writable -------------------------------------------------------------

_WRITABLE_ATTRS = ["distinguishedName",
                   "allowedAttributesEffective",
                   "sDRightsEffective",
                   "allowedChildClassesEffective"]
# distinguishedName is requested so the LDIF writer can emit a ``dn:``
# header: effective-rights blobs are often identical across many objects
# (schema class + inherited ACL -> same shape), so without a DN the output
# looks like duplicate blocks even when every objectReferenceProperty is
# unique. The DN gives the operator the human identifier they need.

_WRITABLE_OTYPE_FILTERS = {
    "any": "(objectClass=*)",
    "user": "(sAMAccountType=805306368)",
    "group": "(objectCategory=group)",
    "ou": "(|(objectClass=container)(objectClass=organizationalUnit))",
    "gpo": "(objectClass=groupPolicyContainer)",
}


def _writable_bases(args) -> list[str]:
    partition = args.writable_partition
    if partition == "domain":
        return [args.base]
    if partition == "config":
        return [f"CN=Configuration,{args.base}"]
    if partition == "schema":
        return [f"CN=Schema,CN=Configuration,{args.base}"]
    return [
        args.base,
        f"CN=Configuration,{args.base}",
        f"CN=Schema,CN=Configuration,{args.base}",
    ]


def _writable_run(client, args) -> Iterator[AdObject]:
    ldap_filter = _WRITABLE_OTYPE_FILTERS[args.writable_otype]
    for base in _writable_bases(args):
        for entry in client.search(
            base=base, scope="sub", ldap_filter=ldap_filter,
            attributes=_WRITABLE_ATTRS,
            size_limit=args.sizelimit, page_size=args.page_size,
        ):
            attrs = entry.attributes
            allowed_attrs = attrs.get("allowedAttributesEffective") or []
            allowed_children = attrs.get("allowedChildClassesEffective") or []
            sd_rights_vals = attrs.get("sDRightsEffective") or []
            sd_rights_int = _numeric(sd_rights_vals[0]) if sd_rights_vals else 0

            if not allowed_attrs and not allowed_children and not sd_rights_int:
                # Nothing writable on this object — skip.
                continue

            if sd_rights_vals:
                attrs["sDRightsEffective"] = [
                    format_sd_rights_effective(_numeric(v)) if isinstance(_numeric(v), int) else v
                    for v in sd_rights_vals
                ]
            yield entry


def _writable_resolve(args) -> dict:
    return {
        "bases": _writable_bases(args),
        "scope": "sub",
        "filter": _WRITABLE_OTYPE_FILTERS[args.writable_otype],
        "attributes": _WRITABLE_ATTRS,
    }


# --- dns-dump -------------------------------------------------------------

_DNS_DUMP_FILTER_NO_GLUE = (
    "(&(|(objectClass=dnsNode)(objectClass=dnsZone))"
    "(!(name=_gc.*))(!(name=_kerberos.*))(!(name=_kpasswd.*))"
    "(!(name=_ldap.*))(!(name=_msdcs))"
    "(!(name=@))(!(name=gc))"
    "(!(name=DomainDnsZones))(!(name=ForestDnsZones)))"
)
_DNS_DUMP_FILTER_WITH_GLUE = "(|(objectClass=dnsNode)(objectClass=dnsZone))"
_DNS_DUMP_ATTRS = ["dnsRecord", "name", "objectClass", "distinguishedName"]


def _dns_dump_bases(args) -> list[str]:
    """Both the modern and legacy AD-integrated DNS containers."""
    return [
        f"CN=MicrosoftDNS,DC=DomainDnsZones,{args.base}",
        f"CN=MicrosoftDNS,CN=System,{args.base}",
    ]


def _resolve_reverse_lookup(zone_name: str, node_name: str) -> str:
    """For .in-addr.arpa reverse zones, format the node as dotted-quad."""
    if not zone_name.lower().endswith(".in-addr.arpa"):
        return node_name
    prefix = zone_name[:-len(".in-addr.arpa")]
    return f"{node_name}.{prefix}" if prefix else node_name


def _stringify_dns_data(data) -> str:
    if isinstance(data, dict):
        return " ".join(f"{k}={v}" for k, v in data.items())
    return str(data)


def _yield_dns_records(entry: AdObject, zone_name: str,
                       include_zone_entry: bool) -> Iterator[AdObject]:
    name_vals = entry.attributes.get("name") or []
    node_name = str(name_vals[0]) if name_vals else ""
    display_name = _resolve_reverse_lookup(zone_name, node_name)

    records = entry.attributes.get("dnsRecord") or []
    if not records and include_zone_entry:
        # Hollow entry (list-children access only): expose the name at least.
        yield AdObject(object_class="dnsRecord",
                       attributes={"zone": [zone_name], "name": [display_name]})
        return

    for raw in records:
        if not isinstance(raw, (bytes, bytearray)):
            continue
        try:
            parsed = parse_dns_record(bytes(raw))
        except Exception as exc:
            # One corrupt dnsRecord blob must not abort the whole container
            # walk: log it and move on so the rest of the zone still dumps.
            _log.warning("skipping malformed dnsRecord under %r: %s",
                         display_name or zone_name, exc)
            continue
        yield AdObject(
            object_class="dnsRecord",
            attributes={
                "zone": [zone_name],
                "name": [display_name],
                "type": [str(parsed["type"])],
                "data": [_stringify_dns_data(parsed["data"])],
                "ttl": [str(parsed["ttl_seconds"])],
            },
        )


def _dns_dump_run(client, args) -> Iterator[AdObject]:
    ldap_filter = (_DNS_DUMP_FILTER_WITH_GLUE if args.dns_include_glue
                   else _DNS_DUMP_FILTER_NO_GLUE)
    for base in _dns_dump_bases(args):
        try:
            entries = client.search(
                base=base, scope="sub", ldap_filter=ldap_filter,
                attributes=_DNS_DUMP_ATTRS,
                size_limit=args.sizelimit, page_size=args.page_size,
            )
            base_rdns = split_dn(base)
            for entry in entries:
                dn_values = entry.attributes.get("distinguishedName") or []
                if not dn_values:
                    raise ValueError("DNS object has no distinguishedName; cannot resolve zone")
                rdns = split_dn(str(dn_values[0]))
                if ([r.casefold() for r in rdns[-len(base_rdns):]] !=
                        [r.casefold() for r in base_rdns] or len(rdns) <= len(base_rdns)):
                    raise ValueError("DNS object DN is outside the requested container")
                zone = rdn_value(rdns[-len(base_rdns) - 1])
                is_zone = entry.object_class.casefold() == "dnszone"
                yield from _yield_dns_records(entry, zone, include_zone_entry=is_zone)
        except AdwsSoapFault as exc:
            if not is_missing_object_fault(exc):
                raise


def _dns_dump_resolve(args) -> dict:
    return {
        "bases": _dns_dump_bases(args),
        "scope": "sub",
        "filter": (_DNS_DUMP_FILTER_WITH_GLUE if args.dns_include_glue
                   else _DNS_DUMP_FILTER_NO_GLUE),
        "attributes": _DNS_DUMP_ATTRS,
    }


# --- registry -------------------------------------------------------------

PRESETS: dict[str, Preset] = {
    "forest-level": Preset(
        name="forest-level",
        description="Read msDS-Behavior-Version on the domain NC root.",
        run=_forest_level_run,
        resolve=_forest_level_resolve,
    ),
    "maq": Preset(
        name="maq",
        description="Read ms-DS-MachineAccountQuota on the domain NC root.",
        run=_maq_run,
        resolve=_maq_resolve,
    ),
    "asrep": Preset(
        name="asrep",
        description="Enumerate users with DONT_REQ_PREAUTH set (AS-REP roastable).",
        run=_asrep_run,
        resolve=_asrep_resolve,
    ),
    "spn": Preset(
        name="spn",
        description=(
            "Enumerate objects with a servicePrincipalName. Use --spn-class NAME "
            "to filter by service class (MSSQLSvc, HTTP, ...). For "
            "kerberoastable targets use the dedicated --preset kerberoastable."
        ),
        run=_spn_run,
        resolve=_spn_resolve,
    ),
    "kerberoastable": Preset(
        name="kerberoastable",
        description=(
            "List enabled user accounts with SPNs and msDS-SupportedEncryptionTypes "
            "(account configuration, not a ticket enctype). Does not request "
            "roasting tickets or collect cracking hashes; JSON is not Hashcat input."
        ),
        run=_kerberoastable_run,
        resolve=_kerberoastable_resolve,
    ),
    "writable": Preset(
        name="writable",
        description="List objects the current user has effective write access on.",
        run=_writable_run,
        resolve=_writable_resolve,
    ),
    "dns-dump": Preset(
        name="dns-dump",
        description="Dump AD-integrated DNS records from both container locations.",
        run=_dns_dump_run,
        resolve=_dns_dump_resolve,
    ),
}
