# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Resolve explicit service principals without impacket's host/ prefix rewrite."""

import logging
import os
import re
import struct

from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import KerberosError

from adwsearch.auth.kerberos_tgs import request_service_ticket

from adwsearch.auth.credentials import Credentials


def resolve_spn(target_host: str, override: str | None) -> str:
    spn = override if override is not None else f"host/{target_host}"
    if not re.fullmatch(r"[^/@\s]+/[^/@\s]+(?:@[^/@\s]+)?", spn):
        raise ValueError("SPN must be service/host with optional @REALM")
    return spn


def ccache_path() -> str:
    value = os.environ.get("KRB5CCNAME", "")
    if not value:
        raise ValueError("--kerberos requires KRB5CCNAME")
    if value.startswith("FILE:"):
        value = value[5:]
    elif ":" in value and not (len(value) > 1 and value[1] == ":"):
        raise ValueError("unsupported KRB5CCNAME prefix; use FILE: or a file path")
    if not os.path.isfile(value):
        raise ValueError("KRB5CCNAME ccache file does not exist")
    return value


def _cache_material(credentials: Credentials, spn: str, policy="aes"):
    path = ccache_path()
    cache = CCache.loadFile(path)
    principal = cache.principal.prettyPrint().decode("utf-8")
    cache_user, cache_realm = principal.rsplit("@", 1)
    if credentials.username and credentials.username.casefold() != cache_user.casefold():
        raise ValueError("ccache principal does not match requested user")
    if credentials.domain and credentials.domain.casefold() != cache_realm.casefold():
        raise ValueError("ccache realm does not match requested domain")
    service, _, explicit_realm = spn.partition("@")
    realm = explicit_realm or cache_realm
    def exact(principal):
        # impacket getCredential(anySPN=False) still ignores realm/cache order.
        return next((entry for entry in cache.credentials
                     if entry["server"].prettyPrint().decode("utf-8").casefold()
                     == principal.casefold()), None)
    matches = [entry for entry in cache.credentials
               if entry["server"].prettyPrint().decode("utf-8").casefold()
               == f"{service}@{realm}".casefold()]
    ticket = next((entry for enctype in _allowed(policy) for entry in matches
                   if entry.toTGS(service)["cipher"].enctype == enctype),
                  matches[0] if matches else None)
    tgt = exact(f"krbtgt/{cache_realm}@{cache_realm}")
    if ticket is None and tgt is None:
        raise ValueError("ccache contains neither the exact service ticket for this realm nor a TGT")
    credentials.username = credentials.username or cache_user
    credentials.domain = credentials.domain or cache_realm
    return service, realm, ticket, tgt


def _allowed(policy):
    if policy not in ("aes", "rc4", "auto"):
        raise ValueError("Kerberos policy must be aes, rc4 or auto")
    return (23,) if policy == "rc4" else (18, 17)


def validate_ccache(credentials: Credentials, spn: str, policy="aes") -> None:
    """Local identity and session-key policy preflight, without any KDC I/O."""
    try:
        allowed = _allowed(policy)
        service, _, ticket, tgt = _cache_material(credentials, spn, policy)
        if ticket is not None:
            enctype = ticket.toTGS(service)["cipher"].enctype
            if enctype in allowed:
                return
        if tgt is None:
            raise ValueError("no compatible cached session key or TGT; use rc4 explicitly for a legacy-only cache")
    except (ValueError, KeyError, IndexError, AttributeError, struct.error) as exc:
        raise ValueError("ccache is invalid, mismatched or incompatible with the Kerberos policy") from exc


def load_service_ticket(credentials: Credentials, spn: str,
                        kdc_host: str | None, *, policy="aes", timeout=30) -> dict:
    allowed = _allowed(policy)
    service, realm, ticket, tgt = _cache_material(credentials, spn, policy)
    if ticket is not None:
        data = ticket.toTGS(service)
        if data["cipher"].enctype in allowed:
            return data
    if tgt is None:
        raise ValueError("no compatible cached session key or TGT for the Kerberos policy")
    def request(enctypes):
        return request_service_ticket(tgt.toTGT(), service, realm, kdc_host,
                                      enctypes=enctypes, timeout=timeout)
    try:
        return request(allowed)
    except KerberosError as exc:
        if policy != "auto" or exc.getErrorCode() != 14:
            raise
    logging.getLogger(__name__).warning(
        "Kerberos auto: KDC rejected AES enctypes; explicitly permitted legacy RC4 fallback")
    return request((23,))
