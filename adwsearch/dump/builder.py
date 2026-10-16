# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Populate a :class:`Cache` from a single ADWS enumeration sweep.

One WS-Enumeration call retrieves every object under ``base`` with just three
attributes: ``objectSid``, ``objectGUID``, ``distinguishedName``. Small enough
to fit comfortably in memory even for very large forests; sufficient to answer
every DN-to-identifier lookup that later dump phases will need.

The LDAP filter ``(!soaphound=*)`` is the SOAPHound trick: a negation on an
attribute that no AD object exposes matches everything — ADWS does not accept
an empty filter, so this is the shortest "select all" form. Reproducing the
filter is not a derivative work of SOAPHound; it is a documented API pattern.
"""

import logging

from adwsearch.dump._coerce import guid_to_canonical, sid_to_canonical
from adwsearch.dump.cache import Cache
from adwsearch.dump.labels import Label, class_to_label
from adwsearch.dump.well_known_sids import WELL_KNOWN_SIDS

_log = logging.getLogger(__name__)


_CACHE_ATTRS = ["objectSid", "objectGUID", "distinguishedName"]

# Only these object kinds are worth caching when they have no SID (containers
# that anchor the tree hierarchy — needed by BH edge computation).
_GUID_FALLBACK_LABELS = frozenset({Label.Domain, Label.OU, Label.GPO, Label.Container})


def _first(values):
    return values[0] if values else None


# SID / GUID coercion is centralised in adwsearch.dump._coerce; local aliases
# keep the (private) call-site names stable.
_sid_to_string = sid_to_canonical
_guid_to_string = guid_to_canonical


def build_cache(client, base: str) -> Cache:
    """Enumerate ``base`` (subtree) once and return a populated :class:`Cache`.

    ``client`` is an :class:`AdwsClient` (or any object with a ``search`` method
    matching its signature); we invoke it with the SOAPHound "match-all" filter
    and a minimal attribute set.
    """
    cache = Cache()
    for entry in client.search(
        base=base, scope="sub", ldap_filter="(!soaphound=*)",
        attributes=_CACHE_ATTRS, size_limit=0, page_size=1000,
    ):
        attrs = entry.attributes
        dn = _first(attrs.get("distinguishedName") or [])
        if not isinstance(dn, str) or not dn:
            continue

        label = class_to_label(entry.object_class)

        sid = _sid_to_string(_first(attrs.get("objectSid") or []))
        if sid:
            cache.value_to_id[dn.lower()] = sid
            # Well-known SIDs win over the objectClass-derived label — a
            # BUILTIN\Administrators computed from `class="group"` and one
            # from S-1-5-32-544 should look identical downstream.
            cache.id_to_type[sid] = WELL_KNOWN_SIDS.get(sid, label)
            continue

        # No SID — only worth caching if it's a container-shaped node BH cares about.
        if label not in _GUID_FALLBACK_LABELS:
            continue
        guid = _guid_to_string(_first(attrs.get("objectGUID") or []))
        if not guid:
            continue
        cache.value_to_id[dn.lower()] = guid
        cache.id_to_type[guid] = label

    _log.info("cache built: %d entries", len(cache.value_to_id))
    return cache
