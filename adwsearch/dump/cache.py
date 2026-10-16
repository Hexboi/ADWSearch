# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""In-memory + on-disk cache of DN -> SID/GUID and SID/GUID -> Label.

This is the pillar of the SOAPHound-style dump: once a single sweep of the
directory has populated both dictionaries, every later phase (BH nodes, ACL
edge resolution, PKI) can resolve DN references (`member`, `gPLink`,
`msDS-AllowedToDelegateTo`, DACL trustees) in constant time, without another
ADWS round-trip.

The serialised format ``{"ValueToIdCache": ..., "IdToTypeCache": ...}`` is the
same keys used by SOAPHound so an operator can share the cache between the two
tools. This is format interop, not code copy.
"""

import json
from dataclasses import dataclass, field

from adwsearch.dump.labels import Label
from adwsearch.output.atomic import atomic_text_file
from adwsearch.dump.common import split_dn


@dataclass
class Cache:
    # DN.lower() -> SID (preferred) or objectGUID (fallback for OU/GPO/Container/Domain
    # objects that have no SID). Lower-cased because AD DNs are case-insensitive.
    value_to_id: dict[str, str] = field(default_factory=dict)
    # SID_or_GUID -> Label. Stored as Label enum in memory; JSON stores the .value string.
    id_to_type: dict[str, Label] = field(default_factory=dict)
    # Lazy index parent_dn.lower() -> list of typed-principal dicts for the
    # direct children. Built on first access by ``children_index()``. Not
    # serialised; a freshly deserialised Cache rebuilds it on demand.
    _children_index: dict[str, list[dict]] | None = field(
        default=None, init=False, repr=False, compare=False)

    def serialize(self, path: str) -> None:
        payload = {
            "ValueToIdCache": self.value_to_id,
            "IdToTypeCache": {k: v.value for k, v in self.id_to_type.items()},
        }
        with atomic_text_file(path) as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)

    @classmethod
    def deserialize(cls, path: str) -> "Cache":
        with open(path, "r", encoding="utf-8") as stream:
            payload = json.load(stream)
        if (not isinstance(payload, dict) or
                not all(isinstance(payload.get(k), dict)
                        for k in ("ValueToIdCache", "IdToTypeCache"))):
            raise ValueError("invalid cache schema")
        if not all(isinstance(k, str) and isinstance(v, str)
                   for mapping in payload.values() if isinstance(mapping, dict)
                   for k, v in mapping.items()):
            raise ValueError("invalid cache entry")
        value_to_id = {k.lower(): v for k, v in payload.get("ValueToIdCache", {}).items()}
        id_to_type = {k: Label(v) for k, v in payload.get("IdToTypeCache", {}).items()}
        return cls(value_to_id=value_to_id, id_to_type=id_to_type)

    def lookup_by_dn(self, dn: str) -> tuple[str, Label] | None:
        """Resolve a DN to ``(id, label)``. Case-insensitive on the DN.

        Returns ``None`` if the DN is not in the cache -- callers decide whether
        that means "external principal" or "cache is stale".
        """
        obj_id = self.value_to_id.get(dn.lower())
        if obj_id is None:
            return None
        label = self.id_to_type.get(obj_id, Label.Base)
        return obj_id, label

    def children_index(self) -> dict[str, list[dict]]:
        """Return a lazily-built ``parent_dn.lower() -> [child principals]`` index.

        Each child is ``{"ObjectIdentifier": id, "ObjectType": label.value}``,
        the same shape ``bhdump._child_objects`` emits. The parent key is
        "everything after the first comma" of each DN; this covers every
        well-formed AD DN, including RDNs containing escaped commas.

        Built once per ``Cache`` instance; callers must not mutate the result.
        """
        if self._children_index is None:
            index: dict[str, list[dict]] = {}
            for dn_lc, obj_id in self.value_to_id.items():
                rdns = split_dn(dn_lc)
                if len(rdns) < 2:
                    continue
                parent_lc = ",".join(rdns[1:])
                label = self.id_to_type.get(obj_id, Label.Base)
                index.setdefault(parent_lc, []).append(
                    {"ObjectIdentifier": obj_id, "ObjectType": label.value})
            self._children_index = index
        return self._children_index
