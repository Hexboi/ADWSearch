# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Shared coercions for the ``dump`` subpackage.

``builder``, ``bhdump`` and ``certdump`` each need the same three primitives:

* ``objectSid`` bytes/str → canonical ``S-1-...``
* ``objectGUID`` bytes/str/UUID → canonical upper-case GUID string
* Windows FILETIME → Unix epoch seconds (with ``-1`` for "never")

They used to be reimplemented in each module with minor cosmetic drift. This
module is the single source of truth; call sites that need a different default
on failure (e.g. ``""`` instead of ``None``) adapt at the call site.
"""

import uuid

from impacket.ldap.ldaptypes import LDAP_SID

# NT epoch (1601-01-01) -> Unix epoch (1970-01-01) in 100-nanosecond units.
_FILETIME_EPOCH_TO_UNIX_100NS = 116444736000000000
# ``0`` and ``0x7FFFFFFFFFFFFFFF`` are both documented as "no value / never".
_FILETIME_NEVER = {0, 0x7FFFFFFFFFFFFFFF}


def sid_to_canonical(raw) -> str | None:
    """Return the canonical ``S-1-...`` form of an ``objectSid`` value, or ``None``.

    Accepts raw bytes (the common NBF-decoded case) and already-decoded strings.
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        try:
            return LDAP_SID(bytes(raw)).formatCanonical()
        except Exception:
            return None
    return None


def guid_to_canonical(raw) -> str | None:
    """Return the upper-case string form of an ``objectGUID``, or ``None``."""
    if raw is None:
        return None
    if isinstance(raw, uuid.UUID):
        return str(raw).upper()
    if isinstance(raw, str):
        return raw.upper()
    if isinstance(raw, (bytes, bytearray)):
        try:
            return str(uuid.UUID(bytes_le=bytes(raw))).upper()
        except ValueError:
            return None
    return None


def filetime_to_unix(value) -> int:
    """Convert a Windows FILETIME (int or castable) to Unix epoch seconds.

    Returns ``-1`` for unparseable input or the two documented "never"
    sentinels (BloodHound's convention).
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        return -1
    if v in _FILETIME_NEVER:
        return -1
    return (v - _FILETIME_EPOCH_TO_UNIX_100NS) // 10_000_000
