# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Massive-dump modes (SOAPHound-style) built on top of :class:`AdwsClient`.

Phase 9 exposes the SID/GUID <-> DN cache (:func:`build_cache`) and its
offline stats (:func:`showstats`); later phases will add BloodHound v5 node
processors, ACL edge computation, and ADCS certdump on top of the same cache.
"""

from adwsearch.dump.acl import parse_aces
from adwsearch.dump.bhdump import bhdump
from adwsearch.dump.builder import build_cache
from adwsearch.dump.cache import Cache
from adwsearch.dump.certdump import certdump
from adwsearch.dump.labels import Label, class_to_label
from adwsearch.dump.showstats import showstats
from adwsearch.dump.well_known_sids import WELL_KNOWN_SIDS

__all__ = [
    "Cache",
    "Label",
    "WELL_KNOWN_SIDS",
    "bhdump",
    "build_cache",
    "certdump",
    "class_to_label",
    "parse_aces",
    "showstats",
]
