# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""NBF dictionary handling.

Dictionary string ids share a single space: even ids come from the static dictionary
(MC-NBFS), odd ids from the per-connection dynamic dictionary (MC-NBFSE), where the n-th
dynamic string (0-based) is assigned id ``2 * n + 1``.

``STATIC_DICTIONARY`` is the full MC-NBFS table (even ids 0x000..0x3CC), generated from
the official specification (see ``nbfs_dictionary.py``).
"""

from typing import Dict, List

from .nbfs_dictionary import STATIC_DICTIONARY

__all__ = ["STATIC_DICTIONARY", "merge"]


def merge(static: Dict[int, str], dynamic: List[str]) -> Dict[int, str]:
    """Return a single ``{id: string}`` map from a static table and dynamic strings."""
    merged = dict(static)
    for index, value in enumerate(dynamic):
        merged[2 * index + 1] = value
    return merged
