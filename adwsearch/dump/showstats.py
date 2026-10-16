# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Human-readable stats over a :class:`Cache` — the ``--dump showstats`` action.

Purely offline: no ADWS, no auth. Reads the cache the operator built earlier
with ``--dump buildcache`` and prints total counts, per-Label breakdown, and
the distribution of DNs by their first CN character (which is the input signal
for the future ``autosplit`` mode described in the roadmap plan).
"""

import sys

from adwsearch.dump.cache import Cache


def _leading_char(dn: str) -> str:
    """Return the first character of the leftmost ``CN=`` (or ``OU=`` etc.).

    Falls back to ``'?'`` for degenerate DNs. Digits collapse to ``'0-9'`` so
    the histogram stays readable.
    """
    for chunk in dn.split(","):
        eq = chunk.find("=")
        if eq == -1:
            continue
        value = chunk[eq + 1:].strip()
        if not value:
            continue
        first = value[0].lower()
        return "0-9" if first.isdigit() else first
    return "?"


def showstats(cache: Cache, stream=None, split_threshold: int = 1000) -> dict:
    """Compute and print stats. Returns the same dict for programmatic callers.

    ``split_threshold`` (default 1000): if any leading-char bucket exceeds this,
    it is flagged as an autosplit candidate — useful before running
    ``--dump bhdump --autosplit`` on a large domain.
    """
    if stream is None:
        stream = sys.stdout

    by_label: dict[str, int] = {}
    for label in cache.id_to_type.values():
        by_label[label.value] = by_label.get(label.value, 0) + 1

    by_leading_char: dict[str, int] = {}
    for dn in cache.value_to_id:
        c = _leading_char(dn)
        by_leading_char[c] = by_leading_char.get(c, 0) + 1

    autosplit_candidates = sorted(
        char for char, n in by_leading_char.items() if n > split_threshold)

    stats = {
        "total_objects": len(cache.value_to_id),
        "by_label": by_label,
        "by_leading_char": by_leading_char,
        "autosplit_candidates": autosplit_candidates,
        "split_threshold": split_threshold,
    }

    print(f"total_objects: {stats['total_objects']}", file=stream)
    print("by_label:", file=stream)
    for label in sorted(stats["by_label"]):
        print(f"  {label}: {stats['by_label'][label]}", file=stream)
    print("by_leading_char:", file=stream)
    for char in sorted(stats["by_leading_char"]):
        print(f"  {char}: {stats['by_leading_char'][char]}", file=stream)
    if autosplit_candidates:
        print(
            f"autosplit_candidates (over {split_threshold} objects): "
            f"{' '.join(autosplit_candidates)}",
            file=stream)
        print("  -> consider running: --dump bhdump --autosplit", file=stream)

    return stats
