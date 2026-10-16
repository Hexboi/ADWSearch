# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""showstats+ (Phase 14) — autosplit candidate detection."""

import io

from adwsearch.dump import Cache, showstats
from adwsearch.dump.labels import Label


def test_showstats_flags_autosplit_candidates_above_threshold():
    cache = Cache()
    cache.value_to_id = {
        "cn=alice,dc=x": "S-1-5-21-1-1-1-1001",
        "cn=amy,dc=x": "S-1-5-21-1-1-1-1002",
        "cn=arthur,dc=x": "S-1-5-21-1-1-1-1003",
        "cn=bob,dc=x": "S-1-5-21-1-1-1-1004",
    }
    cache.id_to_type = {
        "S-1-5-21-1-1-1-1001": Label.User,
        "S-1-5-21-1-1-1-1002": Label.User,
        "S-1-5-21-1-1-1-1003": Label.User,
        "S-1-5-21-1-1-1-1004": Label.User,
    }

    buf = io.StringIO()
    stats = showstats(cache, stream=buf, split_threshold=2)

    assert stats["total_objects"] == 4
    assert stats["by_leading_char"]["a"] == 3
    assert stats["by_leading_char"]["b"] == 1
    assert stats["autosplit_candidates"] == ["a"]

    out = buf.getvalue()
    assert "autosplit_candidates" in out
    assert "bhdump --autosplit" in out


def test_showstats_omits_autosplit_section_when_under_threshold():
    cache = Cache()
    cache.value_to_id = {"cn=alice,dc=x": "S-1-5-21-1-1-1-1001"}
    cache.id_to_type = {"S-1-5-21-1-1-1-1001": Label.User}

    buf = io.StringIO()
    stats = showstats(cache, stream=buf, split_threshold=1000)

    assert stats["autosplit_candidates"] == []
    assert "autosplit_candidates" not in buf.getvalue()
