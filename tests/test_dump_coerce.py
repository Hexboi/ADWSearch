# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Shared SID/GUID/FILETIME coercions used by every dump mode."""

import uuid

from impacket.ldap.ldaptypes import LDAP_SID

from adwsearch.dump._coerce import (
    filetime_to_unix,
    guid_to_canonical,
    sid_to_canonical,
)


def _sid_bytes(canonical: str) -> bytes:
    sid = LDAP_SID()
    sid.fromCanonical(canonical)
    return sid.getData()


def test_sid_from_bytes_roundtrips_canonical():
    assert sid_to_canonical(_sid_bytes("S-1-5-21-1-2-3-500")) == "S-1-5-21-1-2-3-500"


def test_sid_passthrough_string():
    assert sid_to_canonical("S-1-1-0") == "S-1-1-0"


def test_sid_none_and_bogus_bytes():
    assert sid_to_canonical(None) is None
    assert sid_to_canonical(b"\x00") is None  # too short for a valid SID
    assert sid_to_canonical(42) is None       # unsupported type


def test_guid_from_bytes_little_endian_upper_case():
    u = uuid.UUID("deadbeef-dead-beef-dead-beefdeadbeef")
    assert guid_to_canonical(u.bytes_le) == str(u).upper()


def test_guid_passthrough_uuid_and_string():
    u = uuid.uuid4()
    assert guid_to_canonical(u) == str(u).upper()
    assert guid_to_canonical("deadbeef-dead-beef-dead-beefdeadbeef") == \
        "DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF"


def test_guid_none_and_bad_input():
    assert guid_to_canonical(None) is None
    assert guid_to_canonical(b"\x00\x01") is None  # wrong byte length
    assert guid_to_canonical(3.14) is None


def test_filetime_zero_and_sentinel_are_never():
    assert filetime_to_unix(0) == -1
    assert filetime_to_unix(0x7FFFFFFFFFFFFFFF) == -1


def test_filetime_known_value():
    # 2001-09-09 01:46:40 UTC == 1 000 000 000 unix seconds.
    # FILETIME = NT_EPOCH_DELTA + 1e9 * 1e7 = 116444736000000000 + 1e16.
    assert filetime_to_unix(126_444_736_000_000_000) == 1_000_000_000


def test_filetime_rejects_garbage_input():
    assert filetime_to_unix("not a number") == -1
    assert filetime_to_unix(None) == -1
