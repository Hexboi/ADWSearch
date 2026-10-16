# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Attribute decoders (Phase 4a): turn already-typed NBF values (bytes / int / datetime
/ UUID) into human-readable strings for LDIF and JSON output. ``raw=True`` disables the
per-attribute decoders so raw values pass through — bytes are base64-encoded.
"""

import base64
import datetime as _dt
import uuid


from adwsearch.attributes.decode import (
    decode_attributes,
    decode_filetime,
    decode_sid,
    decode_uac,
)


# --- individual decoders ---------------------------------------------------

def test_decode_sid_builtin_administrators():
    sid_bytes = bytes.fromhex("01020000000000052000000020020000")
    assert decode_sid(sid_bytes) == "S-1-5-32-544"


def test_decode_sid_domain_admin_500():
    sid_bytes = bytes.fromhex(
        "01" "05" "000000000005"
        "15000000"
        "01010101" "02020202" "03030303"
        "f4010000"
    )
    assert decode_sid(sid_bytes) == "S-1-5-21-16843009-33686018-50529027-500"


def test_decode_uac_normal_account_dont_expire():
    # NORMAL_ACCOUNT (0x200) | DONT_EXPIRE_PASSWORD (0x10000) = 0x10200
    out = decode_uac(0x10200)
    assert "NORMAL_ACCOUNT" in out
    assert "DONT_EXPIRE_PASSWORD" in out
    # Preserves the raw value for round-tripping.
    assert "0x10200" in out or "66048" in out


def test_decode_uac_no_flags():
    out = decode_uac(0)
    assert "0" in out


def test_decode_uac_accepts_string_value():
    # The WS-Transfer Get path and preset outputs surface userAccountControl
    # as a decimal string ("4260352"); the decoder must coerce rather than
    # crash with ``TypeError: unsupported operand type(s) for &: 'str' and 'int'``.
    out = decode_uac("4260352")
    assert "NORMAL_ACCOUNT" in out
    assert "DONT_EXPIRE_PASSWORD" in out
    assert "DONT_REQ_PREAUTH" in out


def test_decode_filetime_accepts_string_value():
    assert decode_filetime("0") == "never"
    assert decode_filetime("116444736000000000").startswith("1970-01-01T00:00:00")


def test_decode_filetime_epoch_returns_iso_datetime():
    # FILETIME for 1970-01-01 00:00:00 UTC = 116444736000000000
    ft = 116444736000000000
    out = decode_filetime(ft)
    assert out.startswith("1970-01-01T00:00:00")


def test_decode_filetime_zero_is_never():
    assert decode_filetime(0) == "never"


def test_decode_filetime_int64_max_is_never():
    assert decode_filetime(0x7FFFFFFFFFFFFFFF) == "never"


# --- decode_attributes -----------------------------------------------------

def _sid_bytes():
    return bytes.fromhex("01020000000000052000000020020000")


def test_decode_attributes_applies_known_decoders():
    guid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    attrs = {
        "objectSid": [_sid_bytes()],
        "objectGUID": [guid],
        "userAccountControl": [0x200],
        "pwdLastSet": [116444736000000000],
        "sAMAccountName": ["alice"],
    }
    out = decode_attributes(attrs)

    assert out["objectSid"] == ["S-1-5-32-544"]
    assert out["objectGUID"] == [str(guid)]
    assert "NORMAL_ACCOUNT" in out["userAccountControl"][0]
    assert out["pwdLastSet"][0].startswith("1970-01-01T00:00:00")
    assert out["sAMAccountName"] == ["alice"]


def test_decode_attributes_encodes_unknown_bytes_as_base64():
    payload = b"\x00\x01\x02\xff\xfe"
    attrs = {"nTSecurityDescriptor": [payload]}
    out = decode_attributes(attrs)
    assert out["nTSecurityDescriptor"] == [base64.b64encode(payload).decode("ascii")]


def test_decode_attributes_encodes_datetime_iso():
    ts = _dt.datetime(2024, 6, 15, 12, 30, 45, tzinfo=_dt.timezone.utc)
    attrs = {"whenCreated": [ts]}
    out = decode_attributes(attrs)
    assert out["whenCreated"][0].startswith("2024-06-15T12:30:45")


def test_decode_attributes_raw_mode_skips_decoders_but_still_base64():
    attrs = {
        "objectSid": [_sid_bytes()],
        "userAccountControl": [0x200],
    }
    out = decode_attributes(attrs, raw=True)
    # SID left as base64 of the raw bytes (LDIF-safe).
    assert out["objectSid"] == [base64.b64encode(_sid_bytes()).decode("ascii")]
    # UAC left as its int-string.
    assert out["userAccountControl"] == ["512"]


def test_decode_attributes_falls_back_when_decoder_raises():
    """A malformed SID must not abort the whole entry — fall back to raw base64."""
    import base64
    corrupt = b"\xff\xff"  # too short for a valid SID → LDAP_SID will raise
    attrs = {
        "objectSid": [corrupt],
        "sAMAccountName": ["alice"],
    }
    out = decode_attributes(attrs)
    # sAMAccountName untouched:
    assert out["sAMAccountName"] == ["alice"]
    # objectSid falls back to base64 of the raw bytes (marker for downstream ::):
    assert out["objectSid"] == [base64.b64encode(corrupt).decode("ascii")]


def test_decode_attributes_leaves_multi_valued_lists_intact():
    attrs = {"memberOf": ["CN=a,DC=x", "CN=b,DC=x"]}
    out = decode_attributes(attrs)
    assert out["memberOf"] == ["CN=a,DC=x", "CN=b,DC=x"]
