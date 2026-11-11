# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""ADCS flag + EKU decoder unit tests."""

import pytest

from adwsearch.dump.adcs_flags import (
    CERTIFICATE_NAME_FLAG,
    ENROLLMENT_FLAG,
    PRIVATE_KEY_FLAG,
    _as_u32,
    decode_eku,
    decode_flag,
    eku_contains,
    eku_grants_authentication,
)


def test_as_u32_handles_signed_name_flag():
    # ENROLLEE_SUPPLIES_SUBJECT (0x1) | SUBJECT_REQUIRE_DIRECTORY_PATH (0x80000000)
    # arrives from the NBF decoder as -2147483647 (signed 32-bit).
    assert _as_u32(-2147483647) == 0x80000001
    assert _as_u32(0) == 0
    assert _as_u32("notanumber") == 0


def test_decode_enrollment_flag_nosec_pending():
    out = decode_flag(ENROLLMENT_FLAG, 0x80002)
    assert "NO_SECURITY_EXTENSION" in out
    assert "PEND_ALL_REQUESTS" in out
    assert "AUTO_ENROLLMENT" not in out


def test_decode_name_flag_signed_wire_value():
    out = decode_flag(CERTIFICATE_NAME_FLAG, -2147483647)
    assert "ENROLLEE_SUPPLIES_SUBJECT" in out
    assert "SUBJECT_REQUIRE_DIRECTORY_PATH" in out


NAME_FLAGS_MS_CRTD_2_28 = [
    (0x00000001, 'ENROLLEE_SUPPLIES_SUBJECT'),
    (0x00000008, 'OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME'),
    (0x00010000, 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME'),
    (0x00400000, 'SUBJECT_ALT_REQUIRE_DOMAIN_DNS'),
    (0x00800000, 'SUBJECT_ALT_REQUIRE_SPN'),
    (0x01000000, 'SUBJECT_ALT_REQUIRE_DIRECTORY_GUID'),
    (0x02000000, 'SUBJECT_ALT_REQUIRE_UPN'),
    (0x04000000, 'SUBJECT_ALT_REQUIRE_EMAIL'),
    (0x08000000, 'SUBJECT_ALT_REQUIRE_DNS'),
    (0x10000000, 'SUBJECT_REQUIRE_DNS_AS_CN'),
    (0x20000000, 'SUBJECT_REQUIRE_EMAIL'),
    (0x40000000, 'SUBJECT_REQUIRE_COMMON_NAME'),
    (0x80000000, 'SUBJECT_REQUIRE_DIRECTORY_PATH'),
]


@pytest.mark.parametrize('bit,name', NAME_FLAGS_MS_CRTD_2_28)
def test_name_flag_matches_ms_crtd_2_28(bit, name):
    assert decode_flag(CERTIFICATE_NAME_FLAG, bit) == [name]


def test_unassigned_name_flag_is_not_decoded_as_a_subject_requirement():
    assert decode_flag(CERTIFICATE_NAME_FLAG, 0x80 | 0x100 | 0x200) == []


def test_decode_private_key_flag_exportable():
    out = decode_flag(PRIVATE_KEY_FLAG, 0x10)
    assert "EXPORTABLE_KEY" in out


def test_decode_eku_names_and_auth_marker():
    ekus = decode_eku(["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.4",
                       "1.3.6.1.4.1.311.20.2.1"])
    names = {e["name"] for e in ekus}
    assert "Client Authentication" in names
    assert "Secure Email" in names
    assert "Certificate Request Agent" in names
    assert sum(1 for e in ekus if e["allows_authentication"]) == 1


def test_decode_eku_unknown_oid_passthrough():
    out = decode_eku(["1.9.9.9.9"])
    assert out == [{"oid": "1.9.9.9.9", "name": "1.9.9.9.9",
                    "allows_authentication": False}]


def test_eku_grants_authentication_empty_is_true():
    assert eku_grants_authentication([]) is True


def test_eku_grants_authentication_server_only_is_false():
    ekus = decode_eku(["1.3.6.1.5.5.7.3.1"])
    assert eku_grants_authentication(ekus) is False


def test_eku_contains_locator():
    ekus = decode_eku(["2.5.29.37.0"])
    assert eku_contains(ekus, "2.5.29.37.0")
    assert not eku_contains(ekus, "1.3.6.1.5.5.7.3.2")
