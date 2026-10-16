# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""ADCS bitmask + EKU decoders (MS-WCCE / MS-CRTD).

Offline decoders used by :mod:`adwsearch.dump.certdump` to turn the raw
integer attributes shipped on ``pKICertificateTemplate`` objects into
BloodHound-CE-compatible boolean properties plus the ESCx classifier.

Bitmask values are from [MS-WCCE] 3.2.1.4.3.1 (``msPKI-Enrollment-Flag``,
``msPKI-Certificate-Name-Flag``, ``msPKI-Private-Key-Flag``). EKU OID -> name
mapping is the subset relevant to ADCS attack paths (Certify / Certipy
conventions).
"""


# [MS-WCCE] 3.2.1.4.3.1.2 msPKI-Enrollment-Flag
ENROLLMENT_FLAG = {
    0x00000001: "INCLUDE_SYMMETRIC_ALGORITHMS",
    0x00000002: "PEND_ALL_REQUESTS",  # manager approval
    0x00000004: "PUBLISH_TO_KRA_CONTAINER",
    0x00000008: "PUBLISH_TO_DS",
    0x00000010: "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
    0x00000020: "AUTO_ENROLLMENT",
    0x00000040: "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
    0x00000100: "USER_INTERACTION_REQUIRED",
    0x00000200: "ADD_TEMPLATE_NAME",
    0x00000400: "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
    0x00000800: "ALLOW_ENROLL_ON_BEHALF_OF",
    0x00001000: "ADD_OCSP_NOCHECK",
    0x00002000: "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
    0x00004000: "NOREVOCATIONINFOINISSUEDCERTS",
    0x00008000: "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
    0x00010000: "ALLOW_PREVIOUS_APPROVAL_KEYBASED_RENEWAL_VALIDATION",
    0x00020000: "ISSUANCE_POLICIES_FROM_REQUEST",
    0x00040000: "SKIP_AUTO_RENEWAL",
    0x00080000: "NO_SECURITY_EXTENSION",  # ESC9
}

# [MS-WCCE] 3.2.1.4.3.1.3 msPKI-Certificate-Name-Flag. The on-wire value is
# a signed 32-bit int; use ``_as_u32`` before bit testing.
CERTIFICATE_NAME_FLAG = {
    0x00000001: "ENROLLEE_SUPPLIES_SUBJECT",  # ESC1 core
    0x00000008: "SUBJECT_REQUIRE_DIRECTORY_PATH",
    0x00000080: "SUBJECT_REQUIRE_COMMON_NAME",
    0x00000100: "SUBJECT_REQUIRE_EMAIL",
    0x00000200: "SUBJECT_REQUIRE_DNS",
    0x00010000: "OLD_CERT_SUPPLIES_SUBJECT",
    0x00400000: "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",  # ESC1 full
    0x02000000: "SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
    0x04000000: "SUBJECT_ALT_REQUIRE_SPN",
    0x08000000: "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
    0x10000000: "SUBJECT_ALT_REQUIRE_UPN",
    0x20000000: "SUBJECT_ALT_REQUIRE_EMAIL",
    0x40000000: "SUBJECT_ALT_REQUIRE_DNS",
    0x80000000: "SUBJECT_REQUIRE_DNS_AS_CN",
}

# [MS-WCCE] 3.2.1.4.3.1.4 msPKI-Private-Key-Flag.
PRIVATE_KEY_FLAG = {
    0x00000001: "REQUIRE_PRIVATE_KEY_ARCHIVAL",
    0x00000010: "EXPORTABLE_KEY",
    0x00000020: "STRONG_KEY_PROTECTION_REQUIRED",
    0x00000040: "REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM",
    0x00000080: "REQUIRE_SAME_KEY_RENEWAL",
    0x00000100: "USE_LEGACY_PROVIDER",
    0x00000200: "ATTEST_NONE",
    0x00000400: "ATTEST_REQUIRED",
    0x00000800: "ATTEST_PREFERRED",
    0x00001000: "ATTESTATION_WITHOUT_POLICY",
    0x00002000: "EK_VALIDATE_CERT",
    0x00004000: "EK_VALIDATE_KEY",
    0x00200000: "HELLO_LOGON_KEY",
}

# EKU OIDs relevant to ADCS attack paths (Certify/Certipy's working set).
EKU_NAMES = {
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",  # ESC3
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "2.5.29.37.0": "Any Purpose",  # ESC2
}

# EKUs that let a certificate authenticate as the subject. An empty EKU list
# is treated as auth-capable too (an EKU-less cert is accepted by the KDC).
AUTH_EKU_OIDS = frozenset({
    "1.3.6.1.5.5.7.3.2",         # Client Authentication
    "1.3.6.1.5.2.3.4",           # PKINIT Client Authentication
    "1.3.6.1.4.1.311.20.2.2",    # Smart Card Logon
    "2.5.29.37.0",               # Any Purpose
})

CERTIFICATE_REQUEST_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"
ANY_PURPOSE_OID = "2.5.29.37.0"


def _as_u32(value) -> int:
    """Return ``value`` as an unsigned 32-bit int, tolerating signed inputs.

    ``msPKI-Certificate-Name-Flag`` has the sign bit set in the common
    ``ENROLLEE_SUPPLIES_SUBJECT`` / ``SUBJECT_REQUIRE_DNS_AS_CN`` combinations;
    the NBF decoder yields a signed int that would miss every bit above
    0x40000000 without this normalisation.
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 0
    return v & 0xFFFFFFFF


def decode_flag(mapping: dict[int, str], value) -> list[str]:
    """Return the names of every bit set in ``value`` per ``mapping``."""
    bits = _as_u32(value)
    return [name for bit, name in mapping.items() if bits & bit]


def decode_eku(oids) -> list[dict]:
    """Resolve a list of OID strings to ``[{oid, name, allows_authentication}]``."""
    out: list[dict] = []
    for raw in oids or []:
        oid = str(raw).strip()
        if not oid:
            continue
        out.append({
            "oid": oid,
            "name": EKU_NAMES.get(oid, oid),
            "allows_authentication": oid in AUTH_EKU_OIDS,
        })
    return out


def eku_grants_authentication(ekus: list[dict]) -> bool:
    """``True`` if the EKU list lets the cert authenticate (incl. empty = any)."""
    if not ekus:
        return True
    return any(e["allows_authentication"] for e in ekus)


def eku_contains(ekus: list[dict], oid: str) -> bool:
    return any(e["oid"] == oid for e in ekus)
