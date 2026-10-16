# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""ACL parser (Phase 11): nTSecurityDescriptor -> BloodHound Aces."""

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    ACCESS_MASK,
    ACE,
    ACL,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
)

from adwsearch.dump import Cache
from adwsearch.dump.acl import (
    ACE_OBJECT_TYPE_PRESENT,
    DS_CONTROL_ACCESS,
    GENERIC_ALL,
    SE_DACL_PROTECTED,
    parse_aces,
)
from adwsearch.dump.labels import Label


_GUID_USER_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"


def _sid(canonical: str) -> LDAP_SID:
    s = LDAP_SID()
    s.fromCanonical(canonical)
    return s


def _build_sd(owner_canonical: str,
              plain_aces=(),
              object_aces=(),
              control: int = 0x8004) -> bytes:
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = control
    sd["OffsetOwner"] = 0
    sd["OffsetGroup"] = 0
    sd["OffsetSacl"] = 0
    sd["OffsetDacl"] = 0
    sd["OwnerSid"] = _sid(owner_canonical)
    sd["GroupSid"] = _sid(owner_canonical)
    sd["Sacl"] = b""

    acl = ACL()
    acl["AclRevision"] = 2
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []

    for mask, trustee, flags in plain_aces:
        body = ACCESS_ALLOWED_ACE()
        m = ACCESS_MASK()
        m["Mask"] = mask
        body["Mask"] = m
        body["Sid"] = _sid(trustee)
        ace = ACE()
        ace["AceType"] = 0x00
        ace["AceFlags"] = flags
        ace["Ace"] = body
        acl.aces.append(ace)

    for mask, trustee, flags, object_guid_le in object_aces:
        body = ACCESS_ALLOWED_OBJECT_ACE()
        m = ACCESS_MASK()
        m["Mask"] = mask
        body["Mask"] = m
        body["Flags"] = ACE_OBJECT_TYPE_PRESENT
        body["ObjectType"] = object_guid_le
        body["InheritedObjectType"] = b""
        body["Sid"] = _sid(trustee)
        ace = ACE()
        ace["AceType"] = 0x05
        ace["AceFlags"] = flags
        ace["Ace"] = body
        acl.aces.append(ace)

    sd["Dacl"] = acl
    return sd.getData()


def _guid_str_to_le_bytes(guid_str: str) -> bytes:
    parts = guid_str.split("-")
    d1 = int(parts[0], 16).to_bytes(4, "little")
    d2 = int(parts[1], 16).to_bytes(2, "little")
    d3 = int(parts[2], 16).to_bytes(2, "little")
    d4 = bytes.fromhex(parts[3])
    d5 = bytes.fromhex(parts[4])
    return d1 + d2 + d3 + d4 + d5


def test_parse_aces_empty_returns_no_edges():
    aces, protected = parse_aces(b"", Cache())
    assert aces == []
    assert protected is False


def test_parse_aces_owner_emits_owns_edge():
    sd_bytes = _build_sd(owner_canonical="S-1-5-32-544")
    aces, _ = parse_aces(sd_bytes, Cache())
    owns = [a for a in aces if a["RightName"] == "Owns"]
    assert len(owns) == 1
    assert owns[0]["PrincipalSID"] == "S-1-5-32-544"


def test_parse_aces_generic_all_maps_to_edge():
    sd_bytes = _build_sd(
        owner_canonical="S-1-5-32-544",
        plain_aces=[(GENERIC_ALL, "S-1-5-21-1-2-3-1001", 0)],
    )
    cache = Cache()
    cache.id_to_type = {"S-1-5-21-1-2-3-1001": Label.User}
    aces, _ = parse_aces(sd_bytes, cache)
    generic_all = [a for a in aces if a["RightName"] == "GenericAll"]
    assert len(generic_all) == 1
    assert generic_all[0]["PrincipalSID"] == "S-1-5-21-1-2-3-1001"
    assert generic_all[0]["PrincipalType"] == "User"
    assert generic_all[0]["IsInherited"] is False


def test_parse_aces_force_change_password_via_object_ace():
    guid_le = _guid_str_to_le_bytes(_GUID_USER_FORCE_CHANGE_PASSWORD)
    sd_bytes = _build_sd(
        owner_canonical="S-1-5-32-544",
        object_aces=[(DS_CONTROL_ACCESS, "S-1-5-21-1-2-3-1002", 0, guid_le)],
    )
    aces, _ = parse_aces(sd_bytes, Cache())
    fcp = [a for a in aces if a["RightName"] == "ForceChangePassword"]
    assert len(fcp) == 1
    assert fcp[0]["PrincipalSID"] == "S-1-5-21-1-2-3-1002"


def test_parse_aces_marks_acl_protected():
    sd_bytes = _build_sd(
        owner_canonical="S-1-5-32-544",
        control=0x8004 | SE_DACL_PROTECTED,
    )
    _, protected = parse_aces(sd_bytes, Cache())
    assert protected is True
