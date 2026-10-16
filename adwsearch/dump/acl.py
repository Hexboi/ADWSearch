# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Parse nTSecurityDescriptor bytes into BloodHound v5 Ace edges.

Clean-room reproduction of the ACL edge algorithm documented in the BloodHound
project. Uses ``impacket.ldap.ldaptypes.SR_SECURITY_DESCRIPTOR`` to walk the
MS-DTYP binary layout; the ACE-to-edge mapping is derived from Microsoft
schema documentation (well-known control-access rights + property-set GUIDs).

We emit a conservative subset of edges that cover the common attack paths:

    GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns,
    AllExtendedRights, AddMember, ForceChangePassword,
    GetChanges, GetChangesAll, ReadLAPSPassword

The ``Owns`` edge comes from ``OwnerSid`` (not the DACL). ``IsACLProtected`` is
the SE_DACL_PROTECTED bit of the SD Control field.
"""

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    SR_SECURITY_DESCRIPTOR,
)

from adwsearch.dump.labels import Label


GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
DS_WRITE_PROP = 0x00000020
DS_CONTROL_ACCESS = 0x00000100
DS_SELF = 0x00000008

ACE_TYPE_ACCESS_ALLOWED = 0x00
ACE_TYPE_ACCESS_ALLOWED_OBJECT = 0x05
ACE_INHERITED_FLAG = 0x10

SE_DACL_PROTECTED = 0x1000

ACE_OBJECT_TYPE_PRESENT = 0x01


_GUID_USER_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
_GUID_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
_GUID_DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
_GUID_DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
_GUID_DS_REPL_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"
_GUID_MS_MCS_ADMPWD_LAPS = "40483c32-6906-497e-a2bd-baba3fdb1b6f"
_GUID_MS_LAPS_PASSWORD = "8c4ce407-c37d-4c47-b1c0-0d9c45c49f19"
# AD CS extended-right GUIDs on pKICertificateTemplate / pKIEnrollmentService
# (Certify / Certipy / BloodHound-CE reference).
_GUID_PKI_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
_GUID_PKI_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"


def _guid_bytes_to_str(raw: bytes) -> str:
    if len(raw) != 16:
        return ""
    d1 = int.from_bytes(raw[0:4], "little")
    d2 = int.from_bytes(raw[4:6], "little")
    d3 = int.from_bytes(raw[6:8], "little")
    d4 = raw[8:10]
    d5 = raw[10:16]
    return (f"{d1:08x}-{d2:04x}-{d3:04x}-"
            f"{d4[0]:02x}{d4[1]:02x}-"
            f"{d5[0]:02x}{d5[1]:02x}{d5[2]:02x}{d5[3]:02x}{d5[4]:02x}{d5[5]:02x}")


def _principal_from_cache(sid_str: str, cache):
    label = cache.id_to_type.get(sid_str, Label.Base)
    return {"PrincipalSID": sid_str, "PrincipalType": label.value}


def _edge_from_mask_and_guid(mask: int, object_guid) -> str | None:
    if object_guid:
        guid = object_guid.lower()
        if (mask & DS_CONTROL_ACCESS) and guid == _GUID_USER_FORCE_CHANGE_PASSWORD:
            return "ForceChangePassword"
        if (mask & (DS_WRITE_PROP | DS_SELF)) and guid == _GUID_MEMBER:
            return "AddMember"
        if (mask & DS_CONTROL_ACCESS) and guid == _GUID_DS_REPL_GET_CHANGES:
            return "GetChanges"
        if (mask & DS_CONTROL_ACCESS) and guid == _GUID_DS_REPL_GET_CHANGES_ALL:
            return "GetChangesAll"
        if (mask & DS_CONTROL_ACCESS) and guid == _GUID_DS_REPL_GET_CHANGES_FILTERED:
            return "GetChangesInFilteredSet"
        if (mask & DS_CONTROL_ACCESS) and guid in (
                _GUID_MS_MCS_ADMPWD_LAPS, _GUID_MS_LAPS_PASSWORD):
            return "ReadLAPSPassword"
        if (mask & DS_CONTROL_ACCESS) and guid in (
                _GUID_PKI_ENROLL, _GUID_PKI_AUTOENROLL):
            # BloodHound CE accepts ``Enroll`` as a RightName kind but
            # rejects ``AutoEnroll`` with ``unknown kind AutoEnroll`` during
            # ingest. SharpHound v5 collapses both grants into a single
            # ``Enroll`` ACE because they're abuse-equivalent for ADCS
            # exploit chains; mirror that here.
            return "Enroll"
        return None
    if mask & GENERIC_ALL:
        return "GenericAll"
    if mask & WRITE_DAC:
        return "WriteDacl"
    if mask & WRITE_OWNER:
        return "WriteOwner"
    if mask & GENERIC_WRITE:
        return "GenericWrite"
    if mask & DS_CONTROL_ACCESS:
        return "AllExtendedRights"
    return None


def parse_aces(nt_sd_bytes, cache) -> tuple[list[dict], bool]:
    """Parse an nTSecurityDescriptor blob; return ``(aces, is_acl_protected)``.

    Empty/invalid input yields ``([], False)`` — the DC may hide the SD for
    some objects even with SD_FLAGS, and that's not an error to surface.
    """
    if not nt_sd_bytes or not isinstance(nt_sd_bytes, (bytes, bytearray)):
        return [], False

    try:
        sd = SR_SECURITY_DESCRIPTOR(data=bytes(nt_sd_bytes))
    except Exception:
        return [], False

    aces: list[dict] = []

    try:
        owner = sd["OwnerSid"].formatCanonical()
    except Exception:
        owner = None
    if owner:
        aces.append({**_principal_from_cache(owner, cache),
                     "RightName": "Owns", "IsInherited": False})

    is_protected = bool(sd["Control"] & SE_DACL_PROTECTED)

    dacl = sd["Dacl"]
    if dacl is None or not hasattr(dacl, "aces"):
        return aces, is_protected

    for ace in dacl.aces:
        ace_type = ace["AceType"]
        if ace_type not in (ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_ALLOWED_OBJECT):
            continue

        ace_body = ace["Ace"]
        is_inherited = bool(ace["AceFlags"] & ACE_INHERITED_FLAG)

        if isinstance(ace_body, ACCESS_ALLOWED_ACE):
            mask = ace_body["Mask"]["Mask"]
            try:
                trustee = ace_body["Sid"].formatCanonical()
            except Exception:
                continue
            edge = _edge_from_mask_and_guid(mask, None)
            if edge:
                aces.append({**_principal_from_cache(trustee, cache),
                             "RightName": edge, "IsInherited": is_inherited})
            continue

        if isinstance(ace_body, ACCESS_ALLOWED_OBJECT_ACE):
            mask = ace_body["Mask"]["Mask"]
            try:
                trustee = ace_body["Sid"].formatCanonical()
            except Exception:
                continue
            flags = ace_body["Flags"]
            obj_guid = None
            if flags & ACE_OBJECT_TYPE_PRESENT:
                raw = ace_body["ObjectType"]
                if isinstance(raw, (bytes, bytearray)) and len(raw) == 16:
                    obj_guid = _guid_bytes_to_str(bytes(raw))
            edge = _edge_from_mask_and_guid(mask, obj_guid)
            if edge:
                aces.append({**_principal_from_cache(trustee, cache),
                             "RightName": edge, "IsInherited": is_inherited})

    return aces, is_protected
