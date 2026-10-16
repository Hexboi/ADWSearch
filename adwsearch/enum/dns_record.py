# SPDX-License-Identifier: MPL-2.0 AND MIT
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)
# Upstream portions: Copyright (c) 2022 CravateRouge, MIT License.
# MPL-2.0 covers ADWSearch additions; see NOTICE.

"""dnsRecord binary parser ([MS-DNSP] section 2.3.2.2).

Ported from bloodyAD (https://github.com/CravateRouge/bloodyAD),
Copyright (c) 2022 CravateRouge — MIT License. See NOTICE.
bloodyAD credits @dirkjanm and adidnsdump for the original design.

This module reuses ``impacket.structure.Structure`` (already a project dependency)
instead of re-bundling bloodyAD's Structure copy.

Public API:
    parse_dns_record(raw: bytes) -> dict[str, Any]
        Keys: ``type`` (str for known RRTYPEs or int otherwise),
              ``data`` (str for simple types, dict for MX/SRV/SOA),
              ``ttl_seconds`` (int).
"""

import ipaddress

from impacket.structure import Structure


# [MS-DNSP] 2.2.2.1.1 (subset).
DNS_RECORD_TYPE: dict[str, int] = {
    "A": 0x1,
    "NS": 0x2,
    "CNAME": 0x5,
    "SOA": 0x6,
    "PTR": 0xC,
    "MX": 0xF,
    "TXT": 0x10,
    "AAAA": 0x1C,
    "SRV": 0x21,
}
_DNS_TYPE_BY_CODE = {v: k for k, v in DNS_RECORD_TYPE.items()}


class _DnsRecord(Structure):
    """dnsRecord — [MS-DNSP] 2.3.2.2."""
    structure = (
        ("DataLength", "<H-Data"),
        ("Type", "<H"),
        ("Version", "B=5"),
        ("Rank", "B"),
        ("Flags", "<H=0"),
        ("Serial", "<I"),
        ("TtlSeconds", ">I"),
        ("Reserved", "<I=0"),
        ("TimeStamp", "<I=0"),
        ("Data", ":"),
    )


class _RecordA(Structure):
    structure = (("address", "!I"),)

    def to_canonical(self) -> str:
        return str(ipaddress.IPv4Address(self["address"]))


class _RecordAAAA(Structure):
    structure = (("ipv6Address", "!16s"),)

    def to_canonical(self) -> str:
        return str(ipaddress.IPv6Address(self["ipv6Address"]))


class _CountName(Structure):
    """DNS_COUNT_NAME — [MS-DNSP] 2.2.2.2.2. Length-prefixed label stream."""
    structure = (("Length", "B-RawName"), ("LabelCount", "B"), ("RawName", ":"))

    def to_canonical(self) -> str:
        ind = 0
        labels = []
        raw = self["RawName"]
        for _ in range(self["LabelCount"]):
            nextlen = raw[ind]
            labels.append(raw[ind + 1: ind + 1 + nextlen].decode("utf-8"))
            ind += nextlen + 1
        return ".".join(labels)


class _RecordNodeName(Structure):
    """Used for CNAME / NS / PTR."""
    structure = (("nameNode", ":", _CountName),)

    def to_canonical(self) -> str:
        return self["nameNode"].to_canonical()


class _RecordMx(Structure):
    structure = (("wPreference", ">H"), ("nameExchange", ":", _CountName))

    def to_canonical(self) -> dict:
        return {
            "preference": self["wPreference"],
            "name": self["nameExchange"].to_canonical(),
        }


class _RecordSrv(Structure):
    structure = (
        ("wPriority", ">H"),
        ("wWeight", ">H"),
        ("wPort", ">H"),
        ("nameTarget", ":", _CountName),
    )

    def to_canonical(self) -> dict:
        return {
            "priority": self["wPriority"],
            "weight": self["wWeight"],
            "port": self["wPort"],
            "target": self["nameTarget"].to_canonical(),
        }


class _RecordString(Structure):
    """Wrapper for DNS_RPC_NAME (length-prefixed byte string)."""
    structure = (("cchNameLength", "B-dnsName"), ("dnsName", ":"))

    def to_canonical(self) -> str:
        return self["dnsName"].decode("utf-8")


class _RecordSoa(Structure):
    structure = (
        ("dwSerialNo", ">I"),
        ("dwRefresh", ">I"),
        ("dwRetry", ">I"),
        ("dwExpire", ">I"),
        ("dwMinimumTtl", ">I"),
        ("namePrimaryServer", ":", _CountName),
        ("zoneAdminEmail", ":", _CountName),
    )

    def to_canonical(self) -> dict:
        return {
            "serial": self["dwSerialNo"],
            "refresh": self["dwRefresh"],
            "retry": self["dwRetry"],
            "expire": self["dwExpire"],
            "minimum_ttl": self["dwMinimumTtl"],
            "primary_server": self["namePrimaryServer"].to_canonical(),
            "admin_email": self["zoneAdminEmail"].to_canonical(),
        }


def parse_dns_record(raw: bytes) -> dict:
    """Parse one ``dnsRecord`` blob and return a plain dict.

    The dict has keys ``type``, ``data``, ``ttl_seconds``. ``type`` is the RRTYPE
    name (``A``, ``AAAA``, ``CNAME``, ``NS``, ``PTR``, ``MX``, ``SRV``, ``TXT``,
    ``SOA``) when known, otherwise the raw ``int`` code. ``data`` is a string for
    simple types and a nested dict for MX/SRV/SOA.
    """
    record = _DnsRecord(raw)
    type_code = record["Type"]
    type_name: str | int = _DNS_TYPE_BY_CODE.get(type_code, type_code)

    payload = record["Data"]
    if type_name == "A":
        data: str | dict = _RecordA(payload).to_canonical()
    elif type_name == "AAAA":
        data = _RecordAAAA(payload).to_canonical()
    elif type_name in ("NS", "CNAME", "PTR"):
        data = _RecordNodeName(payload).to_canonical()
    elif type_name == "MX":
        data = _RecordMx(payload).to_canonical()
    elif type_name == "SRV":
        data = _RecordSrv(payload).to_canonical()
    elif type_name == "TXT":
        data = _RecordString(payload).to_canonical()
    elif type_name == "SOA":
        data = _RecordSoa(payload).to_canonical()
    else:
        data = payload.hex()

    return {
        "type": type_name,
        "data": data,
        "ttl_seconds": record["TtlSeconds"],
    }
