# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Shared directory conversion helpers and LDAP controls for dump collectors."""

import datetime as dt
import re
from typing import Any

SD_FLAGS_OID = "1.2.840.113556.1.4.801"
SD_FLAGS_OWNER_GROUP_DACL = "MIQAAAADAgEH"


def first_value(values: Any) -> Any:
    return values[0] if values else None


def datetime_to_unix(value: Any) -> int:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return int(value.timestamp())
    if isinstance(value, str):
        try:
            return int(dt.datetime.strptime(value.split(".")[0], "%Y%m%d%H%M%S")
                       .replace(tzinfo=dt.timezone.utc).timestamp())
        except ValueError:
            return -1
    return -1


def split_dn(dn: str) -> list[str]:
    parts, start, escaped = [], 0, False
    for index, char in enumerate(dn):
        if char == "," and not escaped:
            parts.append(dn[start:index].strip())
            start = index + 1
        escaped = char == "\\" and not escaped
    parts.append(dn[start:].strip())
    return parts


def rdn_value(rdn: str) -> str:
    value = rdn.split("=", 1)[1]
    # Escaped hex pairs are bytes, potentially a multi-byte UTF-8 sequence.
    encoded = bytearray()
    position = 0
    for match in re.finditer(r"\\([0-9a-fA-F]{2}|.)", value):
        encoded.extend(value[position:match.start()].encode("utf-8"))
        if len(match[1]) == 2:
            encoded.append(int(match[1], 16))
        else:
            encoded.extend(match[1].encode("utf-8"))
        position = match.end()
    encoded.extend(value[position:].encode("utf-8"))
    return encoded.decode("utf-8")


def domain_from_dn(dn: str) -> str:
    return ".".join(rdn_value(r) for r in split_dn(dn)
                    if r.upper().startswith("DC=")).upper()
