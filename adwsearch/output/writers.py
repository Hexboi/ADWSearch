# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Streaming LDIF and JSON writers.

Both walk an iterable of :class:`~adwsearch.soap.parser.AdObject`, apply
:func:`~adwsearch.attributes.decode.decode_attributes` (unless ``raw=True``) and stream
one entry at a time so a large search doesn't buffer the whole result in memory.

DN is extracted from the ``distinguishedName`` attribute (single-valued in AD); when
absent, LDIF omits the ``dn:`` line and JSON emits ``"dn": null``.

LDIF safety: any server-controlled string value that is not a SAFE-STRING per RFC 2849
(embedded NUL/LF/CR, leading space/colon/less-than, trailing space, non-ASCII) is
base64-encoded and emitted with the ``::`` (double colon) marker so a malicious
attribute value cannot inject fake ``dn:`` / attribute lines into the LDIF output.
"""

import base64
import json

from adwsearch.attributes.decode import Base64Value, decode_attributes


def _extract_dn(attributes):
    values = attributes.get("distinguishedName")
    if not values:
        return None
    value = values[0]
    return value if isinstance(value, str) else str(value)


def _ldif_needs_base64(value: str) -> bool:
    """RFC 2849 SAFE-STRING check: return True when the value is NOT a SAFE-STRING.

    SAFE-INIT-CHAR excludes: NUL, LF, CR, SPACE, ':', '<'.
    SAFE-CHAR excludes: NUL, LF, CR.
    Trailing SPACE also requires base64. Non-ASCII (%x80+) requires base64.
    """
    if not value:
        return False
    if value[0] in " :<":
        return True
    if value[-1] == " ":
        return True
    for ch in value:
        code = ord(ch)
        if code == 0x00 or code == 0x0A or code == 0x0D or code > 0x7F:
            return True
    return False


def _ldif_line(name: str, value: str) -> str:
    """Format one LDIF attribute line, base64-encoding when RFC 2849 requires it."""
    if isinstance(value, Base64Value):
        return f"{name}:: {value}\n"
    if _ldif_needs_base64(value):
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        return f"{name}:: {encoded}\n"
    return f"{name}: {value}\n"


# --- LDIF ------------------------------------------------------------------

def write_ldif(entries, stream, *, raw: bool = False) -> None:
    for entry in entries:
        decoded = decode_attributes(entry.attributes, raw=raw)
        dn = _extract_dn(decoded)
        if dn is not None:
            stream.write(_ldif_line("dn", dn))
        for name, values in decoded.items():
            if name == "distinguishedName":
                continue  # already emitted as dn:
            for value in values:
                stream.write(_ldif_line(name, value))
        stream.write("\n")


# --- JSON ------------------------------------------------------------------

def write_json(entries, stream, *, raw: bool = False) -> None:
    stream.write("[")
    first = True
    for entry in entries:
        if not first:
            stream.write(",")
        stream.write("\n  ")
        decoded = decode_attributes(entry.attributes, raw=raw)
        obj = {
            "dn": _extract_dn(decoded),
            "object_class": entry.object_class,
            "attributes": decoded,
        }
        json.dump(obj, stream, ensure_ascii=False)
        first = False
    stream.write("\n]" if not first else "]")
    stream.write("\n")
