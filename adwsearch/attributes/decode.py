# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Decoders for well-known Active Directory attributes.

The NBF binary decoder already types values (bytes / int / datetime / UUID), so this
module just formats them for text output. Unknown attributes are passed through unchanged
except that bytes get base64-encoded (LDIF-safe) and datetime/UUID get str()'d.

With ``raw=True`` the per-attribute decoders are skipped (useful for ``ldapsearch``-style
"no decoding" output); bytes still get base64-encoded so the output stays text.
"""

import base64
import datetime as _dt
import logging
import uuid

from impacket.ldap.ldaptypes import LDAP_SID

_log = logging.getLogger(__name__)


class Base64Value(str):
    """Marker subclass: this string is a base64-encoded binary value.

    JSON serialisation is unchanged (still a str). LDIF checks isinstance and emits
    ``attr:: value`` (double colon) so downstream LDIF tools decode it as binary.
    """
    __slots__ = ()


_FILETIME_EPOCH_TO_UNIX_100NS = 116444736000000000
_FILETIME_NEVER = {0, 0x7FFFFFFFFFFFFFFF}

# [MS-ADTS] 2.2.16 userAccountControl bit flags (least-common trimmed).
_UAC_FLAGS = [
    (0x00000001, "SCRIPT"),
    (0x00000002, "ACCOUNTDISABLE"),
    (0x00000008, "HOMEDIR_REQUIRED"),
    (0x00000010, "LOCKOUT"),
    (0x00000020, "PASSWD_NOTREQD"),
    (0x00000040, "PASSWD_CANT_CHANGE"),
    (0x00000080, "ENCRYPTED_TEXT_PWD_ALLOWED"),
    (0x00000100, "TEMP_DUPLICATE_ACCOUNT"),
    (0x00000200, "NORMAL_ACCOUNT"),
    (0x00000800, "INTERDOMAIN_TRUST_ACCOUNT"),
    (0x00001000, "WORKSTATION_TRUST_ACCOUNT"),
    (0x00002000, "SERVER_TRUST_ACCOUNT"),
    (0x00010000, "DONT_EXPIRE_PASSWORD"),
    (0x00020000, "MNS_LOGON_ACCOUNT"),
    (0x00040000, "SMARTCARD_REQUIRED"),
    (0x00080000, "TRUSTED_FOR_DELEGATION"),
    (0x00100000, "NOT_DELEGATED"),
    (0x00200000, "USE_DES_KEY_ONLY"),
    (0x00400000, "DONT_REQ_PREAUTH"),
    (0x00800000, "PASSWORD_EXPIRED"),
    (0x01000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
    (0x04000000, "PARTIAL_SECRETS_ACCOUNT"),
]


def decode_sid(sid_bytes: bytes) -> str:
    """Binary SID (MS-DTYP 2.4.2) to its canonical ``S-1-...`` textual form."""
    return LDAP_SID(sid_bytes).formatCanonical()


def decode_uac(value) -> str:
    """Format userAccountControl as ``0xNNN (FLAG_A | FLAG_B | ...)``.

    ADWS exposes ``userAccountControl`` as ``xsd:int``, so the NBF decoder
    usually yields an ``int``; the WS-Transfer Get path and a few test
    fixtures surface it as a decimal ``str``. Coerce so both shapes decode.
    """
    value = int(value)
    names = [name for bit, name in _UAC_FLAGS if value & bit]
    if not names:
        return f"0x{value:X}"
    return f"0x{value:X} ({' | '.join(names)})"


def decode_filetime(value) -> str:
    """Windows FILETIME (100-ns intervals since 1601-01-01 UTC) to ISO 8601 UTC.

    Both 0 and 0x7FFFFFFFFFFFFFFF are returned as the string ``"never"``.
    """
    value = int(value)
    if value in _FILETIME_NEVER:
        return "never"
    seconds = (value - _FILETIME_EPOCH_TO_UNIX_100NS) / 10_000_000
    ts = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc) + _dt.timedelta(seconds=seconds)
    return ts.isoformat()


# --- catalog of per-attribute decoders (name -> callable(value) -> str). ---

_FILETIME_ATTRS = frozenset({
    "pwdLastSet", "lastLogon", "lastLogonTimestamp",
    "accountExpires", "badPasswordTime", "lockoutTime",
})

def _decode_functional_level(value):
    # Lazy import: enum.constants is a leaf module but importing it at load-time
    # here would tie decode.py's import order to the enum package.
    from adwsearch.enum.constants import format_functional_level
    return format_functional_level(int(value))


_DECODERS = {
    "objectSid": decode_sid,
    "userAccountControl": decode_uac,
    "msDS-Behavior-Version": _decode_functional_level,
}


def _default_encode(value) -> str:
    if isinstance(value, bytes):
        return Base64Value(base64.b64encode(value).decode("ascii"))
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    return str(value)


def decode_attributes(attributes, *, raw: bool = False):
    """Transform ``{name: [values]}`` from the parser into text-ready form.

    Known attributes get their dedicated decoder unless ``raw=True``. Everything else
    goes through :func:`_default_encode`.
    """
    out = {}
    for name, values in attributes.items():
        decoder = None
        if not raw:
            decoder = _DECODERS.get(name)
            if decoder is None and name in _FILETIME_ATTRS:
                decoder = decode_filetime
        decoded = []
        for value in values:
            if decoder is not None:
                try:
                    decoded.append(decoder(value))
                except Exception:
                    # Never abort a whole search on one malformed value: fall back
                    # to the raw / base64 form and leave a diagnostic trail so the
                    # operator can spot the corrupted attribute.
                    _log.warning(
                        "decoder for %r failed on value %r; falling back to raw",
                        name, value, exc_info=True)
                    decoded.append(_default_encode(value))
            else:
                decoded.append(_default_encode(value))
        out[name] = decoded
    return out
