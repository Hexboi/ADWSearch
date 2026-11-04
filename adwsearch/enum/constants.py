# SPDX-License-Identifier: MPL-2.0 AND MIT
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)
# Upstream portions: Copyright (c) 2022 CravateRouge, MIT License.
# MPL-2.0 covers ADWSearch additions; see NOTICE.

"""Constants used by the enumeration presets.

Portions ported from bloodyAD (https://github.com/CravateRouge/bloodyAD),
Copyright (c) 2022 CravateRouge — MIT License. See NOTICE.
"""

# msDS-Behavior-Version → release name.
# [MS-ADTS] section 6.1.4.3; table ported from bloodyAD/formatters/common.py.
FUNCTIONAL_LEVEL: dict[int, str] = {
    0: "DS_BEHAVIOR_WIN2000",
    1: "DS_BEHAVIOR_WIN2003_WITH_MIXED_DOMAINS",
    2: "DS_BEHAVIOR_WIN2003",
    3: "DS_BEHAVIOR_WIN2008",
    4: "DS_BEHAVIOR_WIN2008R2",
    5: "DS_BEHAVIOR_WIN2012",
    6: "DS_BEHAVIOR_WIN2012R2",
    7: "DS_BEHAVIOR_WIN2016",
    10: "DS_BEHAVIOR_WIN2025",
}


# sDRightsEffective bit mask (MS-ADTS 3.1.1.4.5.3 / MS-DTYP 2.4.6).
SD_RIGHTS_EFFECTIVE_BITS: list[tuple[int, str]] = [
    (0x1, "OWNER"),
    (0x2, "GROUP"),
    (0x4, "DACL"),
    (0x8, "SACL"),
]


# UAC bit exposed for the AS-REP roasting filter (also present in
# adwsearch/attributes/decode.py::_UAC_FLAGS).
DONT_REQ_PREAUTH = 0x00400000


def format_functional_level(value: int) -> str:
    """Render ``msDS-Behavior-Version`` value as ``"<n> (<name>)"``."""
    name = FUNCTIONAL_LEVEL.get(value)
    if name is None:
        return str(value)
    return f"{value} ({name})"


def format_sd_rights_effective(value: int) -> str:
    """Render ``sDRightsEffective`` as ``"OWNER|DACL|SACL"``."""
    names = [name for bit, name in SD_RIGHTS_EFFECTIVE_BITS if value & bit]
    return "|".join(names) if names else str(value)


_PASSWORD_PROPERTY_BITS = [
    (1, "DOMAIN_PASSWORD_COMPLEX"),
    (2, "DOMAIN_PASSWORD_NO_ANON_CHANGE"),
    (4, "DOMAIN_PASSWORD_NO_CLEAR_CHANGE"),
    (8, "DOMAIN_LOCKOUT_ADMINS"),
    (16, "DOMAIN_PASSWORD_STORE_CLEARTEXT"),
    (32, "DOMAIN_REFUSE_PASSWORD_CHANGE"),
]


def format_password_policy_value(name: str, value) -> str:
    """Annotate policy flags and signed 100-ns intervals without losing the raw value."""
    raw = str(value)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return raw
    try:
        number = int(value)
    except ValueError:
        return raw
    name = name.casefold()
    if name == "pwdproperties" and number >= 0:
        flags = [label for bit, label in _PASSWORD_PROPERTY_BITS if number & bit]
        unknown = number & ~0x3F
        if unknown:
            flags.append(f"unknown bits: 0x{unknown:X}")
        return f"{raw} ({' | '.join(flags) if flags else 'no flags set'})"
    if name == "lockoutthreshold" and number == 0:
        return f"{raw} (lockout disabled)"
    if name == "maxpwdage" and number in (0, -(2**63)):
        return f"{raw} (never expires)"
    if name == "lockoutduration" and number in (0, -(2**63)):
        return f"{raw} (administrator unlock required when lockout is enabled)"
    if name == "minpwdage" and number == 0:
        return f"{raw} (no minimum age)"
    if name == "forcelogoff" and number == -(2**63):
        return f"{raw} (forced logoff disabled)"
    if name == "forcelogoff" and number == 0:
        return f"{raw} (immediate logoff when logon hours expire)"
    if (name in ("minpwdage", "maxpwdage", "lockoutduration", "lockoutobservationwindow", "forcelogoff")
            and -(2**63) < number <= 0):
        seconds, fraction = divmod(-number, 10_000_000)
        duration = str(seconds) + (f".{fraction:07d}".rstrip("0") if fraction else "")
        return f"{raw} ({duration} seconds)"
    return raw
