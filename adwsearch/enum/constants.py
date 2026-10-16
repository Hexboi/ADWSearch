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
