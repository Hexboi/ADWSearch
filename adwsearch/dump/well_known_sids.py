# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Well-known SIDs that AD does not materialise as normal principals.

BloodHound (and any collector targeting it) needs to reason about principals
like "Everyone" (S-1-1-0) or "Authenticated Users" (S-1-5-11) that appear in
DACLs but have no corresponding directory object. We tag them as Groups so the
edge computation in later dump phases can treat them uniformly.

This is a documented Microsoft catalogue (see MS-DTYP 2.4.2.4 and
[MS-DTYP] Appendix "Well-Known SIDs"); reproducing it is not a derivative
work of SOAPHound.
"""

from adwsearch.dump.labels import Label


WELL_KNOWN_SIDS: dict[str, Label] = {
    "S-1-0-0":       Label.Group,
    "S-1-1-0":       Label.Group,
    "S-1-2-0":       Label.Group,
    "S-1-2-1":       Label.Group,
    "S-1-3-0":       Label.User,
    "S-1-3-1":       Label.Group,
    "S-1-3-4":       Label.Group,
    "S-1-5-1":       Label.Group,
    "S-1-5-2":       Label.Group,
    "S-1-5-3":       Label.Group,
    "S-1-5-4":       Label.Group,
    "S-1-5-6":       Label.Group,
    "S-1-5-7":       Label.Group,
    "S-1-5-9":       Label.Group,
    "S-1-5-10":      Label.User,
    "S-1-5-11":      Label.Group,
    "S-1-5-12":      Label.Group,
    "S-1-5-13":      Label.Group,
    "S-1-5-14":      Label.Group,
    "S-1-5-15":      Label.Group,
    "S-1-5-17":      Label.Group,
    "S-1-5-18":      Label.User,
    "S-1-5-19":      Label.User,
    "S-1-5-20":      Label.User,
    "S-1-5-32-544":  Label.Group,
    "S-1-5-32-545":  Label.Group,
    "S-1-5-32-546":  Label.Group,
    "S-1-5-32-547":  Label.Group,
    "S-1-5-32-548":  Label.Group,
    "S-1-5-32-549":  Label.Group,
    "S-1-5-32-550":  Label.Group,
    "S-1-5-32-551":  Label.Group,
    "S-1-5-32-552":  Label.Group,
    "S-1-5-32-554":  Label.Group,
    "S-1-5-32-555":  Label.Group,
    "S-1-5-32-556":  Label.Group,
    "S-1-5-32-557":  Label.Group,
    "S-1-5-32-558":  Label.Group,
    "S-1-5-32-559":  Label.Group,
    "S-1-5-32-560":  Label.Group,
    "S-1-5-32-561":  Label.Group,
    "S-1-5-32-562":  Label.Group,
    "S-1-5-32-568":  Label.Group,
    "S-1-5-32-569":  Label.Group,
    "S-1-5-32-573":  Label.Group,
    "S-1-5-32-574":  Label.Group,
    "S-1-5-32-575":  Label.Group,
    "S-1-5-32-576":  Label.Group,
    "S-1-5-32-577":  Label.Group,
    "S-1-5-32-578":  Label.Group,
    "S-1-5-32-579":  Label.Group,
    "S-1-5-32-580":  Label.Group,
}
