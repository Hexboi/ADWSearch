# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""BloodHound-style object labels + mapping from AD objectClass to Label.

The label taxonomy mirrors BloodHound v5's node kinds so a downstream dump can
categorise every principal in a single symbol. This module is deliberately
pure-Python (no I/O, no ADWS) so the mapping can be unit-tested standalone.

Conceptual reference: SOAPHound (`Enums/Labels.cs` and
`ADWSUtils.ClasstoLabel`). See NOTICE.
"""

import enum


class Label(str, enum.Enum):
    User = "User"
    Group = "Group"
    Computer = "Computer"
    Domain = "Domain"
    OU = "OU"
    GPO = "GPO"
    Container = "Container"
    Base = "Base"


# The AD schema exposes a lot of container-like classes; we collapse the ones
# BloodHound treats as plain "Container" nodes into a single Label.Container.
_CONTAINER_CLASSES = frozenset({
    "container",
    "rpccontainer",
    "msimaging-psps",
    "msexchconfigurationcontainer",
})

# gMSA / sMSA are user-shaped for BloodHound purposes.
_USER_CLASSES = frozenset({
    "user",
    "msds-managedserviceaccount",
    "msds-groupmanagedserviceaccount",
})

_DOMAIN_CLASSES = frozenset({"domain", "domaindns"})


def class_to_label(object_class: str) -> Label:
    """Map a local-name objectClass string (lower-case) to a :class:`Label`.

    Unknown classes fall back to :attr:`Label.Base` (BloodHound's neutral kind).
    Callers should pass ``adobject.object_class`` directly — the parser already
    lower-cases the LocalName of the returned element.
    """
    name = (object_class or "").lower()
    if name in _USER_CLASSES:
        return Label.User
    if name == "group":
        return Label.Group
    if name == "computer":
        return Label.Computer
    if name in _DOMAIN_CLASSES:
        return Label.Domain
    if name == "organizationalunit":
        return Label.OU
    if name == "grouppolicycontainer":
        return Label.GPO
    if name in _CONTAINER_CLASSES:
        return Label.Container
    return Label.Base
