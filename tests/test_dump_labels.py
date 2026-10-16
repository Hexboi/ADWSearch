# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""BloodHound label mapping + well-known SID catalogue."""

from adwsearch.dump.labels import Label, class_to_label
from adwsearch.dump.well_known_sids import WELL_KNOWN_SIDS


def test_class_to_label_maps_known_classes():
    assert class_to_label("user") == Label.User
    assert class_to_label("computer") == Label.Computer
    assert class_to_label("group") == Label.Group
    assert class_to_label("organizationalunit") == Label.OU
    assert class_to_label("container") == Label.Container
    assert class_to_label("rpccontainer") == Label.Container
    assert class_to_label("grouppolicycontainer") == Label.GPO
    assert class_to_label("domain") == Label.Domain
    assert class_to_label("domaindns") == Label.Domain
    assert class_to_label("msds-managedserviceaccount") == Label.User
    assert class_to_label("msds-groupmanagedserviceaccount") == Label.User
    assert class_to_label("unknown-class") == Label.Base
    assert class_to_label("") == Label.Base


def test_well_known_sid_lookup():
    assert WELL_KNOWN_SIDS["S-1-5-32-544"] == Label.Group
    assert WELL_KNOWN_SIDS["S-1-5-11"] == Label.Group
    assert WELL_KNOWN_SIDS["S-1-1-0"] == Label.Group
    assert WELL_KNOWN_SIDS["S-1-5-18"] == Label.User
