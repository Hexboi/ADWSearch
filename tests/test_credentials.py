# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import pytest

from adwsearch.auth.credentials import Credentials, parse_hashes


def test_credentials_defaults():
    c = Credentials(username="alice", domain="CORP")
    assert c.username == "alice"
    assert c.domain == "CORP"
    assert c.password == ""
    assert c.lmhash == b""
    assert c.nthash == b""
    assert c.workstation == ""


def test_credentials_with_password():
    c = Credentials(username="alice", domain="CORP", password="S3cret!")
    assert c.password == "S3cret!"


def test_credentials_with_nthash():
    nt = bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")
    c = Credentials(username="alice", domain="CORP", nthash=nt)
    assert c.nthash == nt


def test_parse_hashes_full():
    lm, nt = parse_hashes(
        "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
    )
    assert lm == bytes.fromhex("aad3b435b51404eeaad3b435b51404ee")
    assert nt == bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")


def test_parse_hashes_nt_only():
    lm, nt = parse_hashes(":31d6cfe0d16ae931b73c59d7e0c089c0")
    assert lm == b""
    assert nt == bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")


def test_parse_hashes_rejects_missing_colon():
    with pytest.raises(ValueError):
        parse_hashes("31d6cfe0d16ae931b73c59d7e0c089c0")


def test_parse_hashes_rejects_odd_hex():
    with pytest.raises(ValueError):
        parse_hashes(":31d6cfe0d16ae931b73c59d7e0c089c")
