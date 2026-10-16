# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""LDIF and JSON writers (Phase 4b): stream ``AdObject`` entries out for the CLI.

The writers apply :func:`adwsearch.attributes.decode.decode_attributes` first so tests
here exercise both integration (SID decoding round-trips through the writer) and the
format-specific bits (LDIF ``::`` marker for binary, JSON entry shape).
"""

import io
import json

from adwsearch.output.writers import write_json, write_ldif
from adwsearch.soap.parser import AdObject


def _entry(dn: str, **attrs):
    fields = {"distinguishedName": [dn], **attrs}
    return AdObject(object_class="user", attributes=fields)


# --- LDIF ------------------------------------------------------------------

def test_ldif_dn_line_first_then_attributes_in_order():
    buf = io.StringIO()
    entry = _entry("CN=Alice,OU=Users,DC=corp,DC=local",
                   sAMAccountName=["alice"], objectClass=["user"])
    write_ldif([entry], buf)
    lines = buf.getvalue().splitlines()
    assert lines[0] == "dn: CN=Alice,OU=Users,DC=corp,DC=local"
    # sAMAccountName and objectClass show up as single-colon text lines.
    assert "sAMAccountName: alice" in lines
    assert "objectClass: user" in lines


def test_ldif_binary_bytes_get_double_colon_base64():
    sid_bytes = bytes.fromhex("01020000000000052000000020020000")
    buf = io.StringIO()
    entry = _entry("CN=Group,DC=corp,DC=local",
                   nTSecurityDescriptor=[b"\x00\x01\x02\xff"],
                   objectSid=[sid_bytes])
    write_ldif([entry], buf)
    text = buf.getvalue()
    # Unknown binary → base64 with ::, known SID → decoded text with :.
    assert "nTSecurityDescriptor:: AAEC/w==" in text
    assert "objectSid: S-1-5-32-544" in text


def test_ldif_separates_entries_with_blank_line():
    buf = io.StringIO()
    write_ldif([
        _entry("CN=a,DC=x", sAMAccountName=["a"]),
        _entry("CN=b,DC=x", sAMAccountName=["b"]),
    ], buf)
    # Two entries, each terminated by a blank line.
    assert buf.getvalue().count("\n\n") == 2
    assert "dn: CN=a,DC=x" in buf.getvalue()
    assert "dn: CN=b,DC=x" in buf.getvalue()


def test_ldif_omits_dn_line_when_distinguished_name_missing():
    buf = io.StringIO()
    entry = AdObject(object_class="user",
                     attributes={"sAMAccountName": ["alice"]})
    write_ldif([entry], buf)
    text = buf.getvalue()
    assert "dn:" not in text
    assert "sAMAccountName: alice" in text


def test_ldif_multi_valued_attribute_emits_one_line_per_value():
    buf = io.StringIO()
    entry = _entry("CN=Alice,DC=x", memberOf=["CN=Grp1,DC=x", "CN=Grp2,DC=x"])
    write_ldif([entry], buf)
    lines = buf.getvalue().splitlines()
    assert "memberOf: CN=Grp1,DC=x" in lines
    assert "memberOf: CN=Grp2,DC=x" in lines


def test_ldif_escapes_value_with_embedded_newline_as_base64():
    """RFC 2849: a string value with LF/CR must be base64-encoded (``::``)."""
    buf = io.StringIO()
    entry = _entry("CN=Alice,DC=x", description=["line1\nline2"])
    write_ldif([entry], buf)
    text = buf.getvalue()
    # Must NOT split across lines as if two attributes.
    assert "description: line1\nline2" not in text
    # Must be emitted with :: (double colon) and a base64 payload.
    import base64
    b64 = base64.b64encode("line1\nline2".encode("utf-8")).decode("ascii")
    assert f"description:: {b64}" in text


def test_ldif_escapes_value_with_leading_space():
    buf = io.StringIO()
    entry = _entry("CN=Alice,DC=x", comment=[" leading-space"])
    write_ldif([entry], buf)
    assert "comment: " not in buf.getvalue()  # would be leading-space attr line
    assert "comment:: " in buf.getvalue()


def test_ldif_escapes_value_with_leading_colon():
    buf = io.StringIO()
    entry = _entry("CN=Alice,DC=x", info=[":masked"])
    write_ldif([entry], buf)
    assert "info:: " in buf.getvalue()


def test_ldif_leaves_normal_ascii_values_alone():
    buf = io.StringIO()
    entry = _entry("CN=Alice,DC=x", description=["hello world"])
    write_ldif([entry], buf)
    assert "description: hello world" in buf.getvalue()


def test_ldif_raw_mode_leaves_uac_as_int_string():
    buf = io.StringIO()
    entry = _entry("CN=Alice,DC=x", userAccountControl=[512])
    write_ldif([entry], buf, raw=True)
    text = buf.getvalue()
    assert "userAccountControl: 512" in text
    # No flag-name decoration in raw mode.
    assert "NORMAL_ACCOUNT" not in text


# --- JSON ------------------------------------------------------------------

def test_json_emits_list_of_entries_with_dn_and_attributes():
    buf = io.StringIO()
    write_json([
        _entry("CN=Alice,DC=x", sAMAccountName=["alice"]),
        _entry("CN=Bob,DC=x", sAMAccountName=["bob"]),
    ], buf)
    data = json.loads(buf.getvalue())
    assert isinstance(data, list) and len(data) == 2
    assert data[0]["dn"] == "CN=Alice,DC=x"
    assert data[0]["attributes"]["sAMAccountName"] == ["alice"]
    assert data[1]["dn"] == "CN=Bob,DC=x"


def test_json_applies_sid_decoder():
    sid_bytes = bytes.fromhex("01020000000000052000000020020000")
    buf = io.StringIO()
    write_json([_entry("CN=Grp,DC=x", objectSid=[sid_bytes])], buf)
    data = json.loads(buf.getvalue())
    assert data[0]["attributes"]["objectSid"] == ["S-1-5-32-544"]


def test_json_raw_mode_base64_encodes_binary():
    buf = io.StringIO()
    write_json([_entry("CN=Grp,DC=x", nTSecurityDescriptor=[b"\xde\xad"])], buf, raw=True)
    data = json.loads(buf.getvalue())
    assert data[0]["attributes"]["nTSecurityDescriptor"] == ["3q0="]


def test_json_object_class_is_carried_through():
    buf = io.StringIO()
    entry = AdObject(object_class="group",
                     attributes={"distinguishedName": ["CN=g,DC=x"]})
    write_json([entry], buf)
    data = json.loads(buf.getvalue())
    assert data[0]["object_class"] == "group"


def test_json_handles_empty_iterable():
    buf = io.StringIO()
    write_json([], buf)
    assert json.loads(buf.getvalue()) == []
