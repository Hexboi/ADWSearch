# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""KerberosSecurityContext (Phase 3c): SPNEGO+AP-REQ handshake + GSS_Wrap sign+seal.

Handshake pieces (getKerberosType1 / getKerberosType3) are exercised via monkeypatch to
keep the tests offline. wrap/unwrap use the real impacket AES128 crypto against a
synthesised "server" side that mirrors the standard GSS_Wrap_LDAP layout with the
ACCEPTOR_SEAL key usage.
"""

import struct

import pytest
from impacket.krb5 import kerberosv5 as _krb5
from impacket.krb5.crypto import Key, _AES128CTS, Enctype
from impacket.krb5.gssapi import GSSAPI_AES128, KG_USAGE_ACCEPTOR_SEAL

from adwsearch.auth.credentials import Credentials
from adwsearch.auth.kerberos import KerberosSecurityContext


@pytest.fixture(autouse=True)
def service_ticket(monkeypatch):
    # These tests own the SPNEGO/crypto boundary; cache selection has separate tests.
    monkeypatch.setattr("adwsearch.auth.kerberos.load_service_ticket",
                        lambda *args, **kwargs: {"KDC_REP": b"ticket", "cipher": None, "sessionKey": None})
    monkeypatch.setattr("adwsearch.auth.kerberos._initial_timestamp", lambda *args: ('fixture', 0))


# --- fakes -----------------------------------------------------------------

class _FakeCipher:
    """Stand-in for impacket cipher during handshake plumbing tests."""
    enctype = Enctype.AES128


class _FakeSessionKey:
    """Stand-in for impacket Key during handshake plumbing tests."""


def _simulate_server_wrap(session_key, cipher, plaintext: bytes, seq: int) -> bytes:
    """Mirror impacket's GSS_Wrap_LDAP with KG_USAGE_ACCEPTOR_SEAL (server outbound)."""
    gss = GSSAPI_AES128()
    token = gss.WRAP()
    token["Flags"] = 7
    token["EC"] = 0
    token["RRC"] = 0
    token["SND_SEQ"] = struct.pack(">Q", seq)
    ct = cipher.encrypt(session_key, KG_USAGE_ACCEPTOR_SEAL,
                        plaintext + token.getData(), None)
    token["RRC"] = 28
    rotated = gss.rotate(ct, 28)
    return token.getData() + rotated


# --- handshake state machine -----------------------------------------------

def test_step_initial_calls_get_kerberos_type1(monkeypatch):
    creds = Credentials(username="alice", domain="CORP.LOCAL", password="S3cret!")
    ctx = KerberosSecurityContext(creds, target_host="dc01.corp.local")

    seen = {}

    def fake_type1(username, password, domain, lmhash, nthash, aesKey=b"",
                   TGT=None, TGS=None, targetName="", kdcHost=None, useCache=True):
        seen.update(
            username=username, password=password, domain=domain,
            lmhash=lmhash, nthash=nthash, aesKey=aesKey,
            targetName=targetName, kdcHost=kdcHost, useCache=useCache,
        )
        return _FakeCipher(), _FakeSessionKey(), b"NEGTOKEN_INIT"

    monkeypatch.setattr(_krb5, "getKerberosType1", fake_type1)

    out = ctx.step(None)

    assert out == b"NEGTOKEN_INIT"
    assert ctx.complete is False
    assert seen["username"] == "alice"
    assert seen["domain"] == "CORP.LOCAL"
    assert seen["password"] == "S3cret!"
    assert seen["targetName"] == "dc01.corp.local"
    assert seen["useCache"] is False
    # cipher / session key were stashed for the next step
    assert isinstance(ctx._cipher, _FakeCipher)


def test_step_mutual_calls_get_kerberos_type3_and_sets_complete(monkeypatch):
    creds = Credentials(username="alice", domain="CORP.LOCAL", password="S3cret!")
    ctx = KerberosSecurityContext(creds, target_host="dc01.corp.local")

    monkeypatch.setattr(_krb5, "getKerberosType1",
                        lambda *a, **kw: (_FakeCipher(), _FakeSessionKey(), b"INIT"))
    ctx.step(None)

    new_cipher = _FakeCipher()
    new_session = _FakeSessionKey()
    seen = {}

    def fake_type3(cipher, session_key, auth_data, allowed, timestamp, *, dce_style=True):
        seen.update(cipher=cipher, session_key=session_key, auth_data=auth_data)
        return new_cipher, new_session, b"NEGTOKEN_RESP2", 0

    monkeypatch.setattr("adwsearch.auth.kerberos._mutual_exchange", fake_type3)

    out = ctx.step(b"SERVER_AP_REP")

    assert out == b"NEGTOKEN_RESP2"
    assert ctx.complete is True
    assert seen["auth_data"] == b"SERVER_AP_REP"
    assert ctx._cipher is new_cipher
    assert ctx._session_key is new_session


def test_step_refuses_rc4_cipher(monkeypatch):
    """RC4/arcfour-hmac Kerberos: GSS_Unwrap has no HMAC on the plaintext, so a
    MITM can bit-flip ciphertext without detection. Refuse the session outright."""

    class Rc4Cipher:
        enctype = Enctype.RC4

    creds = Credentials(username="alice", domain="CORP.LOCAL", password="pw")
    ctx = KerberosSecurityContext(creds, target_host="dc01")
    monkeypatch.setattr(_krb5, "getKerberosType1",
                        lambda *a, **kw: (Rc4Cipher(), _FakeSessionKey(), b"INIT"))
    with pytest.raises(RuntimeError, match="[Rr][Cc]4"):
        ctx.step(None)


def test_step_uses_pass_the_hash_and_aes_key(monkeypatch):
    creds = Credentials(
        username="alice", domain="CORP.LOCAL",
        nthash=bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0"),
        aes_key=bytes(16),
    )
    ctx = KerberosSecurityContext(creds, target_host="dc01.corp.local",
                                  kdc_host="192.0.2.10")

    seen = {}
    def fake_type1(username, password, domain, lmhash, nthash, aesKey=b"",
                   TGT=None, TGS=None, targetName="", kdcHost=None, useCache=True):
        seen.update(nthash=nthash, aesKey=aesKey, kdcHost=kdcHost)
        return _FakeCipher(), _FakeSessionKey(), b"INIT"
    monkeypatch.setattr(_krb5, "getKerberosType1", fake_type1)

    ctx.step(None)

    assert seen["nthash"] == creds.nthash
    assert seen["aesKey"] == creds.aes_key
    assert seen["kdcHost"] == "192.0.2.10"


# --- sign + seal -----------------------------------------------------------

def test_wrap_before_handshake_raises():
    creds = Credentials(username="alice", domain="CORP.LOCAL", password="pw")
    ctx = KerberosSecurityContext(creds, target_host="dc01")
    with pytest.raises(RuntimeError):
        ctx.wrap(b"x")


def test_wrap_produces_16_byte_header_plus_ciphertext():
    creds = Credentials(username="alice", domain="CORP.LOCAL", password="pw")
    ctx = KerberosSecurityContext(creds, target_host="dc01")
    # Bypass handshake: inject a completed state with a real AES128 key.
    ctx._cipher = _AES128CTS()
    ctx._session_key = Key(Enctype.AES128, b"\x00" * 16)
    ctx._state = "done"
    ctx.complete = True

    plaintext = b"hello world"
    wrapped = ctx.wrap(plaintext)

    # The GSS_Wrap_LDAP header is 16 bytes; ciphertext follows.
    assert len(wrapped) >= 16
    # TOK_ID = 0x0504 for GSS_Wrap
    assert wrapped[:2] == b"\x05\x04"


def test_wrap_increments_sequence_number_across_calls():
    creds = Credentials(username="alice", domain="CORP.LOCAL", password="pw")
    ctx = KerberosSecurityContext(creds, target_host="dc01")
    ctx._cipher = _AES128CTS()
    ctx._session_key = Key(Enctype.AES128, b"\x00" * 16)
    ctx._state = "done"
    ctx.complete = True

    w0 = ctx.wrap(b"AAAA")
    w1 = ctx.wrap(b"AAAA")

    # Two wraps at different sequence numbers must differ (GSS_Wrap header includes seq).
    assert w0 != w1
    # The 8-byte SND_SEQ lives at bytes 8..16 of the WRAP header.
    seq0 = struct.unpack(">Q", w0[8:16])[0]
    seq1 = struct.unpack(">Q", w1[8:16])[0]
    assert seq1 == seq0 + 1


def test_unwrap_does_not_bump_the_send_sequence_number():
    """Client's outbound seq and server's outbound seq must be tracked separately."""
    creds = Credentials(username="alice", domain="CORP.LOCAL", password="pw")
    ctx = KerberosSecurityContext(creds, target_host="dc01")
    session_key = Key(Enctype.AES128, b"\x22" * 16)
    cipher = _AES128CTS()
    ctx._cipher = cipher
    ctx._session_key = session_key
    ctx._state = "done"
    ctx.complete = True

    w0 = ctx.wrap(b"first")
    ctx.unwrap(_simulate_server_wrap(session_key, cipher, b"server_msg", seq=0))
    w1 = ctx.wrap(b"second")

    seq0 = struct.unpack(">Q", w0[8:16])[0]
    seq1 = struct.unpack(">Q", w1[8:16])[0]
    assert seq0 == 0
    assert seq1 == 1, "unwrap must not advance the send seq counter"


def test_unwrap_rejects_wrong_incoming_sequence_number():
    """Server-sent SND_SEQ must equal our _recv_seq (RFC 4121 ordering)."""
    creds = Credentials(username="alice", domain="CORP.LOCAL", password="pw")
    ctx = KerberosSecurityContext(creds, target_host="dc01")
    session_key = Key(Enctype.AES128, b"\x33" * 16)
    cipher = _AES128CTS()
    ctx._cipher = cipher
    ctx._session_key = session_key
    ctx._state = "done"
    ctx.complete = True

    # Server sends seq=5, but we expect seq=0 (first receive)
    wrong_seq_msg = _simulate_server_wrap(session_key, cipher, b"msg", seq=5)
    with pytest.raises(ValueError, match="[Ss]eq"):
        ctx.unwrap(wrong_seq_msg)


def test_unwrap_rejects_replayed_message():
    """A replayed valid message must not be accepted twice."""
    creds = Credentials(username="alice", domain="CORP.LOCAL", password="pw")
    ctx = KerberosSecurityContext(creds, target_host="dc01")
    session_key = Key(Enctype.AES128, b"\x44" * 16)
    cipher = _AES128CTS()
    ctx._cipher = cipher
    ctx._session_key = session_key
    ctx._state = "done"
    ctx.complete = True

    msg = _simulate_server_wrap(session_key, cipher, b"first", seq=0)
    assert ctx.unwrap(msg) == b"first"
    with pytest.raises(ValueError, match="[Ss]eq"):
        ctx.unwrap(msg)  # replay: SND_SEQ=0 but _recv_seq is now 1


def test_unwrap_rejects_too_short_input():
    creds = Credentials(username="alice", domain="CORP.LOCAL", password="pw")
    ctx = KerberosSecurityContext(creds, target_host="dc01")
    ctx._cipher = _AES128CTS()
    ctx._session_key = Key(Enctype.AES128, b"\x00" * 16)
    ctx._state = "done"
    ctx.complete = True

    with pytest.raises(ValueError):
        ctx.unwrap(b"\x05\x04short")


def test_unwrap_recovers_server_wrapped_payload():
    creds = Credentials(username="alice", domain="CORP.LOCAL", password="pw")
    ctx = KerberosSecurityContext(creds, target_host="dc01")
    session_key = Key(Enctype.AES128, b"\x11" * 16)
    cipher = _AES128CTS()
    ctx._cipher = cipher
    ctx._session_key = session_key
    ctx._state = "done"
    ctx.complete = True

    plaintext = b"server->client message"
    server_wrapped = _simulate_server_wrap(session_key, cipher, plaintext, seq=0)

    recovered = ctx.unwrap(server_wrapped)
    assert recovered == plaintext
