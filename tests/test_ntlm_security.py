# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""NtlmSecurityContext (Phase 3b): SPNEGO-wrapped NTLM handshake + sign+seal.

Verifies the outgoing byte structure against MS-NLMP / RFC 4178 and full round-trips wrap
against a server-side SEAL synthesised from the same session key.
"""

import struct

import pytest
from impacket import ntlm as impacket_ntlm
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from Cryptodome.Cipher import ARC4

from adwsearch.auth.credentials import Credentials
from adwsearch.auth.ntlm import NtlmSecurityContext


NTLMSSP_OID = TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]
NTLM_SIGNATURE = b"NTLMSSP\x00"


def _build_server_type2(target_name: str = "CORP",
                        challenge: bytes = b"\x11\x22\x33\x44\x55\x66\x77\x88") -> bytes:
    """Build a minimal but valid NTLM Type2 (Challenge) message.

    Header layout without VERSION is 48 bytes fixed, then domain_name, then TargetInfoFields.
    ``NTLMAuthChallenge`` requires the offsets to be set explicitly.
    """
    ch = impacket_ntlm.NTLMAuthChallenge()
    ch["flags"] = (
        impacket_ntlm.NTLMSSP_NEGOTIATE_UNICODE
        | impacket_ntlm.NTLMSSP_REQUEST_TARGET
        | impacket_ntlm.NTLMSSP_NEGOTIATE_NTLM
        | impacket_ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | impacket_ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | impacket_ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO
        | impacket_ntlm.NTLMSSP_NEGOTIATE_128
        | impacket_ntlm.NTLMSSP_NEGOTIATE_56
        | impacket_ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
        | impacket_ntlm.NTLMSSP_NEGOTIATE_SEAL
        | impacket_ntlm.NTLMSSP_NEGOTIATE_SIGN
        | impacket_ntlm.NTLMSSP_TARGET_TYPE_DOMAIN
    )
    domain_bytes = target_name.encode("utf-16le")
    ch["domain_name"] = domain_bytes
    ch["challenge"] = challenge
    ch["reserved"] = b"\x00" * 8
    av_pairs = impacket_ntlm.AV_PAIRS()
    av_pairs[impacket_ntlm.NTLMSSP_AV_DOMAINNAME] = domain_bytes
    av_pairs[impacket_ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = domain_bytes
    av_pairs[impacket_ntlm.NTLMSSP_AV_DNS_HOSTNAME] = f"dc.{target_name}".encode("utf-16le")
    av_pairs[impacket_ntlm.NTLMSSP_AV_HOSTNAME] = b"DC"
    target_info = av_pairs.getData()
    ch["TargetInfoFields"] = target_info
    ch["Version"] = b""
    ch["domain_offset"] = 48
    ch["TargetInfoFields_offset"] = 48 + len(domain_bytes)
    return ch.getData()


def _wrap_server_challenge_in_spnego(ntlm_type2: bytes) -> bytes:
    """Emulate what the server sends: SPNEGO NegTokenResp with the NTLM Type2 inside."""
    resp = SPNEGO_NegTokenResp()
    resp["NegState"] = b"\x01"  # accept-incomplete
    resp["SupportedMech"] = NTLMSSP_OID
    resp["ResponseToken"] = ntlm_type2
    return resp.getData()


# ---------------------------------------------------------------------------

def test_step_initial_emits_spnego_neg_token_init_with_ntlm_type1():
    creds = Credentials(username="alice", domain="CORP", password="S3cret!")
    ctx = NtlmSecurityContext(creds)

    out = ctx.step(None)

    assert isinstance(out, bytes) and len(out) > 0
    assert not ctx.complete
    # GSS-API application tag [APPLICATION 0] = 0x60
    assert out[0] == 0x60
    parsed = SPNEGO_NegTokenInit(out)
    assert NTLMSSP_OID in parsed["MechTypes"]
    inner = parsed["MechToken"]
    assert inner.startswith(NTLM_SIGNATURE)
    # MessageType == 0x00000001 (NEGOTIATE)
    assert inner[8:12] == b"\x01\x00\x00\x00"


def test_step_challenge_response_emits_type3_and_sets_complete():
    creds = Credentials(username="alice", domain="CORP", password="S3cret!",
                        workstation="WKS01")
    ctx = NtlmSecurityContext(creds)
    ctx.step(None)  # advance to challenge state

    server_reply = _wrap_server_challenge_in_spnego(_build_server_type2())
    out = ctx.step(server_reply)

    assert ctx.complete is True
    parsed = SPNEGO_NegTokenResp(out)
    inner = parsed["ResponseToken"]
    assert inner.startswith(NTLM_SIGNATURE)
    # MessageType == 0x00000003 (AUTHENTICATE)
    assert inner[8:12] == b"\x03\x00\x00\x00"


def test_step_challenge_response_pass_the_hash():
    """PtH: no password, only NT hash — Type3 still generated correctly."""
    nt = bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")
    creds = Credentials(username="alice", domain="CORP", nthash=nt)
    ctx = NtlmSecurityContext(creds)
    ctx.step(None)
    ctx.step(_wrap_server_challenge_in_spnego(_build_server_type2()))
    assert ctx.complete is True


def test_wrap_produces_signature_plus_ciphertext():
    creds = Credentials(username="alice", domain="CORP", password="S3cret!")
    ctx = NtlmSecurityContext(creds)
    ctx.step(None)
    ctx.step(_wrap_server_challenge_in_spnego(_build_server_type2()))

    plaintext = b"hello"
    wrapped = ctx.wrap(plaintext)

    # NTLMv2 with KEY_EXCH: 16-byte message signature + sealed ciphertext of same length.
    assert len(wrapped) == 16 + len(plaintext)
    # Signature version field (first 4 bytes) == 0x00000001
    assert wrapped[:4] == b"\x01\x00\x00\x00"
    # Ciphertext is not equal to plaintext (RC4-sealed)
    assert wrapped[16:] != plaintext


def test_wrap_uses_incrementing_sequence_number():
    creds = Credentials(username="alice", domain="CORP", password="S3cret!")
    ctx = NtlmSecurityContext(creds)
    ctx.step(None)
    ctx.step(_wrap_server_challenge_in_spnego(_build_server_type2()))

    w0 = ctx.wrap(b"AAAA")
    w1 = ctx.wrap(b"AAAA")

    # seq number lives in the last 4 bytes of the 16-byte NTLM message signature.
    seq0 = struct.unpack("<I", w0[12:16])[0]
    seq1 = struct.unpack("<I", w1[12:16])[0]
    assert seq1 == seq0 + 1


def test_unwrap_round_trips_a_server_sealed_message():
    creds = Credentials(username="alice", domain="CORP", password="S3cret!")
    ctx = NtlmSecurityContext(creds)
    ctx.step(None)
    ctx.step(_wrap_server_challenge_in_spnego(_build_server_type2()))

    # Simulate the server side using the same session key with mode='Server'.
    session_key = ctx._exported_session_key
    flags = ctx._flags
    server_sign_key = impacket_ntlm.SIGNKEY(flags, session_key, mode="Server")
    server_seal_key = impacket_ntlm.SEALKEY(flags, session_key, mode="Server")
    server_handle = ARC4.new(server_seal_key).encrypt

    plaintext = b"server->client payload"
    sealed, signature = impacket_ntlm.SEAL(flags, server_sign_key, server_seal_key,
                                           plaintext, plaintext, 0, server_handle)
    server_wrapped = signature.getData() + sealed

    recovered = ctx.unwrap(server_wrapped)
    assert recovered == plaintext


def test_unwrap_rejects_bad_signature():
    creds = Credentials(username="alice", domain="CORP", password="S3cret!")
    ctx = NtlmSecurityContext(creds)
    ctx.step(None)
    ctx.step(_wrap_server_challenge_in_spnego(_build_server_type2()))

    # 16 bytes of garbage signature + some ciphertext — must not authenticate.
    with pytest.raises(ValueError):
        ctx.unwrap(b"\x00" * 16 + b"payload")


def test_wrap_before_handshake_raises():
    creds = Credentials(username="alice", domain="CORP", password="S3cret!")
    ctx = NtlmSecurityContext(creds)
    with pytest.raises(RuntimeError):
        ctx.wrap(b"x")
