# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""NTLM (+ pass-the-hash) SecurityContext for the NNS negotiate stream.

Implements the ``complete``/``step``/``wrap``/``unwrap`` interface consumed by
``adwsearch.transport.nns.NegotiateStream``.

Wire flow (client side):

    step(None)               -> SPNEGO NegTokenInit (GSS-API 0x60 wrapped) with mechType
                                 NTLMSSP and mechToken = NTLM Type1 (NEGOTIATE)
    step(server_bytes)       -> SPNEGO NegTokenResp with responseToken = NTLM Type3
                                 (AUTHENTICATE), and marks self.complete=True

After handshake, ``wrap`` produces ``NTLMMessageSignature(16 bytes) || sealed`` and
``unwrap`` reverses it. Signing keys / sealing keys / ARC4 handles / sequence numbers are
derived per [MS-NLMP] 3.4 using impacket's ``SIGNKEY``, ``SEALKEY`` and ``SEAL`` helpers.

Note: the wire crypto (NTLMv2 sign+seal, key exchange) is API-version sensitive; full
interop is validatable only against a live DC (Phase 6). The unit tests cover structure
and self-consistency (roundtrip against a synthesised server side using the same session
key).
"""

import struct

from Cryptodome.Cipher import ARC4
from impacket import ntlm as _impacket_ntlm
from impacket.spnego import (
    SPNEGO_NegTokenInit,
    SPNEGO_NegTokenResp,
    TypesMech,
)
from adwsearch.auth.spnego import verify_completion


_NTLMSSP_OID = TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]
_NTLM_SIGNATURE_LEN = 16
_NTLM_SIG_VERSION = b"\x01\x00\x00\x00"


class NtlmSecurityContext:
    def __init__(self, credentials):
        self.credentials = credentials
        self.complete = False
        self._state = "init"
        self._type1 = None
        self._flags = 0
        self._exported_session_key = None
        self._client_sign_key = None
        self._server_sign_key = None
        self._client_seal_key = None
        self._server_seal_key = None
        self._client_handle = None
        self._server_handle = None
        self._client_seq = 0
        self._server_seq = 0

    # -- handshake ----------------------------------------------------------

    def step(self, in_token):
        if self._state == "init":
            return self._make_initial_token()
        if self._state == "challenge":
            return self._make_authenticate_token(in_token)
        # Empty Done is valid; a nonempty SPNEGO acknowledgment must positively
        # complete this mechanism, not reject it or request another exchange.
        if in_token:
            verify_completion(in_token, mechanisms=('1.3.6.1.4.1.311.2.2.10',))
        return None

    def _make_initial_token(self) -> bytes:
        self._type1 = _impacket_ntlm.getNTLMSSPType1(
            workstation=self.credentials.workstation,
            domain=self.credentials.domain,
            signingRequired=True,
        )
        init = SPNEGO_NegTokenInit()
        init["MechTypes"] = [_NTLMSSP_OID]
        init["MechToken"] = self._type1.getData()
        self._state = "challenge"
        return init.getData()

    def _make_authenticate_token(self, in_token: bytes) -> bytes:
        server_resp = SPNEGO_NegTokenResp(in_token)
        type2_bytes = server_resp["ResponseToken"]

        type3, exported_session_key = _impacket_ntlm.getNTLMSSPType3(
            self._type1,
            type2_bytes,
            self.credentials.username,
            self.credentials.password,
            self.credentials.domain,
            self.credentials.lmhash or "",
            self.credentials.nthash or "",
            use_ntlmv2=True,
        )

        self._exported_session_key = exported_session_key
        self._flags = type3["flags"]

        self._client_sign_key = _impacket_ntlm.SIGNKEY(
            self._flags, exported_session_key, mode="Client")
        self._server_sign_key = _impacket_ntlm.SIGNKEY(
            self._flags, exported_session_key, mode="Server")
        self._client_seal_key = _impacket_ntlm.SEALKEY(
            self._flags, exported_session_key, mode="Client")
        self._server_seal_key = _impacket_ntlm.SEALKEY(
            self._flags, exported_session_key, mode="Server")
        self._client_handle = ARC4.new(self._client_seal_key).encrypt
        self._server_handle = ARC4.new(self._server_seal_key).encrypt

        client_resp = SPNEGO_NegTokenResp()
        client_resp["ResponseToken"] = type3.getData()

        self._state = "done"
        self.complete = True
        return client_resp.getData()

    # -- sign + seal --------------------------------------------------------

    def wrap(self, data: bytes) -> bytes:
        if not self.complete:
            raise RuntimeError("NTLM handshake not complete")
        sealed, signature = _impacket_ntlm.SEAL(
            self._flags,
            self._client_sign_key,
            self._client_seal_key,
            data,
            data,
            self._client_seq,
            self._client_handle,
        )
        self._client_seq += 1
        return signature.getData() + sealed

    def unwrap(self, data: bytes) -> bytes:
        if not self.complete:
            raise RuntimeError("NTLM handshake not complete")
        if len(data) < _NTLM_SIGNATURE_LEN:
            raise ValueError("wrapped message too short for NTLM signature")

        signature = data[:_NTLM_SIGNATURE_LEN]
        ciphertext = data[_NTLM_SIGNATURE_LEN:]

        # Fail-fast on the version field so a rejected garbage message does not
        # advance the RC4 keystream and desync the stream permanently.
        if signature[:4] != _NTLM_SIG_VERSION:
            raise ValueError("bad NTLM signature version")

        seq_num = struct.unpack("<I", signature[12:16])[0]
        if seq_num != self._server_seq:
            raise ValueError(
                f"bad NTLM sequence number: got {seq_num}, expected {self._server_seq}")

        plaintext = self._server_handle(ciphertext)

        expected_checksum_encrypted = self._server_handle(
            _impacket_ntlm.hmac_md5(
                self._server_sign_key,
                struct.pack("<I", self._server_seq) + plaintext,
            )[:8]
        )
        checksum = signature[4:12]
        if checksum != expected_checksum_encrypted:
            raise ValueError("bad NTLM signature checksum")

        self._server_seq += 1
        return plaintext
