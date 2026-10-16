# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Kerberos NNS context with explicit session-key policy and replay protection.

Exact service tickets come from a matching cache or explicit TGS exchange.
The authenticated AP-REP seeds receive sequence state before adopting its
subkey. AES uses RFC4121 tokens; explicitly permitted RC4 uses the separate
authenticated RFC4757 backend, never impacket's unauthenticated RC4 unwrap.
"""

import logging
import hmac
import struct

from impacket.krb5 import kerberosv5 as _krb5
from pyasn1.error import PyAsn1Error

from adwsearch.auth.kerberos_ticket import _allowed, load_service_ticket, resolve_spn
from adwsearch.auth import kerberos_rc4 as rc4
from adwsearch.auth.kerberos_mutual import mutual_exchange as _mutual_exchange
from adwsearch.auth.kerberos_mutual import initial_timestamp as _initial_timestamp
from adwsearch.auth.kerberos_mutual import standard_initial_token, verify_completion


# RFC 4121 GSS-Wrap header (16 bytes): TOK_ID(2) + Flags(1) + Filler(1) + EC(2) +
# RRC(2) + SND_SEQ(8, big-endian). We use SND_SEQ for anti-replay / ordering checks
# because impacket's ``GSS_Unwrap_LDAP`` ignores the caller-supplied sequence number.
_GSS_WRAP_HEADER_LEN = 16
_GSS_WRAP_TOK_ID = b"\x05\x04"

class KerberosAuthenticationError(RuntimeError):
    """Sanitized failure suitable for reporting at the CLI boundary."""


class KerberosSecurityContext:
    def __init__(self, credentials, target_host: str, kdc_host: str | None = None,
                 *, spn: str | None = None, policy="aes", timeout=30):
        _allowed(policy)
        self.policy = policy
        self.timeout = timeout
        self._session_etypes = (18, 17)
        self._initiator_timestamp = None
        self._acceptor_subkey = True
        self._dce_style = True
        self.credentials = credentials
        self.target_host = target_host
        self.kdc_host = kdc_host
        self.spn = resolve_spn(target_host, spn)
        self._explicit_spn = spn is not None
        self.complete = False
        self._state = "init"
        self._cipher = None
        self._session_key = None
        # Client authenticator starts outbound sequence at zero. The acceptor
        # independently chooses receive sequence in its authenticated AP-REP.
        self._send_seq = 0
        self._recv_seq = 0

    # -- handshake ----------------------------------------------------------

    def step(self, in_token):
        if self._state == "init":
            return self._make_initial_token()
        if self._state == "mutual":
            return self._make_mutual_response(in_token)
        if in_token:
            try:
                verify_completion(in_token)
            except (ValueError, PyAsn1Error) as exc:
                raise KerberosAuthenticationError('invalid Kerberos completion acknowledgment') from exc
        return None

    def _make_initial_token(self) -> bytes:
        try:
            ticket_options = {"TGS": load_service_ticket(
                self.credentials, self.spn, self.kdc_host,
                policy=self.policy, timeout=self.timeout)}
        except (ValueError, KeyError, struct.error, OSError) as exc:
            raise KerberosAuthenticationError("Kerberos cache unavailable or inconsistent") from exc
        cipher, session_key, blob = _krb5.getKerberosType1(
            self.credentials.username,
            self.credentials.password,
            self.credentials.domain,
            self.credentials.lmhash,
            self.credentials.nthash,
            aesKey=self.credentials.aes_key,
            targetName=self.target_host,
            kdcHost=self.kdc_host,
            useCache=False,
            **ticket_options,
        )
        allowed = (18, 17, 23) if self.policy == "auto" else _allowed(self.policy)
        if getattr(cipher, "enctype", None) not in allowed:
            raise KerberosAuthenticationError("Kerberos session enctype violates policy (RC4 requires explicit permission)")
        self._session_etypes = (23,) if cipher.enctype == 23 else (18, 17)
        if cipher.enctype == 23:
            logging.getLogger(__name__).warning("Kerberos: using explicitly permitted legacy RC4-HMAC")
            try:
                blob = standard_initial_token(cipher, session_key, blob)
            except (ValueError, PyAsn1Error, KeyError, IndexError, struct.error) as exc:
                raise KerberosAuthenticationError('invalid Kerberos initial authenticator') from exc
            self._dce_style = False
        self._cipher = cipher
        self._session_key = session_key
        self._initiator_timestamp = _initial_timestamp(cipher, session_key, blob)
        self._state = "mutual"
        return blob

    def _make_mutual_response(self, in_token: bytes) -> bytes | None:
        try:
            new_cipher, new_session_key, response, sequence = _mutual_exchange(
                self._cipher, self._session_key, in_token, self._session_etypes,
                self._initiator_timestamp, dce_style=self._dce_style)
        except (ValueError, PyAsn1Error, KeyError, IndexError, struct.error) as exc:
            raise KerberosAuthenticationError("Kerberos mutual authentication integrity or policy failure") from exc
        if getattr(new_cipher, "enctype", None) not in self._session_etypes:
            raise KerberosAuthenticationError("Kerberos mutual authentication enctype violates negotiated policy; RC4 downgrade refused")
        self._acceptor_subkey = new_session_key is not self._session_key
        self._cipher = new_cipher
        self._session_key = new_session_key
        self._recv_seq = sequence
        self._state = "done"
        self.complete = True
        return response

    # -- sign + seal --------------------------------------------------------

    def wrap(self, data: bytes) -> bytes:
        if not self.complete:
            raise RuntimeError("Kerberos handshake not complete")
        if self._cipher.enctype == 23:
            token = rc4.wrap(self._session_key.contents, data, self._send_seq)
            self._send_seq += 1
            return token
        if self._send_seq >= 2**64:
            raise ValueError("Kerberos send sequence exhausted")
        flags = 6 if self._acceptor_subkey else 2
        protected_header = struct.pack('>2sBBHHQ', b'\x05\x04', flags, 255, 0, 0, self._send_seq)
        ciphertext = self._cipher.encrypt(self._session_key, 24, data + protected_header, None)
        rotation = 28 % len(ciphertext)
        ciphertext = ciphertext[-rotation:] + ciphertext[:-rotation]
        header = protected_header[:6] + struct.pack('>H', 28) + protected_header[8:]
        self._send_seq += 1
        return header + ciphertext

    def unwrap(self, data: bytes) -> bytes:
        if not self.complete:
            raise RuntimeError("Kerberos handshake not complete")
        if self._cipher.enctype == 23:
            plaintext = rc4.unwrap(self._session_key.contents, data, self._recv_seq)
            self._recv_seq += 1
            return plaintext
        if self._recv_seq >= 2**64:
            raise ValueError("Kerberos receive sequence exhausted")
        if len(data) < _GSS_WRAP_HEADER_LEN:
            raise ValueError("wrapped message too short for GSS-Wrap header")
        if data[:2] != _GSS_WRAP_TOK_ID:
            raise ValueError(
                f"bad GSS-Wrap TOK_ID: got {data[:2].hex()}, expected 0504")

        # Fail-fast on the wire sequence number: impacket's GSS_Unwrap_LDAP does not
        # verify it, so a MITM could otherwise replay a valid past frame silently.
        snd_seq = struct.unpack(">Q", data[8:16])[0]
        if snd_seq != self._recv_seq:
            raise ValueError(
                f"bad Kerberos seq: got {snd_seq}, expected {self._recv_seq}")

        expected_flags = 7 if self._acceptor_subkey else 3
        if data[2] != expected_flags or data[3] != 255:
            raise ValueError('invalid Kerberos sealed acceptor flags or filler')
        ec, rrc = struct.unpack('>HH', data[4:8])
        ciphertext = data[16:]
        if not ciphertext:
            raise ValueError('missing Kerberos ciphertext')
        rotation = (rrc + ec) % len(ciphertext)
        ciphertext = ciphertext[rotation:] + ciphertext[:rotation]
        plaintext = self._cipher.decrypt(self._session_key, 22, ciphertext)
        protected_header = data[:6] + b'\x00\x00' + data[8:16]
        if len(plaintext) < 16 + ec or not hmac.compare_digest(plaintext[-16:], protected_header):
            raise ValueError('Kerberos authenticated header mismatch')
        self._recv_seq += 1
        return plaintext[:len(plaintext) - 16 - ec]
