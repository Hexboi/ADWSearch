# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Credentials model + ``--hashes`` parser.

Only what the NTLM (Phase 3b) and Kerberos (Phase 3c) SecurityContexts need to construct
themselves: username / domain / workstation and either password or NT (+ optional LM) hash.
"""

from dataclasses import dataclass


@dataclass
class Credentials:
    username: str
    domain: str = ""
    password: str = ""
    lmhash: bytes = b""
    nthash: bytes = b""
    aes_key: bytes = b""       # for Kerberos AES pre-auth (raw bytes, 16 or 32 bytes)
    workstation: str = ""


def parse_hashes(hashes: str) -> tuple[bytes, bytes]:
    """Parse an impacket-style ``LM:NT`` (or ``:NT``) hex hash pair.

    Returns ``(lmhash, nthash)`` as bytes. Empty halves yield ``b""``.
    Raises ``ValueError`` when the string is missing the ``:`` separator or contains
    non-hex characters.
    """
    if hashes.count(":") != 1:
        raise ValueError("expected 'LM:NT' hex format (missing ':')")
    lm_hex, nt_hex = hashes.split(":", 1)
    if len(nt_hex) != 32 or (lm_hex and len(lm_hex) != 32):
        raise ValueError("NT must be 16 bytes; LM must be empty or 16 bytes")
    lmhash, nthash = bytes.fromhex(lm_hex), bytes.fromhex(nt_hex)
    if len(nthash) != 16 or (lmhash and len(lmhash) != 16):
        raise ValueError("each nonempty hash must decode to 16 bytes")
    return lmhash, nthash
