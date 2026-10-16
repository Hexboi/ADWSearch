# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Authenticated RFC4757 sealed GSS tokens for explicit legacy Kerberos use.

Unlike impacket's RC4 LDAP unwrap, authenticate the recovered plaintext before
returning it. Direction octets and usage 13 follow deployed Windows semantics
(RFC4757 with errata), also checked against independent impacket sender vectors.
"""

import hashlib
import hmac
import secrets
import struct

from Cryptodome.Cipher import ARC4

_OID = bytes.fromhex('06092a864886f712010202')
_HEADER = bytes.fromhex('020111001000ffff')


def _mac(key, data):
    return hmac.new(key, data, hashlib.md5).digest()


def _length(size):
    if size < 128:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([128 + len(raw)]) + raw


def _token(data):
    if len(data) < 2 or data[0] != 0x60:
        raise ValueError('invalid RC4 GSS envelope')
    size, offset = data[1], 2
    if size >= 128:
        count = size & 127
        if not 1 <= count <= 4 or len(data) < 2 + count or data[2] == 0:
            raise ValueError('invalid RC4 GSS length')
        size = int.from_bytes(data[2:2 + count], 'big')
        offset += count
        if size < 128:
            raise ValueError('noncanonical RC4 GSS length')
    if offset + size != len(data) or data[offset:offset + len(_OID)] != _OID:
        raise ValueError('invalid RC4 GSS length or mechanism')
    body = data[offset + len(_OID):]
    if len(body) < 33 or body[:8] != _HEADER:
        raise ValueError('invalid RC4 sealed token header')
    return body


def _check(key, sequence, direction):
    if len(key) != 16 or not 0 <= sequence < 2**32:
        raise ValueError('invalid RC4 key or exhausted sequence')
    if direction not in ('init', 'accept'):
        raise ValueError('invalid RC4 direction')


def _sequence_key(key, checksum):
    return _mac(_mac(key, b'\x00' * 4), checksum)


def _sealing_key(key, sequence_bytes):
    local = bytes(x ^ 0xf0 for x in key)
    return _mac(_mac(local, b'\x00' * 4), sequence_bytes)


def _checksum(key, confounder, padded):
    signing = _mac(key, b'signaturekey\x00')
    digest = hashlib.md5(struct.pack('<I', 13) + _HEADER + confounder + padded).digest()
    return _mac(signing, digest)[:8]


def wrap(key: bytes, data: bytes, sequence: int, *, direction='init') -> bytes:
    _check(key, sequence, direction)
    seq = struct.pack('>I', sequence)
    direction_bytes = b'\x00' * 4 if direction == 'init' else b'\xff' * 4
    confounder = secrets.token_bytes(8)
    padded = data + b'\x01'
    checksum = _checksum(key, confounder, padded)
    encrypted_sequence = ARC4.new(_sequence_key(key, checksum)).encrypt(seq + direction_bytes)
    encrypted = ARC4.new(_sealing_key(key, seq)).encrypt(confounder + padded)
    body = _OID + _HEADER + encrypted_sequence + checksum + encrypted
    return b'\x60' + _length(len(body)) + body


def unwrap(key: bytes, data: bytes, sequence: int, *, direction='accept') -> bytes:
    _check(key, sequence, direction)
    body = _token(data)
    checksum = body[16:24]
    decoded_seq = ARC4.new(_sequence_key(key, checksum)).decrypt(body[8:16])
    plain = ARC4.new(_sealing_key(key, decoded_seq[:4])).decrypt(body[24:])
    confounder, padded = plain[:8], plain[8:]
    # Never release unauthenticated data or accept a reflected initiator token.
    expected_seq = struct.pack('>I', sequence) + (b'\x00' * 4 if direction == 'init' else b'\xff' * 4)
    if not hmac.compare_digest(checksum, _checksum(key, confounder, padded)):
        raise ValueError('bad RC4 integrity checksum')
    if not hmac.compare_digest(decoded_seq, expected_seq):
        raise ValueError('bad RC4 sequence or direction')
    if not padded or padded[-1:] != b'\x01':
        raise ValueError('invalid RC4 padding')
    return padded[:-1]
