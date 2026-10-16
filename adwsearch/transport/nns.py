# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""MS-NNS: .NET NegotiateStream Protocol.

Runs the SPNEGO/Negotiate handshake over the raw stream (after the NMF Upgrade), then
presents a secure byte-stream (``write`` / ``read_exact``) that signs-and-seals data using
the negotiated security context. ADWS negotiates sign+seal, so data is always framed.

The cryptography and token generation live behind two injected collaborators, so this
module can be unit tested without a live server:

    RawStream       -- the underlying transport: ``sendall(bytes)`` and ``recv_exact(n)->bytes``
    SecurityContext -- ``complete`` flag, ``step(in_token)->out_token|None`` (SPNEGO handshake),
                       and ``wrap(bytes)->bytes`` / ``unwrap(bytes)->bytes`` (seal/unseal)

The impacket-backed SecurityContext (NTLM / pass-the-hash / Kerberos) is provided by the
auth layer (Phase 3).
"""

# Handshake MessageId values (MS-NNS section 2.2.1)
HANDSHAKE_DONE = 0x14
HANDSHAKE_ERROR = 0x15
HANDSHAKE_IN_PROGRESS = 0x16

MAJOR_VERSION = 0x01
MINOR_VERSION = 0x00

# Data Message PayloadSize maximum (MS-NNS section 2.2.2). We chunk plaintext below this so
# the wrapped payload (plaintext + signature overhead) stays within the limit.
MAX_DATA_PAYLOAD = 0xFC30       # 64560
MAX_PLAINTEXT_CHUNK = 0xFC00    # 64512


class NnsHandshakeError(Exception):
    """The server returned a HandshakeError during the NNS handshake."""

    def __init__(self, error_code: int, raw: bytes):
        self.error_code = error_code
        self.raw = raw
        super().__init__(f"NNS handshake failed with error 0x{error_code:08X}")


# --- framing ---------------------------------------------------------------

def build_handshake_message(message_id: int, payload: bytes) -> bytes:
    return bytes([message_id, MAJOR_VERSION, MINOR_VERSION]) + len(payload).to_bytes(2, "big") + payload


def build_data_message(wrapped: bytes) -> bytes:
    # MS-NNS section 2.2.2: the Data Message PayloadSize is a 4-byte LITTLE-endian
    # length prefix (not big-endian). Verified against a live Windows ADWS DC via
    # SOAPy's reference implementation.
    return len(wrapped).to_bytes(4, "little") + wrapped


class NegotiateStream:
    def __init__(self, raw, security, max_chunk: int = MAX_PLAINTEXT_CHUNK):
        self.raw = raw
        self.security = security
        self.max_chunk = max_chunk
        self._buffer = bytearray()

    # -- handshake --
    def handshake(self) -> None:
        token = self.security.step(None)
        while True:
            client_done = self.security.complete
            self._write_handshake(HANDSHAKE_DONE if client_done else HANDSHAKE_IN_PROGRESS,
                                  token or b"")
            message_id, payload = self._read_handshake()
            if message_id == HANDSHAKE_ERROR:
                raise self._handshake_error(payload)
            if message_id == HANDSHAKE_DONE:
                token = self.security.step(payload) if payload else None
                if not self.security.complete or token:
                    raise ValueError("NNS peer completed before security context completion")
                # In a two-leg exchange the server is already in the data phase.
                # Sending another empty HandshakeDone would corrupt that stream.
                return
            if client_done:
                raise ValueError("NNS peer did not acknowledge client completion")
            token = self.security.step(payload)

    def _write_handshake(self, message_id: int, payload: bytes) -> None:
        self.raw.sendall(build_handshake_message(message_id, payload))

    def _read_handshake(self):
        header = self.raw.recv_exact(5)
        if (len(header) != 5 or header[0] not in
                (HANDSHAKE_DONE, HANDSHAKE_ERROR, HANDSHAKE_IN_PROGRESS) or
                header[1:3] != bytes([MAJOR_VERSION, MINOR_VERSION])):
            raise ValueError("invalid NNS handshake header")
        message_id = header[0]
        size = (header[3] << 8) | header[4]
        payload = self.raw.recv_exact(size) if size else b""
        return message_id, payload

    @staticmethod
    def _handshake_error(payload: bytes) -> NnsHandshakeError:
        # AuthPayload = Reserved(4) + ErrorCode(4), HRESULT little-endian.
        error_code = int.from_bytes(payload[4:8], "little") if len(payload) >= 8 else 0
        return NnsHandshakeError(error_code, payload)

    # -- secured data phase --
    def write(self, data: bytes) -> None:
        view = memoryview(data)
        for start in range(0, len(view), self.max_chunk):
            wrapped = self.security.wrap(bytes(view[start:start + self.max_chunk]))
            self.raw.sendall(build_data_message(wrapped))

    def read_exact(self, n: int) -> bytes:
        while len(self._buffer) < n:
            self._read_data_frame()
        result = bytes(self._buffer[:n])
        del self._buffer[:n]
        return result

    def _read_data_frame(self) -> None:
        size = int.from_bytes(self.raw.recv_exact(4), "little")
        self._buffer += self.security.unwrap(self.raw.recv_exact(size))
