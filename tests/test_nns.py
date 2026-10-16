# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import pytest

from adwsearch.transport import nns


class FakeStream:
    """In-memory bidirectional stream for tests."""

    def __init__(self, incoming=b""):
        self.incoming = bytearray(incoming)
        self.outgoing = bytearray()

    def sendall(self, data):
        self.outgoing += data

    def recv_exact(self, n):
        if len(self.incoming) < n:
            raise EOFError("fake stream exhausted")
        chunk = bytes(self.incoming[:n])
        del self.incoming[:n]
        return chunk


class XorContext:
    """A fake SecurityContext: wrap/unwrap are a reversible XOR; handshake is scripted."""

    def __init__(self, out_tokens):
        # out_tokens: list of (token_or_None, complete_after) returned by successive step()
        self._out = list(out_tokens)
        self._i = 0
        self.complete = False
        self.seen = []

    def step(self, in_token):
        self.seen.append(in_token)
        token, complete = self._out[self._i]
        self._i += 1
        self.complete = complete
        return token

    def wrap(self, data):
        return bytes(b ^ 0x5A for b in data)

    def unwrap(self, data):
        return bytes(b ^ 0x5A for b in data)


# --- framing: exact bytes (MS-NNS) ---

def test_build_handshake_in_progress_with_payload():
    # MessageId 0x16, Major 1, Minor 0, size 0x0003 big-endian, payload
    assert nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, b"tok") == \
        bytes([0x16, 0x01, 0x00, 0x00, 0x03]) + b"tok"


def test_build_handshake_done_empty():
    assert nns.build_handshake_message(nns.HANDSHAKE_DONE, b"") == \
        bytes([0x14, 0x01, 0x00, 0x00, 0x00])


def test_build_data_message_little_endian_length():
    """MS-NNS 2.2.2 PayloadSize is a 4-byte little-endian uint, not big-endian.
    Regression guard after the live-DC fix."""
    assert nns.build_data_message(b"abcd") == bytes([0x04, 0x00, 0x00, 0x00]) + b"abcd"


# --- handshake choreography (NTLM-style: InProgress(T1) then Done(T3)) ---

def test_handshake_ntlm_flow():
    # server preloaded responses: InProgress(T2), then Done(empty)
    server = (
        nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, b"T2")
        + nns.build_handshake_message(nns.HANDSHAKE_DONE, b"")
    )
    stream = FakeStream(incoming=server)
    ctx = XorContext([(b"T1", False), (b"T3", True)])
    ns = nns.NegotiateStream(stream, ctx)

    ns.handshake()

    assert ctx.complete
    assert ctx.seen == [None, b"T2"]  # step(None)->T1, step(T2)->T3
    assert bytes(stream.outgoing) == (
        nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, b"T1")
        + nns.build_handshake_message(nns.HANDSHAKE_DONE, b"T3")
    )


def test_handshake_error_raises():
    server = nns.build_handshake_message(nns.HANDSHAKE_ERROR, bytes(4) + (0x8009030C).to_bytes(4, "little"))
    stream = FakeStream(incoming=server)
    ctx = XorContext([(b"T1", False)])
    ns = nns.NegotiateStream(stream, ctx)
    with pytest.raises(nns.NnsHandshakeError):
        ns.handshake()


def test_server_done_without_output_goes_directly_to_data():
    # Break caught: an extra empty client HandshakeDone corrupts the data stream.
    stream = FakeStream(nns.build_handshake_message(nns.HANDSHAKE_DONE, b"APREP")
                        + b"\x01\x00\x00\x00Z")
    ctx = XorContext([(b"APREQ", False), (None, True)])
    ns = nns.NegotiateStream(stream, ctx)
    ns.handshake()
    assert bytes(stream.outgoing) == b"\x16\x01\x00\x00\x05APREQ"
    assert ns.read_exact(1) == b"\x00"


@pytest.mark.parametrize('complete,output', [(False, None), (True, b"unexpected")])
def test_server_done_rejects_unfinished_or_residual_context(complete, output):
    stream = FakeStream(nns.build_handshake_message(nns.HANDSHAKE_DONE, b"final"))
    ctx = XorContext([(b"initial", False), (output, complete)])
    with pytest.raises(ValueError):
        nns.NegotiateStream(stream, ctx).handshake()


@pytest.mark.parametrize('header', [b'\x17\x01\x00\x00\x00',
                                  b'\x14\x02\x00\x00\x00',
                                  b'\x14\x01\x01\x00\x00'])
def test_invalid_terminal_id_or_version_rejected(header):
    stream = FakeStream(nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, b"T2") + header)
    ctx = XorContext([(b"T1", False), (b"T3", True)])
    with pytest.raises(ValueError):
        nns.NegotiateStream(stream, ctx).handshake()


def test_inprogress_is_not_a_final_peer_acknowledgment():
    stream = FakeStream(nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, b"T2")
                        + nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, b""))
    ctx = XorContext([(b"T1", False), (b"T3", True)])
    with pytest.raises(ValueError):
        nns.NegotiateStream(stream, ctx).handshake()


def test_residual_token_after_client_done_is_rejected():
    stream = FakeStream(nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, b"T2")
                        + nns.build_handshake_message(nns.HANDSHAKE_DONE, b"final"))
    ctx = XorContext([(b"T1", False), (b"T3", True), (b"extra", True)])
    with pytest.raises(ValueError):
        nns.NegotiateStream(stream, ctx).handshake()


@pytest.mark.parametrize('terminal', [
    bytes.fromhex('a1073005a0030a0102'),  # explicit SPNEGO reject
    b'garbage',
    bytes.fromhex('a1093007a205040378797a'),  # residual mechanism response
    bytes.fromhex('a1073005a0030a0100') + b'x',
])
def test_real_ntlm_rejects_invalid_server_completion(terminal):
    from adwsearch.auth.credentials import Credentials
    from adwsearch.auth.ntlm import NtlmSecurityContext
    from tests.test_ntlm_security import (_build_server_type2,
                                          _wrap_server_challenge_in_spnego)

    challenge = _wrap_server_challenge_in_spnego(_build_server_type2())
    stream = FakeStream(nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, challenge)
                        + nns.build_handshake_message(nns.HANDSHAKE_DONE, terminal))
    ctx = NtlmSecurityContext(Credentials('alice', 'CORP', 'synthetic-password'))
    with pytest.raises(ValueError):
        nns.NegotiateStream(stream, ctx).handshake()


@pytest.mark.parametrize('terminal', [b'', bytes.fromhex('a1073005a0030a0100')])
def test_real_ntlm_accepts_valid_server_completion(terminal):
    from adwsearch.auth.credentials import Credentials
    from adwsearch.auth.ntlm import NtlmSecurityContext
    from tests.test_ntlm_security import (_build_server_type2,
                                          _wrap_server_challenge_in_spnego)

    challenge = _wrap_server_challenge_in_spnego(_build_server_type2())
    stream = FakeStream(nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, challenge)
                        + nns.build_handshake_message(nns.HANDSHAKE_DONE, terminal))
    ctx = NtlmSecurityContext(Credentials('alice', 'CORP', 'synthetic-password'))
    ns = nns.NegotiateStream(stream, ctx)
    ns.handshake()
    assert ctx.complete
    before = len(stream.outgoing)
    ns.write(b'application-data')
    assert len(stream.outgoing) > before


# --- data phase: wrap + frame, and read + unwrap ---

def test_write_wraps_and_frames():
    stream = FakeStream()
    ctx = XorContext([])
    ns = nns.NegotiateStream(stream, ctx)
    ns.write(b"hello")
    wrapped = ctx.wrap(b"hello")
    assert bytes(stream.outgoing) == nns.build_data_message(wrapped)


def test_write_chunks_large_payloads():
    stream = FakeStream()
    ctx = XorContext([])
    ns = nns.NegotiateStream(stream, ctx, max_chunk=4)
    ns.write(b"abcdefgh")
    expected = (
        nns.build_data_message(ctx.wrap(b"abcd"))
        + nns.build_data_message(ctx.wrap(b"efgh"))
    )
    assert bytes(stream.outgoing) == expected


def test_read_exact_unwraps_across_frames():
    ctx = XorContext([])
    incoming = (
        nns.build_data_message(ctx.wrap(b"foo"))
        + nns.build_data_message(ctx.wrap(b"bar"))
    )
    ns = nns.NegotiateStream(FakeStream(incoming=incoming), ctx)
    assert ns.read_exact(6) == b"foobar"


def test_roundtrip_write_then_read():
    ctx = XorContext([])
    sender = nns.NegotiateStream(FakeStream(), ctx, max_chunk=4)
    sender.write(b"the quick brown fox")
    receiver = nns.NegotiateStream(FakeStream(incoming=bytes(sender.raw.outgoing)), ctx)
    assert receiver.read_exact(len(b"the quick brown fox")) == b"the quick brown fox"
