# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

from adwsearch.transport import nbf, nmf, nns
from adwsearch.transport.connection import AdwsConnection
from adwsearch.transport.nbf.records import EndElement, StartElement, Text
from adwsearch.transport.streams import SocketStream

VIA = "net.tcp://dc01:9389/ActiveDirectoryWebServices/Windows/Enumeration"


def xor(data):
    return bytes(b ^ 0x5A for b in data)


class FakeSock:
    def __init__(self, data=b""):
        self.inb = bytearray(data)
        self.outb = bytearray()

    def recv(self, n):
        chunk = bytes(self.inb[:n])
        del self.inb[:len(chunk)]
        return chunk

    def sendall(self, d):
        self.outb += d


class XorContext:
    """Fake SecurityContext: XOR seal, scripted NTLM-style handshake (T1 then T3-complete)."""

    def __init__(self):
        self.complete = False

    def step(self, in_token):
        if in_token is None:
            return b"T1"
        self.complete = True
        return b"T3"

    def wrap(self, data):
        return xor(data)

    def unwrap(self, data):
        return xor(data)


def el(prefix, name, children=(), text=None):
    ev = [StartElement(prefix, name)]
    if text is not None:
        ev.append(Text(text))
    for c in children:
        ev += c
    ev.append(EndElement())
    return ev


def test_connect_and_request_full_stack():
    request_records = el("s", "Envelope", [el("s", "Body", [el("wsen", "Ping")])])
    response_records = el("s", "Envelope", [el("s", "Body", [el("wsen", "Pong", text="ok")])])

    # Scripted bytes the server sends, in the order the client consumes them.
    server_bytes = (
        bytes([nmf.RT_UPGRADE_RESPONSE])                                 # NMF UpgradeResponse (raw)
        + nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, b"T2")  # NNS handshake (raw)
        + nns.build_handshake_message(nns.HANDSHAKE_DONE, b"")
        + nns.build_data_message(xor(bytes([nmf.RT_PREAMBLE_ACK])))      # PreambleAck over NNS
        + nns.build_data_message(xor(nmf.sized_envelope_record(nbf.encode_message(response_records))))
    )
    sock = FakeSock(server_bytes)
    conn = AdwsConnection(SocketStream(sock), XorContext(), VIA)

    conn.connect()
    result = conn.request(request_records)

    assert result == response_records

    expected_out = (
        nmf.build_preamble(VIA) + nmf.upgrade_request_record()
        + nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, b"T1")
        + nns.build_handshake_message(nns.HANDSHAKE_DONE, b"T3")
        + nns.build_data_message(xor(nmf.preamble_end_record()))
        + nns.build_data_message(xor(nmf.sized_envelope_record(nbf.encode_message(request_records))))
    )
    assert bytes(sock.outb) == expected_out
