# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""connect_adws(host, port, security, ...) factory: opens the socket, wraps it as a
SocketStream, builds an AdwsConnection and drives its handshake.

Verified with an injected ``socket_factory`` returning a scripted FakeSock and an XOR
SecurityContext — same offline harness used in test_connection.py.
"""

from adwsearch.adws.factory import ADWS_DEFAULT_ENDPOINT, connect_adws
from adwsearch.transport import nbf, nmf, nns
from adwsearch.transport.connection import AdwsConnection
from adwsearch.transport.nbf.records import EndElement, StartElement


def xor(data):
    return bytes(b ^ 0x5A for b in data)


class FakeSock:
    def __init__(self, data=b""):
        self.inb = bytearray(data)
        self.outb = bytearray()
        self.closed = False

    def recv(self, n):
        chunk = bytes(self.inb[:n])
        del self.inb[:len(chunk)]
        return chunk

    def sendall(self, d):
        self.outb += d

    def close(self):
        self.closed = True

    def settimeout(self, timeout):
        self.timeout = timeout


class XorContext:
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


def _scripted_server_bytes():
    return (
        bytes([nmf.RT_UPGRADE_RESPONSE])
        + nns.build_handshake_message(nns.HANDSHAKE_IN_PROGRESS, b"T2")
        + nns.build_handshake_message(nns.HANDSHAKE_DONE, b"")
        + nns.build_data_message(xor(bytes([nmf.RT_PREAMBLE_ACK])))
    )


def test_connect_adws_calls_socket_factory_with_host_port():
    sock = FakeSock(_scripted_server_bytes())
    calls = []

    def factory(host, port):
        calls.append((host, port))
        return sock

    connect_adws("dc01", 9389, XorContext(), socket_factory=factory)

    assert calls == [("dc01", 9389)]


def test_connect_adws_returns_a_connected_adws_connection():
    sock = FakeSock(_scripted_server_bytes())
    conn = connect_adws("dc01", 9389, XorContext(), socket_factory=lambda h, p: sock)

    assert isinstance(conn, AdwsConnection)
    # A connected AdwsConnection has an NNS stream in place after connect().
    assert conn.nns is not None
    # Client sent Preamble (starts with NMF Version record 0x00 0x01 0x00)
    assert bytes(sock.outb[:3]) == b"\x00\x01\x00"


def test_connect_adws_builds_default_enumeration_via_url_from_host_port():
    sock = FakeSock(_scripted_server_bytes())
    conn = connect_adws("dc01", 9389, XorContext(), socket_factory=lambda h, p: sock)

    assert conn.via == (
        f"net.tcp://dc01:9389/ActiveDirectoryWebServices/{ADWS_DEFAULT_ENDPOINT}"
    )


def test_connect_adws_accepts_endpoint_override():
    sock = FakeSock(_scripted_server_bytes())
    conn = connect_adws("dc01", 9389, XorContext(),
                        endpoint="Windows/Resource",
                        socket_factory=lambda h, p: sock)

    assert conn.via.endswith("/ActiveDirectoryWebServices/Windows/Resource")


def test_connect_adws_closes_socket_when_handshake_fails():
    # Server sends an unexpected first record so connect() raises.
    sock = FakeSock(bytes([0xFF]))  # not RT_UPGRADE_RESPONSE
    with __import__("pytest").raises(Exception):
        connect_adws("dc01", 9389, XorContext(),
                     socket_factory=lambda h, p: sock)
    assert sock.closed is True


def test_connect_adws_can_round_trip_a_request_after_handshake():
    request_records = [StartElement("s", "Envelope"), EndElement()]
    response_records = [StartElement("s", "Envelope"), EndElement()]

    server_bytes = (
        _scripted_server_bytes()
        + nns.build_data_message(xor(nmf.sized_envelope_record(
            nbf.encode_message(response_records))))
    )
    sock = FakeSock(server_bytes)

    conn = connect_adws("dc01", 9389, XorContext(),
                        socket_factory=lambda h, p: sock)
    result = conn.request(request_records)

    assert result == response_records
