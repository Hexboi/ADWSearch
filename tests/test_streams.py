# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import pytest

from adwsearch.transport.nbf.primitives import encode_multibyteint31
from adwsearch.transport.streams import FramingReader, SocketStream


class FakeSock:
    def __init__(self, data=b""):
        self.inb = bytearray(data)
        self.outb = bytearray()

    def recv(self, n):
        chunk = bytes(self.inb[:min(n, 2)])  # cap at 2 to force multi-recv assembly
        del self.inb[:len(chunk)]
        return chunk

    def sendall(self, d):
        self.outb += d


def test_socketstream_recv_exact_assembles_across_recvs():
    s = SocketStream(FakeSock(b"abcdef"))
    assert s.recv_exact(3) == b"abc"
    assert s.recv_exact(3) == b"def"


def test_socketstream_recv_exact_raises_on_close():
    s = SocketStream(FakeSock(b"ab"))
    with pytest.raises(EOFError):
        s.recv_exact(4)


def test_socketstream_sendall_delegates():
    sock = FakeSock()
    SocketStream(sock).sendall(b"xyz")
    assert bytes(sock.outb) == b"xyz"


def test_framing_reader_byte_bytes_mbi31():
    data = bytes([0x41]) + encode_multibyteint31(5521) + b"hello"
    reader = FramingReader(SocketStream(FakeSock(data)).recv_exact)
    assert reader.read_byte() == 0x41
    assert reader.read_multibyteint31() == 5521
    assert reader.read_bytes(5) == b"hello"
