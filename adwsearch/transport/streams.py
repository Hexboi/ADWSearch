# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Small stream adapters used by the connection layer.

- ``SocketStream`` wraps a socket as a RawStream (``sendall`` + blocking ``recv_exact``).
- ``FramingReader`` adapts any ``read_exact(n)`` source to the byte / MultiByteInt31 reader
  interface that ``nmf.read_record`` expects, so NMF records can be read straight off a
  socket or off the NNS-secured stream.
"""


class SocketStream:
    def __init__(self, sock):
        self.sock = sock

    def sendall(self, data) -> None:
        self.sock.sendall(data)

    def recv_exact(self, n: int) -> bytes:
        chunks = []
        got = 0
        while got < n:
            chunk = self.sock.recv(n - got)
            if not chunk:
                raise EOFError("socket closed while expecting more data")
            chunks.append(chunk)
            got += len(chunk)
        return b"".join(chunks)

    def close(self) -> None:
        """Close the underlying socket. Best-effort; secondary errors are swallowed."""
        try:
            self.sock.close()
        except Exception:
            pass


class FramingReader:
    def __init__(self, read_exact):
        self._read_exact = read_exact

    def read_byte(self) -> int:
        return self._read_exact(1)[0]

    def read_bytes(self, n: int) -> bytes:
        return self._read_exact(n)

    def read_multibyteint31(self) -> int:
        value = 0
        shift = 0
        while True:
            byte = self.read_byte()
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
