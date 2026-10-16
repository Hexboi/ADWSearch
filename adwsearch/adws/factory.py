# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""``connect_adws(host, port, security, ...)`` — the one call the CLI uses to open a
ready-to-query ADWS connection.

Opens a plain TCP socket to the DC, wraps it as a SocketStream, builds an AdwsConnection
with the caller-provided SecurityContext (NTLM / Kerberos), drives the full net.tcp +
NNS handshake, and returns the connected ``AdwsConnection``. The socket factory is
injected so tests can plug in a scripted FakeSock and Phase 5 can plug in a SOCKS5
tunnel.
"""

import socket

from adwsearch.transport.connection import AdwsConnection
from adwsearch.transport.streams import SocketStream


ADWS_DEFAULT_ENDPOINT = "Windows/Enumeration"


def _default_socket_factory(host: str, port: int, timeout: float = 30.0):
    return socket.create_connection((host, port), timeout=timeout)


def connect_adws(host, port, security, *,
                 endpoint: str = ADWS_DEFAULT_ENDPOINT,
                 socket_factory=None, timeout: float = 30.0) -> AdwsConnection:
    sock = (socket_factory(host, port) if socket_factory else
            _default_socket_factory(host, port, timeout))
    try:
        sock.settimeout(timeout)
        via = f"net.tcp://{host}:{port}/ActiveDirectoryWebServices/{endpoint}"
        conn = AdwsConnection(SocketStream(sock), security, via)
        conn.connect()
        return conn
    except BaseException:
        # Handshake failed — don't leak the underlying socket. Swallow secondary
        # close errors so the caller sees the original failure.
        try:
            sock.close()
        except Exception:
            pass
        raise
