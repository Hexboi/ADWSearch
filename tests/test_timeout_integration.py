# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Real loopback server: accept TCP, then stall handshake or a secured request."""

import socket
import threading
import time

import pytest

from adwsearch.adws.factory import connect_adws
from adwsearch.transport.nbf.records import EndElement, StartElement
from test_factory import XorContext, _scripted_server_bytes


@pytest.mark.parametrize("phase", ["handshake", "request"])
def test_accepted_but_stalled_peer_times_out_and_closes(phase):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    address = listener.getsockname()
    stop = threading.Event()
    errors = []
    sockets = []
    def server():
        try:
            with listener.accept()[0] as peer:
                if phase == "request":
                    peer.sendall(_scripted_server_bytes())
                stop.wait(2)
        except Exception as exc:
            errors.append(exc)
    worker = threading.Thread(target=server, daemon=True)
    worker.start()
    def dial(host, port):
        sock = socket.create_connection((host, port), timeout=1)
        sockets.append(sock)
        return sock
    start = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            with connect_adws(address[0], address[1], XorContext(),
                              socket_factory=dial, timeout=0.15) as connection:
                connection.request([StartElement("s", "Envelope"), EndElement()])
        assert time.monotonic() - start < 2
        assert sockets[0].fileno() == -1
    finally:
        stop.set()
        worker.join(3)
        listener.close()
    assert not errors
