# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Exercise real PySocks negotiation without contacting a proxy or a DC."""

from io import BytesIO
import sys
from types import SimpleNamespace

import pytest
import socks

from adwsearch import cli


def test_help_shows_socks4_forest_level_example():
    help_text = cli.build_parser().format_help()
    assert "--socks socks4://127.0.0.1:8443 --preset forest-level" in help_text


class ScriptedSocket(socks.socksocket):
    def __init__(self, response):
        super().__init__()
        self.response = response
        self.sent = b""

    def makefile(self, mode, *args):
        if mode == "rb":
            return BytesIO(self.response)
        owner = self

        class Writer(BytesIO):
            def close(self):
                owner.sent = self.getvalue()
                super().close()

        return Writer()

    def connect(self, address):
        if self.proxy[0] == socks.SOCKS4:
            self._negotiate_SOCKS4(*address)
        else:
            self._negotiate_SOCKS5(*address)


@pytest.mark.parametrize("proxy, response, expected_request", [
    ("127.0.0.1:8443", b"\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00",
     b"\x05\x01\x00\x05\x01\x00\x01\xc0\x00\x02\x0a\x24\xad"),
    ("socks5://127.0.0.1:8443", b"\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00",
     b"\x05\x01\x00\x05\x01\x00\x01\xc0\x00\x02\x0a\x24\xad"),
    ("socks4://127.0.0.1:8443", b"\x00\x5a\x00\x00\x7f\x00\x00\x01",
     b"\x04\x01\x24\xad\xc0\x00\x02\x0a\x00"),
])
def test_socks_sends_dc_ip_and_adws_port(monkeypatch, proxy, response, expected_request):
    sock = ScriptedSocket(response)
    monkeypatch.setitem(sys.modules, "socks", SimpleNamespace(
        SOCKS4=socks.SOCKS4, SOCKS5=socks.SOCKS5, socksocket=lambda: sock, ProxyError=socks.ProxyError))
    try:
        assert cli._build_socks_factory(proxy, 3)("192.0.2.10", 9389) is sock
        assert sock.sent == expected_request
    finally:
        sock.close()


@pytest.mark.parametrize("proxy", [
    "http://127.0.0.1:8443", "socks6://127.0.0.1:8443",
    "socks4://:8443", "socks4://127.0.0.1:0", "socks4://127.0.0.1:65536",
    "socks4://127.0.0.1:8443/path", "socks5://user:password@127.0.0.1:8443",
])
def test_invalid_proxy_fails_before_connect(monkeypatch, proxy, capsys):
    monkeypatch.setattr(cli, "connect_adws", lambda *a, **kw: pytest.fail("network"))
    with pytest.raises(SystemExit) as exc:
        cli.main(["-H", "dc", "-w", "synthetic-secret", "--socks", proxy])
    assert exc.value.code == 2
    assert "--socks" in capsys.readouterr().err


def test_socks4_cli_wiring_and_dry_run(monkeypatch, capsys):
    def connect(host, port, security, **kw):
        assert (host, port) == ("192.0.2.10", 9389)
        sock = ScriptedSocket(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
        monkeypatch.setitem(sys.modules, "socks", SimpleNamespace(
            SOCKS4=socks.SOCKS4, SOCKS5=socks.SOCKS5, socksocket=lambda: sock))
        try:
            kw["socket_factory"](host, port)
        finally:
            sock.close()

    monkeypatch.setattr(cli, "connect_adws", connect)
    args = ["-H", "dc", "--dc-ip", "192.0.2.10", "-w", "synthetic-secret",
            "--socks", "socks4://127.0.0.1:8443", "--preset", "forest-level"]
    assert cli.main(args + ["--dry-run"]) == 0
    assert "socks4://127.0.0.1:8443" in capsys.readouterr().out
    assert cli.main(args) == 1
    error = capsys.readouterr().err
    assert "Request rejected or failed" in error
    assert "SOCKS5" not in error
    assert "synthetic-secret" not in error


@pytest.mark.parametrize("response, reason", [
    (b"", "Connection closed unexpectedly"),
    (b"HT", "SOCKS5 proxy server sent invalid data"),
    (b"\x05\xff", "authentication methods were rejected"),
    (b"\x05\x02", "No username/password supplied"),
    (b"\x05\x00\x05\x05\x00", "Connection refused"),
])
def test_cli_preserves_proxy_failure_reason(monkeypatch, capsys, response, reason):
    sock = ScriptedSocket(response)
    monkeypatch.setitem(sys.modules, "socks", SimpleNamespace(
        SOCKS4=socks.SOCKS4, SOCKS5=socks.SOCKS5, socksocket=lambda: sock, ProxyError=socks.ProxyError))
    try:
        result = cli.main(["-H", "dc.example", "--dc-ip", "192.0.2.10",
                           "--socks", "127.0.0.1:8443", "-u", "alice",
                           "-w", "synthetic-secret", "--preset", "forest-level"])
        assert result == 1
        output = capsys.readouterr()
        assert "SOCKS" in output.err
        assert reason in output.err
        assert "synthetic-secret" not in output.err
        assert output.out == ""
    finally:
        sock.close()
