# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""CLI dispatch for --dump modes (Phase 9)."""

from unittest.mock import MagicMock

import pytest

from adwsearch import cli
from adwsearch.dump import Cache
from adwsearch.dump.labels import Label
from adwsearch.transport.connection import AdwsConnection


def test_cli_dump_buildcache_invokes_build_and_serialize(monkeypatch, tmp_path, capsys):
    called = {}

    def fake_build_cache(client, base):
        called["base"] = base
        c = Cache()
        c.value_to_id = {"cn=alice,dc=x": "S-1-5-21-1-1-1-1001"}
        c.id_to_type = {"S-1-5-21-1-1-1-1001": Label.User}
        return c

    monkeypatch.setattr("adwsearch.dump.builder.build_cache", fake_build_cache)
    monkeypatch.setattr("adwsearch.dump.build_cache", fake_build_cache)

    conn = MagicMock(spec=AdwsConnection)
    monkeypatch.setattr(cli, "connect_adws", lambda *a, **kw: conn)
    monkeypatch.setattr(cli, "AdwsClient", MagicMock())

    cache_path = tmp_path / "cache.json"
    rc = cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
        "--dump", "buildcache", "--cachefile", str(cache_path),
    ])
    assert rc == 0
    assert called["base"] == "DC=corp,DC=local"
    assert cache_path.exists()
    out = capsys.readouterr().out
    assert "cache written" in out
    assert "1 objects" in out


def test_cli_dump_showstats_works_offline_without_auth(monkeypatch, tmp_path, capsys):
    cache_path = tmp_path / "cache.json"
    cache_path.write_text(
        '{"ValueToIdCache":{"cn=alice,dc=x":"S-1-5-21-1-2-3-1001",'
        '"cn=bob,dc=x":"S-1-5-21-1-2-3-1002"},'
        '"IdToTypeCache":{"S-1-5-21-1-2-3-1001":"User",'
        '"S-1-5-21-1-2-3-1002":"User"}}',
        encoding="utf-8",
    )

    def guard(*a, **kw):
        raise AssertionError("connect_adws must not be called for --dump showstats")
    monkeypatch.setattr(cli, "connect_adws", guard)

    rc = cli.main(["--dump", "showstats", "--cachefile", str(cache_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "total_objects: 2" in out
    assert "User: 2" in out


def test_cli_dump_with_preset_errors(capsys):
    with pytest.raises(SystemExit):
        cli.main([
            "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
            "--dump", "buildcache", "--preset", "spn",
        ])
    err = capsys.readouterr().err.lower()
    assert "dump" in err and "mutually exclusive" in err


def test_cli_dump_bhdump_dispatches_and_reads_cache(monkeypatch, tmp_path, capsys):
    cache_path = tmp_path / "cache.json"
    cache_path.write_text(
        '{"ValueToIdCache":{"cn=alice,dc=x":"S-1-5-21-1-1-1-1001"},'
        '"IdToTypeCache":{"S-1-5-21-1-1-1-1001":"User"}}',
        encoding="utf-8",
    )
    outdir = tmp_path / "bh-out"

    called = {}

    def fake_bhdump(client, base, out, cache, autosplit=False):
        called["base"] = base
        called["outdir"] = out
        called["cache_size"] = len(cache.value_to_id)
        called["autosplit"] = autosplit
        return {"users": 1, "computers": 0, "groups": 0, "ous": 0,
                "gpos": 0, "containers": 0, "domains": 0}

    import adwsearch.dump as dump_pkg
    monkeypatch.setattr(dump_pkg, "bhdump", fake_bhdump)

    conn = MagicMock(spec=AdwsConnection)
    monkeypatch.setattr(cli, "connect_adws", lambda *a, **kw: conn)
    monkeypatch.setattr(cli, "AdwsClient", MagicMock())

    rc = cli.main([
        "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
        "--dump", "bhdump", "--cachefile", str(cache_path),
        "--outdir", str(outdir),
    ])
    assert rc == 0
    assert called["base"] == "DC=corp,DC=local"
    assert called["outdir"] == str(outdir)
    assert called["cache_size"] == 1
    out = capsys.readouterr().out
    assert "bhdump written" in out


def test_cli_dump_bhdump_without_cachefile_errors(monkeypatch, tmp_path, capsys):
    conn = MagicMock(spec=AdwsConnection)
    monkeypatch.setattr(cli, "connect_adws", lambda *a, **kw: conn)
    monkeypatch.setattr(cli, "AdwsClient", MagicMock())

    missing_cache = tmp_path / "does-not-exist.json"

    with pytest.raises(SystemExit):
        cli.main([
            "-H", "dc01", "-u", "alice", "-w", "pw", "-b", "DC=corp,DC=local",
            "--dump", "bhdump", "--cachefile", str(missing_cache),
        ])
    err = capsys.readouterr().err.lower()
    assert "buildcache first" in err or "requires an existing cache" in err
