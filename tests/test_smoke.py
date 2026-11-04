# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import shlex

import pytest

import adwsearch
from adwsearch import cli
from adwsearch.cli import build_parser


def test_package_has_version():
    assert adwsearch.__version__ == "0.1.0"


def test_help_exits_zero(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--help"])
    assert exc.value.code == 0
    assert "adwsearch" in capsys.readouterr().out


def test_help_examples_do_not_put_passwords_in_command_arguments(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--help"])
    assert exc.value.code == 0
    examples = capsys.readouterr().out.split("examples:\n", 1)[1]
    commands = [line.strip() for line in examples.replace("\\\n", " ").splitlines()
                if line.strip().startswith("adwsearch ")]
    assert commands
    for command in commands:
        args = parser.parse_args(shlex.split(command)[1:])
        assert args.password is None, command
        assert (args.prompt_password or args.kerberos or args.hashes
                or args.dump == "showstats"), command


def test_help_warns_about_password_argument_exposure(capsys):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "process" in help_text.lower()
    assert "prefer -W" in help_text


def test_help_and_readme_cover_registered_presets():
    import re
    from pathlib import Path
    from adwsearch.enum import PRESETS
    help_text = build_parser().format_help()
    examples = help_text.split('examples:', 1)[1].replace('\\\n', ' ')
    for name in PRESETS:
        assert '--preset ' + name in examples
    readme = (Path(__file__).parents[1] / 'README.md').read_text(encoding='utf-8')
    assert set(re.findall(r'^\| `([^`]+)` \|', readme, re.M)) == set(PRESETS)
    assert 'forest / domain functional level' not in examples
    assert 'policy annotations' in help_text
    commands = [line for line in examples.splitlines() if line.strip().startswith('adwsearch ')]
    assert any('--preset users-description' in line and '-b ' not in line for line in commands)
    assert any('--preset password-policy' in line and '-b ' not in line for line in commands)


def test_help_distinguishes_kerberoastable_json_from_cracking_hashes(capsys):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--help"])
    help_text = " ".join(capsys.readouterr().out.lower().split())
    assert "not hashcat input" in help_text
    assert "does not request roasting tickets" in help_text


def test_kerberoastable_dry_run_explains_metadata_only_output(capsys):
    assert cli.main([
        "-H", "dc01.corp.example", "-u", "alice@corp.example",
        "-w", "synthetic-test-only", "-b", "DC=corp,DC=example",
        "--preset", "kerberoastable", "--dry-run",
    ]) == 0
    summary = " ".join(capsys.readouterr().out.lower().split())
    assert "not hashcat input" in summary
    assert "does not request roasting tickets" in summary
    assert "synthetic-test-only" not in summary


def test_defaults():
    args = build_parser().parse_args([])
    assert args.port == 9389
    assert args.scope == "sub"
    assert args.filter == "(objectClass=*)"
    assert args.attributes == []
    # The CLI resolves the omitted format after it knows the selected preset.
    assert args.output is None
    assert build_parser().parse_args(['-o', 'ldif']).output == 'ldif'


def test_positional_filter_and_attributes():
    args = build_parser().parse_args(["(objectClass=user)", "cn", "mail"])
    assert args.filter == "(objectClass=user)"
    assert args.attributes == ["cn", "mail"]
