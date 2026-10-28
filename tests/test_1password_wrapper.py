"""Isolated subprocess tests for the standalone shell wrapper."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "cm500_1password.sh"
_USERNAME = "test-admin"
_PASSWORD = "  fake-password ' $ \\ \n\n"
_FIELDS = [
    {"label": "username", "value": _USERNAME},
    {"label": "password", "value": _PASSWORD},
]


@pytest.fixture
def commands(tmp_path: Path) -> dict[str, str]:
    jq = shutil.which("jq")
    assert jq is not None, "wrapper tests require jq"
    (tmp_path / "jq").symlink_to(jq)
    op = tmp_path / "op"
    op.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "expected = ['item', 'get', '--fields', 'label=username,label=password', "
        "'--format', 'json', '--reveal']\n"
        "if os.environ.get('WITH_VAULT', '1') == '1':\n"
        "    expected += ['--vault', 'test-vault']\n"
        "assert sys.argv[1:] == expected + ['--', '-item with spaces']\n"
        "print(os.environ['OP_PAYLOAD'])\n"
        "print('private diagnostic', file=sys.stderr)\n"
        "sys.exit(int(os.environ.get('OP_EXIT', '0')))\n"
    )
    op.chmod(0o700)
    utility = tmp_path / "netgear-cm500-cli"
    utility.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"assert os.environ['CM500_USER'] == {_USERNAME!r}\n"
        f"assert os.environ['CM500_PASS'] == {_PASSWORD!r}\n"
        "assert sys.argv[1:] == ['status', '--json', '--host', 'modem.local']\n"
        "print('utility reached')\n"
        "sys.exit(23)\n"
    )
    utility.chmod(0o700)
    return {
        **os.environ,
        "PATH": str(tmp_path),
        "OP_PAYLOAD": json.dumps(_FIELDS),
        "CM500_USER": "old-user",
        "CM500_PASS": "old-password",
    }


def run_wrapper(
    environment: dict[str, str], directory: Path, arguments: list[str] | None = None
) -> subprocess.CompletedProcess[str]:
    if arguments is None:
        arguments = ["--item", "-item with spaces"]
        if environment.get("WITH_VAULT", "1") == "1":
            arguments += ["--vault", "test-vault"]
        arguments += ["--", "status", "--json", "--host", "modem.local"]
    return subprocess.run(
        [str(_SCRIPT), *arguments],
        env=environment,
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


@pytest.mark.parametrize("with_vault", ["0", "1"])
def test_wrapper_passes_credentials_arguments_and_exit_status(
    commands: dict[str, str], tmp_path: Path, with_vault: str
) -> None:
    commands["WITH_VAULT"] = with_vault
    result = run_wrapper(commands, tmp_path)
    assert result.returncode == 23
    assert result.stdout == "utility reached\n"
    assert result.stderr == ""


@pytest.mark.parametrize(
    "payload",
    [
        "private invalid JSON",
        "{}",
        "[]",
        "[null]",
        json.dumps(_FIELDS + [_FIELDS[0]]),
        json.dumps([_FIELDS[0]]),
        json.dumps([_FIELDS[0], {"label": "password", "value": ""}]),
        json.dumps([_FIELDS[0], {"label": "password", "value": 12}]),
        json.dumps([_FIELDS[0], {"label": "password", "value": "a\0b"}]),
    ],
)
def test_invalid_credentials_do_not_launch_utility(
    commands: dict[str, str], tmp_path: Path, payload: str
) -> None:
    commands["OP_PAYLOAD"] = payload
    result = run_wrapper(commands, tmp_path)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "error:" in result.stderr
    assert "private" not in result.stderr


def test_lookup_failure_does_not_launch_utility(
    commands: dict[str, str], tmp_path: Path
) -> None:
    commands["OP_EXIT"] = "1"
    result = run_wrapper(commands, tmp_path)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "failed to resolve credentials" in result.stderr
    assert "private" not in result.stderr


@pytest.mark.parametrize("missing", ["op", "jq", "netgear-cm500-cli"])
def test_wrapper_reports_missing_executables(
    commands: dict[str, str], tmp_path: Path, missing: str
) -> None:
    (tmp_path / missing).unlink()
    result = run_wrapper(commands, tmp_path)
    assert result.returncode == 1
    assert "required command not found" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize(
    "arguments",
    [[], ["--item"], ["--item", ""], ["--item", "item"], ["--vault"], ["--unknown"]],
)
def test_wrapper_rejects_invalid_arguments(
    commands: dict[str, str], tmp_path: Path, arguments: list[str]
) -> None:
    result = run_wrapper(commands, tmp_path, arguments)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "error:" in result.stderr or "Usage:" in result.stderr
