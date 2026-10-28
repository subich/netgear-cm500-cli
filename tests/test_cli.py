"""Tests for the CLI: argument handling, rendering, and error reporting."""

from __future__ import annotations

import io
import json
import subprocess
from collections.abc import Callable

import pytest

from netgear_cm500_cli import cli
from netgear_cm500_cli.color import Palette
from netgear_cm500_cli.modem import (
    DownstreamChannel,
    EventLogEntry,
    GeneralStatus,
    ModemError,
    ModemStatus,
    Severity,
    UpstreamChannel,
)

# Palettes with color forced on/off so render tests are deterministic
# regardless of whether the test runner's stdout is a TTY.
_NO_COLOR = Palette(enabled=False)
_COLOR = Palette(enabled=True)

_STATUS = ModemStatus(
    general=GeneralStatus(
        downstream_frequency_hz="633000000",
        downstream_lock="Locked",
        connectivity_state="OK",
        connectivity_comment="Operational",
        boot_state="OK",
        boot_comment="Operational",
        security="Disabled",
        security_comment="Disabled",
        current_system_time="Mon Oct 12 15:53:43 2026",
        system_uptime="1 day 23:21:39",
    ),
    downstream=[
        DownstreamChannel(
            channel="1",
            lock_status="Locked",
            modulation="QAM256",
            channel_id="29",
            frequency="633000000 Hz",
            power_dbmv="-18.3",
            snr_db="33.6",
            corrected="3823138",
            uncorrected="99990",
        )
    ],
    upstream=[
        UpstreamChannel(
            channel="1",
            lock_status="Locked",
            channel_type="ATDMA",
            channel_id="7",
            symbol_rate="5120",
            frequency="31000000 Hz",
            power_dbmv="46.3",
        )
    ],
)

_EVENTS = [
    EventLogEntry(
        index="93",
        first_time="2026-10-12, 15:27:52.0",
        last_time="2026-10-12, 15:33:00.0",
        count="7",
        level="5",
        severity="Notice",
        event_id="84020300",
        text="MDD message timeout",
    ),
    EventLogEntry(
        index="78",
        first_time="2026-10-11, 03:17:24.0",
        last_time="2026-10-11, 03:17:24.0",
        count="2",
        level="3",
        severity="Error",
        event_id="82000200",
        text="No Ranging Response received - T3 time-out",
    ),
]


@pytest.fixture
def _env_password(monkeypatch: pytest.MonkeyPatch) -> None:
    # Supplying the password via env avoids the interactive getpass prompt.
    monkeypatch.setenv("CM500_PASS", "secret")


@pytest.mark.parametrize("argv", [None, [], ["--json"], ["--host", "modem.local"]])
def test_missing_subcommand_displays_help_without_credentials(
    argv: list[str] | None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli.sys, "argv", ["netgear-cm500-cli"])

    def unexpected_password_request(host: str, user: str) -> str:
        pytest.fail("Help must not request credentials or connect to the modem")

    monkeypatch.setattr(cli, "_resolve_password", unexpected_password_request)
    assert cli.main(argv) == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out
    assert "status" in captured.out
    assert "events" in captured.out
    assert "--host" in captured.out
    assert "--json" in captured.out
    assert captured.err == ""


def test_help_subcommand_does_not_resolve_credentials(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cli,
        "_resolve_credentials",
        lambda *_args: pytest.fail("help must not resolve credentials"),
    )
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out
    assert captured.err == ""


def test_text_output_includes_summary_and_tables(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _env_password: None,
) -> None:
    monkeypatch.setattr(cli, "get_status", lambda *a, **k: _STATUS)
    exit_code = cli.main(["status", "--host", "192.168.100.1"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "NETGEAR CM500 status @ 192.168.100.1" in out
    assert "Downstream bonded channels" in out
    assert "Upstream bonded channels" in out
    assert "QAM256" in out
    assert "ATDMA" in out


def test_json_output_is_valid_and_structured(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _env_password: None,
) -> None:
    monkeypatch.setattr(cli, "get_status", lambda *a, **k: _STATUS)
    exit_code = cli.main(["status", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["general"]["connectivity_state"] == "OK"
    assert payload["downstream"][0]["modulation"] == "QAM256"
    assert payload["upstream"][0]["channel_type"] == "ATDMA"


def test_modem_error_reports_to_stderr_and_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _env_password: None,
) -> None:
    def _raise(*_args: object, **_kwargs: object) -> ModemStatus:
        raise ModemError("authentication failed: check username and password")

    monkeypatch.setattr(cli, "get_status", _raise)
    exit_code = cli.main(["status"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "authentication failed" in captured.err
    assert captured.out == ""


def test_password_resolved_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CM500_PASS", "from-env")
    assert cli._resolve_password("host", "admin") == "from-env"


def test_password_prompts_when_env_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CM500_PASS", raising=False)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "typed-secret")
    assert cli._resolve_password("host", "admin") == "typed-secret"


def test_1password_credentials_parse_username_and_password() -> None:
    payload = json.dumps(
        [
            {"label": "username", "value": "op-admin"},
            {"label": "password", "value": "  op-pass  "},
        ]
    )

    assert cli._parse_op_fields(payload) == ("op-admin", "  op-pass  ")


def test_1password_credentials_require_exactly_one_pair() -> None:
    with pytest.raises(cli.CredentialError, match="exactly one username"):
        cli._parse_op_fields(
            json.dumps(
                [
                    {"label": "username", "value": "one"},
                    {"label": "username", "value": "two"},
                    {"label": "password", "value": "pass"},
                ]
            )
        )

    with pytest.raises(cli.CredentialError, match="exactly one password"):
        cli._parse_op_fields(json.dumps([{"label": "username", "value": "one"}]))


def test_1password_credentials_require_nonempty_username_and_password() -> None:
    with pytest.raises(cli.CredentialError, match="non-empty username"):
        cli._parse_op_fields(
            json.dumps(
                [
                    {"label": "username", "value": ""},
                    {"label": "password", "value": "pass"},
                ]
            )
        )

    with pytest.raises(cli.CredentialError, match="non-empty password"):
        cli._parse_op_fields(
            json.dumps(
                [
                    {"label": "username", "value": "admin"},
                    {"label": "password", "value": ""},
                ]
            )
        )


def test_1password_credentials_require_string_label_and_value() -> None:
    with pytest.raises(cli.CredentialError, match="invalid 1Password response"):
        cli._parse_op_fields(
            json.dumps([{"label": "username", "value": 1}, {"label": 2, "value": "x"}])
        )


def test_1password_resolution_invokes_op_with_safe_args(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(**kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=["op"],
            returncode=0,
            stdout='[{"label":"username","value":"u"},{"label":"password","value":"p"}]',
            stderr="",
        )

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    username, password = cli._resolve_1password_credentials("item-ref", "vault-name")
    assert (username, password) == ("u", "p")
    assert captured["args"] == [
        "op",
        "item",
        "get",
        "--fields",
        "label=username,label=password",
        "--format",
        "json",
        "--reveal",
        "--vault",
        "vault-name",
        "--",
        "item-ref",
    ]
    assert captured["capture_output"] is True
    assert captured["text"] is True
    assert captured["check"] is False
    assert captured["stdin"] is subprocess.DEVNULL
    assert captured["timeout"] == 60


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (FileNotFoundError("missing"), "1Password CLI executable was not found"),
        (OSError("boom"), "unable to execute 1Password CLI"),
        (
            subprocess.TimeoutExpired(cmd=["op"], timeout=60),
            "timed out while waiting for 1Password CLI",
        ),
    ],
)
def test_1password_resolution_redacts_execution_errors(
    monkeypatch: pytest.MonkeyPatch, exc: Exception, expected: str
) -> None:
    def fake_run(**_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise exc

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    with pytest.raises(cli.CredentialError, match=expected):
        cli._resolve_1password_credentials("item-ref", None)


def test_1password_resolution_redacts_nonzero_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(**_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["op"],
            returncode=1,
            stdout="secret-json",
            stderr="sensitive output",
        )

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    with pytest.raises(
        cli.CredentialError, match="failed to resolve credentials"
    ) as excinfo:
        cli._resolve_1password_credentials("item-ref", None)
    message = str(excinfo.value)
    assert "secret-json" not in message
    assert "sensitive output" not in message


def test_1password_resolution_rejects_bad_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(**_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["op"], returncode=0, stdout="{oops", stderr=""
        )

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    with pytest.raises(cli.CredentialError, match="invalid 1Password response"):
        cli._resolve_1password_credentials("item-ref", None)


def test_events_text_output_lists_entries(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _env_password: None,
) -> None:
    monkeypatch.setattr(cli, "get_event_log", lambda *a, **k: _EVENTS)
    exit_code = cli.main(["events"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "event log @" in out
    assert "MDD message timeout" in out
    assert "No Ranging Response received" in out
    assert "Notice" in out
    assert "Error" in out


def test_events_json_output_is_structured(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _env_password: None,
) -> None:
    monkeypatch.setattr(cli, "get_event_log", lambda *a, **k: _EVENTS)
    exit_code = cli.main(["events", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert len(payload) == 2
    assert payload[0]["event_id"] == "84020300"
    assert payload[1]["severity"] == "Error"


def test_events_limit_truncates_to_newest(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _env_password: None,
) -> None:
    monkeypatch.setattr(cli, "get_event_log", lambda *a, **k: _EVENTS)
    cli.main(["events", "--limit", "1"])
    out = capsys.readouterr().out
    assert "MDD message timeout" in out
    assert "No Ranging Response received" not in out


def test_events_limit_zero_shows_all() -> None:
    assert cli._limit_events(_EVENTS, 0) == _EVENTS
    assert cli._limit_events(_EVENTS, -5) == _EVENTS


def test_events_empty_log_renders_placeholder() -> None:
    rendered = cli._render_events_text([], "192.168.100.1", _NO_COLOR)
    assert "(no events)" in rendered


# --- severity filter ------------------------------------------------------


def test_filter_by_severity_keeps_threshold_and_worse() -> None:
    # Error (3) is worse than Notice (5); filtering to "error" keeps only it.
    filtered = cli._filter_by_severity(_EVENTS, "error")
    assert len(filtered) == 1
    assert filtered[0].severity == "Error"


def test_filter_by_severity_notice_keeps_both() -> None:
    filtered = cli._filter_by_severity(_EVENTS, "notice")
    assert len(filtered) == 2


def test_filter_by_severity_none_is_passthrough() -> None:
    assert cli._filter_by_severity(_EVENTS, None) == list(_EVENTS)


def test_filter_by_severity_keeps_unknown_level() -> None:
    # An unparseable level must not be silently dropped by a severity filter.
    unknown = EventLogEntry(
        index="1",
        first_time="t",
        last_time="t",
        count="1",
        level="999",
        severity="999",
        event_id="x",
        text="mystery event",
    )
    filtered = cli._filter_by_severity([unknown], "error")
    assert filtered == [unknown]


def test_events_min_severity_cli_filters_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _env_password: None,
) -> None:
    monkeypatch.setattr(cli, "get_event_log", lambda *a, **k: _EVENTS)
    cli.main(["events", "--min-severity", "error"])
    out = capsys.readouterr().out
    assert "No Ranging Response received" in out
    assert "MDD message timeout" not in out


def test_invalid_severity_choice_exits(_env_password: None) -> None:
    with pytest.raises(SystemExit):
        cli.main(["events", "--min-severity", "bogus"])


# --- colorization ---------------------------------------------------------


def test_render_events_colorizes_error_rows() -> None:
    rendered = cli._render_events_text(_EVENTS, "host", _COLOR)
    # The Error row should carry an ANSI red code; the whole block has a reset.
    assert "\033[31m" in rendered
    assert "\033[0m" in rendered


def test_render_events_plain_when_color_disabled() -> None:
    rendered = cli._render_events_text(_EVENTS, "host", _NO_COLOR)
    assert "\033[" not in rendered


def test_render_status_colorizes_out_of_spec_power() -> None:
    rendered = cli._render_status_text(_STATUS, "host", _COLOR)
    # -18.3 dBmV is out of spec -> red; the sample SNR 33.6 is good -> green.
    assert "\033[31m" in rendered
    assert "\033[32m" in rendered


def test_render_status_plain_when_color_disabled() -> None:
    rendered = cli._render_status_text(_STATUS, "host", _NO_COLOR)
    assert "\033[" not in rendered


@pytest.mark.parametrize(
    ("power", "expected"),
    [("0.0", ("green",)), ("-9", ("yellow",)), ("-18.3", ("red", "bold"))],
)
def test_ds_power_style_thresholds(power: str, expected: tuple[str, ...]) -> None:
    assert cli._ds_power_style(power) == expected


@pytest.mark.parametrize(
    ("snr", "expected"),
    [("35", ("green",)), ("31", ("yellow",)), ("27", ("red", "bold"))],
)
def test_ds_snr_style_thresholds(snr: str, expected: tuple[str, ...]) -> None:
    assert cli._ds_snr_style(snr) == expected


def test_severity_style_mapping() -> None:
    assert cli._severity_style(Severity.ERROR) == ("red", "bold")
    assert cli._severity_style(Severity.WARNING) == ("yellow",)
    assert cli._severity_style(Severity.NOTICE) == ("cyan",)
    assert cli._severity_style(Severity.INFORMATION) == ("dim",)
    assert cli._severity_style(None) == ()


def test_json_output_never_colorized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _env_password: None,
) -> None:
    # --json forces color off even if stdout were a TTY.
    monkeypatch.setattr(cli, "get_event_log", lambda *a, **k: _EVENTS)
    cli.main(["events", "--json"])
    out = capsys.readouterr().out
    assert "\033[" not in out


def _interrupting_sleep(
    interrupt_after: int, calls: list[float]
) -> Callable[[float], None]:
    def fake_sleep(seconds: float) -> None:
        calls.append(seconds)
        if len(calls) >= interrupt_after:
            raise KeyboardInterrupt

    return fake_sleep


def test_status_monitor_repeats_with_default_interval_and_single_credential_prompt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    resolve_calls = 0
    status_calls = 0
    sleep_calls: list[float] = []

    def fake_resolve(_host: str, _user: str) -> str:
        nonlocal resolve_calls
        resolve_calls += 1
        return "secret"

    def fake_get_status(*_args: object, **_kwargs: object) -> ModemStatus:
        nonlocal status_calls
        status_calls += 1
        return _STATUS

    monkeypatch.setattr(cli, "_resolve_password", fake_resolve)
    monkeypatch.setattr(cli, "get_status", fake_get_status)
    monkeypatch.setattr(cli.time, "sleep", _interrupting_sleep(2, sleep_calls))

    exit_code = cli.main(["status", "--monitor"])
    out = capsys.readouterr().out
    assert exit_code == 130
    assert resolve_calls == 1
    assert status_calls == 2
    assert sleep_calls == [5.0, 5.0]
    assert out.count("NETGEAR CM500 status @") == 2
    assert "\x1b[2J\x1b[H" not in out
    assert "\033[" not in out


def test_events_monitor_repeats_with_custom_interval(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    event_calls = 0
    sleep_calls: list[float] = []

    monkeypatch.setattr(cli, "_resolve_password", lambda *_args: "secret")

    def fake_get_events(*_args: object, **_kwargs: object) -> list[EventLogEntry]:
        nonlocal event_calls
        event_calls += 1
        return _EVENTS

    monkeypatch.setattr(cli, "get_event_log", fake_get_events)
    monkeypatch.setattr(cli.time, "sleep", _interrupting_sleep(2, sleep_calls))

    exit_code = cli.main(["events", "--monitor", "--interval", "2.5"])
    out = capsys.readouterr().out
    assert exit_code == 130
    assert event_calls == 2
    assert sleep_calls == [2.5, 2.5]
    assert out.count("NETGEAR CM500 event log @") == 2


def test_monitor_tty_refresh_writes_clear_and_home_per_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _TtyBuffer(io.StringIO):
        def isatty(self) -> bool:
            return True

    output = _TtyBuffer()
    monkeypatch.setattr(cli, "get_status", lambda *a, **k: _STATUS)
    monkeypatch.setattr(cli, "_resolve_password", lambda *_args: "secret")
    monkeypatch.setattr(cli.sys, "stdout", output)
    monkeypatch.setattr(cli.time, "sleep", _interrupting_sleep(1, []))

    exit_code = cli.main(["status", "--monitor", "--no-color"])
    text = output.getvalue()
    assert exit_code == 130
    assert text.startswith("\x1b[2J\x1b[H=== NETGEAR CM500 status @")


def test_monitor_ctrl_c_during_fetch_exits_130(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "_resolve_password", lambda *_args: "secret")
    monkeypatch.setattr(
        cli,
        "get_event_log",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt),
    )
    exit_code = cli.main(["events", "--monitor"])
    captured = capsys.readouterr()
    assert exit_code == 130
    assert captured.out == ""
    assert captured.err == ""


def test_monitor_modem_error_exits_1_and_stops_polling(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0
    sleep_calls: list[float] = []
    monkeypatch.setattr(cli, "_resolve_password", lambda *_args: "secret")

    def fake_get_status(*_args: object, **_kwargs: object) -> ModemStatus:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ModemError("boom")
        return _STATUS

    monkeypatch.setattr(cli, "get_status", fake_get_status)
    monkeypatch.setattr(cli.time, "sleep", _interrupting_sleep(99, sleep_calls))
    exit_code = cli.main(["status", "--monitor"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert calls == 2
    assert sleep_calls == [5.0]
    assert "error: boom" in captured.err


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_monitor_interval_must_be_positive_finite(
    value: str, _env_password: None
) -> None:
    with pytest.raises(SystemExit):
        cli.main(["status", "--monitor", "--interval", value])


def test_monitor_rejects_json_before_credentials_or_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "_resolve_password",
        lambda *_args: pytest.fail("credentials must not be resolved"),
    )
    monkeypatch.setattr(
        cli, "get_status", lambda *_args, **_kwargs: pytest.fail("network must not run")
    )
    with pytest.raises(SystemExit):
        cli.main(["status", "--monitor", "--json"])


def test_op_vault_requires_op_item_before_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "_resolve_credentials",
        lambda *_args: pytest.fail("credentials must not be resolved"),
    )
    with pytest.raises(SystemExit):
        cli.main(["status", "--op-vault", "personal"])


def test_op_item_empty_string_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "_resolve_credentials",
        lambda *_args: pytest.fail("credentials must not be resolved"),
    )
    with pytest.raises(SystemExit):
        cli.main(["status", "--op-item", ""])


def test_status_uses_1password_credentials_and_ignores_env_password(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CM500_PASS", "from-env")
    monkeypatch.setattr(
        cli, "_resolve_1password_credentials", lambda *_args: ("op-u", "op-p")
    )
    monkeypatch.setattr(
        cli,
        "_resolve_password",
        lambda *_args: pytest.fail("password fallback must not be used"),
    )
    captured_args: tuple[str, str, str] | None = None

    def fake_get_status(host: str, user: str, password: str) -> ModemStatus:
        nonlocal captured_args
        captured_args = (host, user, password)
        return _STATUS

    monkeypatch.setattr(cli, "get_status", fake_get_status)
    exit_code = cli.main(["status", "--user", "cli-user", "--op-item", "router"])
    assert exit_code == 0
    assert captured_args == ("192.168.100.1", "op-u", "op-p")
    assert "NETGEAR CM500 status" in capsys.readouterr().out


def test_events_uses_1password_credentials_from_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CM500_OP_ITEM", "item-ref")
    monkeypatch.setenv("CM500_OP_VAULT", "vault-ref")
    calls: list[tuple[str, str, str]] = []

    def fake_resolve(item: str, vault: str | None) -> tuple[str, str]:
        calls.append((item, vault or "", "resolve"))
        return ("op-user", "op-pass")

    monkeypatch.setattr(cli, "_resolve_1password_credentials", fake_resolve)
    monkeypatch.setattr(
        cli,
        "get_event_log",
        lambda host, user, password: _EVENTS if (host, user, password) else [],
    )
    exit_code = cli.main(["events"])
    assert exit_code == 0
    assert calls == [("item-ref", "vault-ref", "resolve")]
    assert "event log @" in capsys.readouterr().out


def test_1password_cli_values_override_environment_defaults(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CM500_OP_ITEM", "env-item")
    monkeypatch.setenv("CM500_OP_VAULT", "env-vault")
    calls: list[tuple[str, str | None]] = []

    def fake_resolve(item: str, vault: str | None) -> tuple[str, str]:
        calls.append((item, vault))
        return ("u", "p")

    monkeypatch.setattr(cli, "_resolve_1password_credentials", fake_resolve)
    monkeypatch.setattr(cli, "get_status", lambda *_args, **_kwargs: _STATUS)

    assert (
        cli.main(
            [
                "status",
                "--op-item",
                "cli-item",
                "--op-vault",
                "cli-vault",
            ]
        )
        == 0
    )
    assert calls == [("cli-item", "cli-vault")]
    assert "NETGEAR CM500 status @" in capsys.readouterr().out


def test_op_item_supported_before_and_after_subcommand(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cli, "_resolve_1password_credentials", lambda *_args: ("u", "p")
    )
    monkeypatch.setattr(cli, "get_status", lambda *_args, **_kwargs: _STATUS)

    assert cli.main(["--op-item", "item-ref", "status"]) == 0
    capsys.readouterr()
    assert cli.main(["status", "--op-item", "item-ref"]) == 0


def test_monitor_resolves_1password_credentials_once(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    resolve_calls = 0
    status_calls = 0
    sleep_calls: list[float] = []

    def fake_resolve(*_args: object) -> tuple[str, str]:
        nonlocal resolve_calls
        resolve_calls += 1
        return ("u", "p")

    def fake_get_status(*_args: object, **_kwargs: object) -> ModemStatus:
        nonlocal status_calls
        status_calls += 1
        return _STATUS

    monkeypatch.setattr(cli, "_resolve_1password_credentials", fake_resolve)
    monkeypatch.setattr(cli, "get_status", fake_get_status)
    monkeypatch.setattr(cli.time, "sleep", _interrupting_sleep(2, sleep_calls))

    exit_code = cli.main(["status", "--monitor", "--op-item", "item-ref"])
    assert exit_code == 130
    assert resolve_calls == 1
    assert status_calls == 2
    assert sleep_calls == [5.0, 5.0]
    assert "NETGEAR CM500 status @" in capsys.readouterr().out


def test_credential_error_exits_1_without_output_leakage(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cli,
        "_resolve_1password_credentials",
        lambda *_args: (_ for _ in ()).throw(
            cli.CredentialError("failed to resolve credentials from 1Password item")
        ),
    )
    exit_code = cli.main(["status", "--op-item", "item-ref"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "failed to resolve credentials from 1Password item" in captured.err
