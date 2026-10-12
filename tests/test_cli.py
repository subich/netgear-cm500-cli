"""Tests for the CLI: argument handling, rendering, and error reporting."""

from __future__ import annotations

import json

import pytest

from cm500_status import cli
from cm500_status.color import Palette
from cm500_status.modem import (
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


def test_text_output_includes_summary_and_tables(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _env_password: None,
) -> None:
    monkeypatch.setattr(cli, "get_status", lambda *a, **k: _STATUS)
    exit_code = cli.main(["--host", "192.168.100.1"])
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
    exit_code = cli.main(["--json"])
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
    exit_code = cli.main([])
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
