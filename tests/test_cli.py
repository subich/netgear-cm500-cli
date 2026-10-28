"""Tests for the CLI: argument handling, rendering, and error reporting."""

from __future__ import annotations

import io
import json
from collections.abc import Callable

import pytest

from netgear_cm500_cli import cli
from netgear_cm500_cli.color import Palette
from netgear_cm500_cli.modem import (
    DownstreamChannel,
    EventLogEntry,
    GatewayStatus,
    GeneralStatus,
    ModemError,
    ModemStatus,
    Severity,
    UpstreamChannel,
    VoiceStatus,
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

_GATEWAY_STATUS = GatewayStatus(
    hardware_version="hardware",
    firmware_version="firmware",
    serial_number="serial",
    cm_certificate="installed",
    cable_mac="cable-mac",
    cable_ip_mask="cable-ip/mask",
    cable_gateway="cable-gateway",
    cable_dns="cable-dns",
    network_access="allowed",
    internet_mac="internet-mac",
    internet_ip_mask="internet-ip/mask",
    internet_dhcp="DHCP",
    internet_gateway="internet-gateway",
    internet_dns="internet-dns",
    lan_mac="lan-mac",
    lan_ip_mask="lan-ip/mask",
    lan_dhcp="LAN DHCP",
    wireless_24_region="region",
    wireless_24_channel="channel",
    wireless_24_mode="mode",
    wireless_24_access_point="enabled",
    wireless_24_broadcast_name="ssid",
    wireless_24_isolation="off",
    wireless_5_region="region5",
    wireless_5_channel="channel5",
    wireless_5_mode="mode5",
    wireless_5_access_point="enabled5",
    wireless_5_broadcast_name="ssid5",
    wireless_5_isolation="off5",
    system_uptime="uptime",
    current_system_time="current-time",
)

_VOICE_STATUS = VoiceStatus(
    line_1_status="Connected",
    line_2_status="Disconnected",
    mta_mac="mta-mac",
    mta_ip="mta-ip",
    mta_fqdn="mta-fqdn",
    telephony_signaling="SIP",
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


def test_gateway_command_text_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _env_password: None,
) -> None:
    monkeypatch.setattr(cli, "get_gateway_status", lambda *a, **k: _GATEWAY_STATUS)

    assert cli.main(["gateway"]) == 0

    out = capsys.readouterr().out
    assert "gateway status" in out
    assert "Wireless 2.4 GHz" in out
    assert "Wireless 5 GHz" in out
    assert "ssid5" in out


def test_voice_command_json_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _env_password: None,
) -> None:
    monkeypatch.setattr(cli, "get_voice_status", lambda *a, **k: _VOICE_STATUS)

    assert cli.main(["voice", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["line_1_status"] == "Connected"
    assert payload["line_2_status"] == "Disconnected"
    assert payload["telephony_signaling"] == "SIP"


def test_voice_text_output_marks_empty_fields_unavailable() -> None:
    status = VoiceStatus(
        line_1_status=None,
        line_2_status=None,
        mta_mac=None,
        mta_ip=None,
        mta_fqdn=None,
        telephony_signaling=None,
    )

    rendered = cli._render_voice_status_text(status, "192.168.100.1")

    assert rendered.count("Unavailable") == 6


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


@pytest.mark.parametrize("option", ["--op-item", "--op-vault"])
def test_removed_1password_options_are_rejected(
    monkeypatch: pytest.MonkeyPatch, option: str
) -> None:
    monkeypatch.setattr(
        cli,
        "_resolve_credentials",
        lambda *_args: pytest.fail("invalid options must not resolve credentials"),
    )
    with pytest.raises(SystemExit) as exc:
        cli.main(["status", option, "item"])
    assert exc.value.code == 2


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
