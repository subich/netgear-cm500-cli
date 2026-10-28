"""Command-line interface for the netgear-cm500-cli tool.

Fetches read-only status and event information from a NETGEAR CM500 modem and
renders it as a human-readable summary or JSON. Credentials are taken from the
environment or an interactive prompt; the password is never accepted as a
command-line argument so it does not leak into shell history or the process list.

Text output is colorized to highlight out-of-spec signal values and severe
events. Color is emitted only to an interactive terminal and is suppressed for
JSON, pipes, ``--no-color``, or the ``NO_COLOR`` convention.

Subcommands:
    status  connection summary and downstream/upstream channel tables
    events  most recent entries from the DOCSIS event log
    gateway gateway, LAN, and wireless status
    voice   voice/MTA status
"""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import math
import os
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from typing import TextIO

from netgear_cm500_cli.color import Palette, palette_for
from netgear_cm500_cli.modem import (
    DEFAULT_HOST,
    DEFAULT_USER,
    DownstreamChannel,
    EventLogEntry,
    GatewayStatus,
    ModemError,
    ModemStatus,
    Severity,
    UpstreamChannel,
    VoiceStatus,
    get_event_log,
    get_gateway_status,
    get_status,
    get_voice_status,
)

_PASSWORD_ENV_VAR = "CM500_PASS"
_HOST_ENV_VAR = "CM500_HOST"
_USER_ENV_VAR = "CM500_USER"
_OP_ITEM_ENV_VAR = "CM500_OP_ITEM"
_OP_VAULT_ENV_VAR = "CM500_OP_VAULT"
_DEFAULT_EVENT_LIMIT = 20
_DEFAULT_MONITOR_INTERVAL = 5.0
_OP_TIMEOUT_SECONDS = 60

# Downstream signal spec limits (dBmV / dB). Values outside these are typical
# fault indicators and get highlighted; see the CableLabs DOCSIS guidance.
_DS_POWER_GOOD_MIN = -7.0
_DS_POWER_GOOD_MAX = 7.0
_DS_POWER_WARN_FLOOR = -10.0
_DS_POWER_WARN_CEIL = 10.0
_DS_SNR_GOOD_MIN = 33.0
_DS_SNR_WARN_MIN = 30.0

# Severity names accepted by --min-severity, ordered most to least severe.
_SEVERITY_CHOICES = [member.label.lower() for member in Severity]


class CredentialError(Exception):
    """Raised when credentials cannot be resolved safely."""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netgear-cm500-cli",
        description=(
            "Fetch read-only status and event information from a NETGEAR CM500."
        ),
    )
    _add_common_arguments(parser, subparser_defaults=False)

    subparsers = parser.add_subparsers(dest="command")

    status_parser = subparsers.add_parser(
        "status", help="connection summary and channel tables"
    )
    _add_common_arguments(status_parser, subparser_defaults=True)

    events_parser = subparsers.add_parser(
        "events", help="most recent entries from the DOCSIS event log"
    )
    _add_common_arguments(events_parser, subparser_defaults=True)
    events_parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=_DEFAULT_EVENT_LIMIT,
        help=(
            "number of most-recent events to show "
            f"(default: {_DEFAULT_EVENT_LIMIT}, 0 for all)"
        ),
    )
    events_parser.add_argument(
        "-s",
        "--min-severity",
        choices=_SEVERITY_CHOICES,
        help=(
            "show only events at this severity or worse "
            "(e.g. 'error' hides notices and informational events)"
        ),
    )

    gateway_parser = subparsers.add_parser(
        "gateway", help="gateway, LAN, and wireless status"
    )
    _add_common_arguments(gateway_parser, subparser_defaults=True)

    voice_parser = subparsers.add_parser("voice", help="voice/MTA status")
    _add_common_arguments(voice_parser, subparser_defaults=True)

    return parser


def _monitor_interval(value: str) -> float:
    try:
        interval = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be a finite number greater than 0"
        ) from exc
    if not math.isfinite(interval) or interval <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than 0")
    return interval


def _add_common_arguments(
    parser: argparse.ArgumentParser, *, subparser_defaults: bool
) -> None:
    """Attach the shared connection flags to a parser or subparser.

    Repeating them on each subparser lets the flags appear either before or
    after the subcommand (e.g. ``--json events`` or ``events --json``).
    """
    parser.add_argument(
        "--host",
        default=os.environ.get(_HOST_ENV_VAR, DEFAULT_HOST),
        help=f"modem address (default: {DEFAULT_HOST}, or ${_HOST_ENV_VAR})",
    )
    parser.add_argument(
        "--user",
        default=os.environ.get(_USER_ENV_VAR, DEFAULT_USER),
        help=f"admin username (default: {DEFAULT_USER}, or ${_USER_ENV_VAR})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the result as JSON instead of a text summary",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable colored output (also honors the NO_COLOR convention)",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="poll continuously and refresh the full view each interval",
    )
    parser.add_argument(
        "--interval",
        type=_monitor_interval,
        default=_DEFAULT_MONITOR_INTERVAL,
        metavar="SECONDS",
        help=(
            "monitor polling interval in seconds "
            f"(default: {_DEFAULT_MONITOR_INTERVAL:g})"
        ),
    )
    op_item_default: str | None = (
        argparse.SUPPRESS
        if subparser_defaults
        else _read_optional_env_value(_OP_ITEM_ENV_VAR)
    )
    op_vault_default: str | None = (
        argparse.SUPPRESS
        if subparser_defaults
        else _read_optional_env_value(_OP_VAULT_ENV_VAR)
    )
    parser.add_argument(
        "--op-item",
        default=op_item_default,
        metavar="ITEM",
        type=_op_item_value,
        help=(
            "resolve username and password from 1Password item ITEM "
            f"(or ${_OP_ITEM_ENV_VAR})"
        ),
    )
    parser.add_argument(
        "--op-vault",
        default=op_vault_default,
        metavar="VAULT",
        help=f"1Password vault for --op-item (or ${_OP_VAULT_ENV_VAR})",
    )


def _op_item_value(value: str) -> str:
    if value == "":
        raise argparse.ArgumentTypeError("must not be empty")
    return value


def _read_optional_env_value(name: str) -> str | None:
    value = os.environ.get(name)
    return value if value else None


def _resolve_password(host: str, user: str) -> str:
    """Return the admin password from the environment or an interactive prompt.

    The password is intentionally not a CLI argument: command-line values leak
    into shell history and the process table.
    """
    password = os.environ.get(_PASSWORD_ENV_VAR)
    if password:
        return password
    return getpass.getpass(f"Password for {user}@{host}: ")


def _parse_op_fields(payload: str) -> tuple[str, str]:
    try:
        raw_fields = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise CredentialError("invalid 1Password response") from exc
    if not isinstance(raw_fields, list):
        raise CredentialError("invalid 1Password response")

    usernames = _op_values_for_label(raw_fields, "username")
    passwords = _op_values_for_label(raw_fields, "password")
    if len(usernames) != 1:
        raise CredentialError("1Password item must include exactly one username field")
    if len(passwords) != 1:
        raise CredentialError("1Password item must include exactly one password field")

    username = usernames[0]
    password = passwords[0]
    if username == "":
        raise CredentialError("1Password item must include a non-empty username")
    if password == "":
        raise CredentialError("1Password item must include a non-empty password")
    return username, password


def _op_values_for_label(raw_fields: list[object], target_label: str) -> list[str]:
    values: list[str] = []
    for field in raw_fields:
        if not isinstance(field, dict):
            raise CredentialError("invalid 1Password response")
        label = field.get("label")
        value = field.get("value")
        if not isinstance(label, str) or not isinstance(value, str):
            raise CredentialError("invalid 1Password response")
        if label == target_label:
            values.append(value)
    return values


def _resolve_1password_credentials(
    op_item: str, op_vault: str | None
) -> tuple[str, str]:
    command = [
        "op",
        "item",
        "get",
        "--fields",
        "label=username,label=password",
        "--format",
        "json",
        "--reveal",
    ]
    if op_vault:
        command.extend(["--vault", op_vault])
    command.extend(["--", op_item])
    try:
        result = subprocess.run(
            args=command,
            capture_output=True,
            text=True,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=_OP_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise CredentialError("1Password CLI executable was not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise CredentialError("timed out while waiting for 1Password CLI") from exc
    except OSError as exc:
        raise CredentialError("unable to execute 1Password CLI") from exc

    if result.returncode != 0:
        raise CredentialError("failed to resolve credentials from 1Password item")
    return _parse_op_fields(result.stdout)


def _resolve_credentials(args: argparse.Namespace) -> tuple[str, str]:
    op_item = getattr(args, "op_item", None)
    op_vault = getattr(args, "op_vault", None)
    if op_item is not None:
        return _resolve_1password_credentials(op_item, op_vault)
    return args.user, _resolve_password(args.host, args.user)


def _status_to_dict(status: ModemStatus) -> dict[str, object]:
    return {
        "general": dataclasses.asdict(status.general),
        "downstream": [dataclasses.asdict(channel) for channel in status.downstream],
        "upstream": [dataclasses.asdict(channel) for channel in status.upstream],
    }


def _as_float(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


def _lock_style(lock_status: str) -> tuple[str, ...]:
    return () if lock_status == "Locked" else ("red", "bold")


def _ds_power_style(power: str) -> tuple[str, ...]:
    """Green when in spec, yellow when marginal, red when out of spec."""
    value = _as_float(power)
    if value is None:
        return ()
    if _DS_POWER_GOOD_MIN <= value <= _DS_POWER_GOOD_MAX:
        return ("green",)
    if _DS_POWER_WARN_FLOOR <= value <= _DS_POWER_WARN_CEIL:
        return ("yellow",)
    return ("red", "bold")


def _ds_snr_style(snr: str) -> tuple[str, ...]:
    value = _as_float(snr)
    if value is None:
        return ()
    if value >= _DS_SNR_GOOD_MIN:
        return ("green",)
    if value >= _DS_SNR_WARN_MIN:
        return ("yellow",)
    return ("red", "bold")


def _severity_style(severity_level: Severity | None) -> tuple[str, ...]:
    """Map an event severity to a color: red for errors, yellow for notices."""
    if severity_level is None:
        return ()
    if severity_level <= Severity.ERROR:
        return ("red", "bold")
    if severity_level <= Severity.WARNING:
        return ("yellow",)
    if severity_level <= Severity.NOTICE:
        return ("cyan",)
    return ("dim",)


def _render_status_text(status: ModemStatus, host: str, palette: Palette) -> str:
    general = status.general
    header = palette.paint(f"=== NETGEAR CM500 status @ {host} ===", "bold")
    conn_style = () if general.connectivity_state == "OK" else ("red", "bold")
    lines = [
        header,
        "",
        f"Downstream acquired : {general.downstream_frequency_hz} Hz "
        f"({general.downstream_lock})",
        f"Connectivity        : "
        f"{palette.paint(general.connectivity_state, *conn_style)} "
        f"({general.connectivity_comment})",
        f"Boot state          : {general.boot_state} ({general.boot_comment})",
        f"Security            : {general.security} ({general.security_comment})",
        f"Current system time : {general.current_system_time}",
        f"System uptime       : {general.system_uptime}",
        "",
        palette.paint("--- Downstream bonded channels ---", "bold"),
        f"{'Ch':<3} {'Lock':<10} {'Mod':<8} {'ID':<4} {'Frequency':<13} "
        f"{'Power':<8} {'SNR':<7} {'Corrected':<12} {'Uncorrect':<12}",
    ]
    lines += [_render_ds_row(ch, palette) for ch in status.downstream]

    lines += [
        "",
        palette.paint("--- Upstream bonded channels ---", "bold"),
        f"{'Ch':<3} {'Lock':<10} {'Type':<8} {'ID':<4} {'SymbolRate':<10} "
        f"{'Frequency':<13} {'Power':<8}",
    ]
    lines += [_render_us_row(ch, palette) for ch in status.upstream]

    return "\n".join(lines)


def _render_ds_row(ch: DownstreamChannel, palette: Palette) -> str:
    # Color the padded cells so highlighting does not disturb column alignment.
    lock = palette.paint(f"{ch.lock_status:<10}", *_lock_style(ch.lock_status))
    power = palette.paint(f"{ch.power_dbmv:<8}", *_ds_power_style(ch.power_dbmv))
    snr = palette.paint(f"{ch.snr_db:<7}", *_ds_snr_style(ch.snr_db))
    return (
        f"{ch.channel:<3} {lock} {ch.modulation:<8} "
        f"{ch.channel_id:<4} {ch.frequency:<13} {power} "
        f"{snr} {ch.corrected:<12} {ch.uncorrected:<12}"
    )


def _render_us_row(ch: UpstreamChannel, palette: Palette) -> str:
    lock = palette.paint(f"{ch.lock_status:<10}", *_lock_style(ch.lock_status))
    return (
        f"{ch.channel:<3} {lock} {ch.channel_type:<8} "
        f"{ch.channel_id:<4} {ch.symbol_rate:<10} {ch.frequency:<13} "
        f"{ch.power_dbmv:<8}"
    )


def _render_events_text(
    events: Sequence[EventLogEntry], host: str, palette: Palette
) -> str:
    lines = [
        palette.paint(f"=== NETGEAR CM500 event log @ {host} ===", "bold"),
        "",
        f"{'Time':<21} {'Severity':<12} {'Cnt':<4} Event",
    ]
    if not events:
        lines.append(palette.paint("(no events)", "dim"))
        return "\n".join(lines)

    for event in events:
        styles = _severity_style(event.severity_level)
        severity = palette.paint(f"{event.severity:<12}", *styles)
        text = palette.paint(event.text, *styles)
        lines.append(f"{event.last_time:<21} {severity} {event.count:<4} {text}")
    return "\n".join(lines)


def _limit_events(events: Sequence[EventLogEntry], limit: int) -> list[EventLogEntry]:
    # 0 (or negative) means "all"; the log is already newest-first.
    if limit <= 0:
        return list(events)
    return list(events[:limit])


def _filter_by_severity(
    events: Sequence[EventLogEntry], min_severity: str | None
) -> list[EventLogEntry]:
    """Keep events at ``min_severity`` or worse (numerically <= threshold).

    An event whose level does not parse to a known severity is kept, so an
    unrecognized but potentially important event is never silently dropped.
    """
    if min_severity is None:
        return list(events)
    threshold = Severity.from_name(min_severity)
    return [
        event
        for event in events
        if event.severity_level is None or event.severity_level <= threshold
    ]


def _run_status(
    args: argparse.Namespace, user: str, password: str, palette: Palette
) -> int:
    if args.monitor:
        return _run_monitor_loop(
            lambda: _render_status_text(
                get_status(args.host, user, password), args.host, palette
            ),
            args.interval,
            sys.stdout,
        )

    status = get_status(args.host, user, password)
    if args.json:
        print(json.dumps(_status_to_dict(status), indent=2))
    else:
        print(_render_status_text(status, args.host, palette))
    return 0


def _run_events(
    args: argparse.Namespace, user: str, password: str, palette: Palette
) -> int:
    if args.monitor:
        return _run_monitor_loop(
            lambda: _render_events_text(
                _limit_events(
                    _filter_by_severity(
                        get_event_log(args.host, user, password), args.min_severity
                    ),
                    args.limit,
                ),
                args.host,
                palette,
            ),
            args.interval,
            sys.stdout,
        )

    events = get_event_log(args.host, user, password)
    events = _filter_by_severity(events, args.min_severity)
    events = _limit_events(events, args.limit)
    if args.json:
        print(json.dumps([dataclasses.asdict(event) for event in events], indent=2))
    else:
        print(_render_events_text(events, args.host, palette))
    return 0


def _render_gateway_status_text(status: GatewayStatus, host: str) -> str:
    lines = [f"=== NETGEAR CM500 gateway status @ {host} ==="]
    sections = (
        (
            "Modem",
            (
                ("Hardware version", status.hardware_version),
                ("Firmware version", status.firmware_version),
                ("Serial number", status.serial_number),
                ("CM certificate", status.cm_certificate),
            ),
        ),
        (
            "Cable connection",
            (
                ("MAC address", status.cable_mac),
                ("IP address/mask", status.cable_ip_mask),
                ("Default gateway", status.cable_gateway),
                ("DNS servers", status.cable_dns),
                ("Network access", status.network_access),
            ),
        ),
        (
            "Internet port",
            (
                ("MAC address", status.internet_mac),
                ("IP address/mask", status.internet_ip_mask),
                ("DHCP", status.internet_dhcp),
                ("Default gateway", status.internet_gateway),
                ("DNS servers", status.internet_dns),
            ),
        ),
        (
            "LAN",
            (
                ("MAC address", status.lan_mac),
                ("IP address/mask", status.lan_ip_mask),
                ("DHCP", status.lan_dhcp),
            ),
        ),
        (
            "Wireless 2.4 GHz",
            (
                ("Region", status.wireless_24_region),
                ("Channel", status.wireless_24_channel),
                ("Mode", status.wireless_24_mode),
                ("Access point", status.wireless_24_access_point),
                ("Broadcast name", status.wireless_24_broadcast_name),
                ("Wireless isolation", status.wireless_24_isolation),
            ),
        ),
        (
            "Wireless 5 GHz",
            (
                ("Region", status.wireless_5_region),
                ("Channel", status.wireless_5_channel),
                ("Mode", status.wireless_5_mode),
                ("Access point", status.wireless_5_access_point),
                ("Broadcast name", status.wireless_5_broadcast_name),
                ("Wireless isolation", status.wireless_5_isolation),
            ),
        ),
        (
            "System",
            (
                ("Current system time", status.current_system_time),
                ("System uptime", status.system_uptime),
            ),
        ),
    )
    for title, fields in sections:
        lines.extend(("", f"--- {title} ---"))
        lines.extend(f"{label:<22}: {value}" for label, value in fields)
    return "\n".join(lines)


def _render_voice_status_text(status: VoiceStatus, host: str) -> str:
    def display(value: str | None) -> str:
        return value if value is not None else "Unavailable"

    lines = [
        f"=== NETGEAR CM500 voice status @ {host} ===",
        f"{'Line 1':<22}: {display(status.line_1_status)}",
        f"{'Line 2':<22}: {display(status.line_2_status)}",
        f"{'MTA MAC address':<22}: {display(status.mta_mac)}",
        f"{'MTA IP address':<22}: {display(status.mta_ip)}",
        f"{'MTA FQDN':<22}: {display(status.mta_fqdn)}",
        f"{'Telephony signaling':<22}: {display(status.telephony_signaling)}",
    ]
    return "\n".join(lines)


def _run_gateway(args: argparse.Namespace, user: str, password: str) -> int:
    if args.monitor:
        return _run_monitor_loop(
            lambda: _render_gateway_status_text(
                get_gateway_status(args.host, user, password), args.host
            ),
            args.interval,
            sys.stdout,
        )

    status = get_gateway_status(args.host, user, password)
    if args.json:
        print(json.dumps(dataclasses.asdict(status), indent=2))
    else:
        print(_render_gateway_status_text(status, args.host))
    return 0


def _run_voice(args: argparse.Namespace, user: str, password: str) -> int:
    if args.monitor:
        return _run_monitor_loop(
            lambda: _render_voice_status_text(
                get_voice_status(args.host, user, password), args.host
            ),
            args.interval,
            sys.stdout,
        )

    status = get_voice_status(args.host, user, password)
    if args.json:
        print(json.dumps(dataclasses.asdict(status), indent=2))
    else:
        print(_render_voice_status_text(status, args.host))
    return 0


def _run_monitor_loop(
    poll_and_render: Callable[[], str], interval: float, output: TextIO
) -> int:
    try:
        while True:
            snapshot = poll_and_render()
            if output.isatty():
                output.write("\x1b[2J\x1b[H")
            output.write(snapshot)
            output.write("\n")
            output.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        return 130


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``netgear-cm500-cli`` console script."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.monitor and args.json:
        parser.error(
            "--monitor cannot be combined with --json (JSON is single-shot only)"
        )
    if getattr(args, "op_vault", None) and getattr(args, "op_item", None) is None:
        parser.error("--op-vault requires --op-item")

    # JSON is machine-readable: never inject ANSI codes into it.
    force_off = args.no_color or args.json
    palette = palette_for(sys.stdout, force_off=force_off)

    try:
        user, password = _resolve_credentials(args)
        if args.command == "events":
            return _run_events(args, user, password, palette)
        if args.command == "gateway":
            return _run_gateway(args, user, password)
        if args.command == "voice":
            return _run_voice(args, user, password)
        return _run_status(args, user, password, palette)
    except (CredentialError, ModemError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
