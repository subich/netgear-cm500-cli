"""Command-line interface for the cm500-status tool.

Fetches status or the event log from a NETGEAR CM500 modem and renders it as a
human-readable summary or JSON. Credentials are taken from the environment or
an interactive prompt; the password is never accepted as a command-line
argument so it does not leak into shell history or the process list.

Text output is colorized to highlight out-of-spec signal values and severe
events. Color is emitted only to an interactive terminal and is suppressed for
JSON, pipes, ``--no-color``, or the ``NO_COLOR`` convention.

Subcommands:
    status  (default)  connection summary and downstream/upstream channel tables
    events             most recent entries from the DOCSIS event log
"""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import os
import sys
from collections.abc import Sequence

from cm500_status.color import Palette, palette_for
from cm500_status.modem import (
    DEFAULT_HOST,
    DEFAULT_USER,
    DownstreamChannel,
    EventLogEntry,
    ModemError,
    ModemStatus,
    Severity,
    UpstreamChannel,
    get_event_log,
    get_status,
)

_PASSWORD_ENV_VAR = "CM500_PASS"
_HOST_ENV_VAR = "CM500_HOST"
_USER_ENV_VAR = "CM500_USER"
_DEFAULT_EVENT_LIMIT = 20

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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cm500-status",
        description="Fetch status or the event log from a NETGEAR CM500 cable modem.",
    )
    _add_common_arguments(parser)

    subparsers = parser.add_subparsers(dest="command")

    status_parser = subparsers.add_parser(
        "status", help="connection summary and channel tables (default)"
    )
    _add_common_arguments(status_parser)

    events_parser = subparsers.add_parser(
        "events", help="most recent entries from the DOCSIS event log"
    )
    _add_common_arguments(events_parser)
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

    return parser


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
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


def _resolve_password(host: str, user: str) -> str:
    """Return the admin password from the environment or an interactive prompt.

    The password is intentionally not a CLI argument: command-line values leak
    into shell history and the process table.
    """
    password = os.environ.get(_PASSWORD_ENV_VAR)
    if password:
        return password
    return getpass.getpass(f"Password for {user}@{host}: ")


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


def _run_status(args: argparse.Namespace, password: str, palette: Palette) -> int:
    status = get_status(args.host, args.user, password)
    if args.json:
        print(json.dumps(_status_to_dict(status), indent=2))
    else:
        print(_render_status_text(status, args.host, palette))
    return 0


def _run_events(args: argparse.Namespace, password: str, palette: Palette) -> int:
    events = get_event_log(args.host, args.user, password)
    events = _filter_by_severity(events, args.min_severity)
    events = _limit_events(events, args.limit)
    if args.json:
        print(json.dumps([dataclasses.asdict(event) for event in events], indent=2))
    else:
        print(_render_events_text(events, args.host, palette))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``cm500-status`` console script."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # JSON is machine-readable: never inject ANSI codes into it.
    force_off = args.no_color or args.json
    palette = palette_for(sys.stdout, force_off=force_off)

    password = _resolve_password(args.host, args.user)

    try:
        if args.command == "events":
            return _run_events(args, password, palette)
        return _run_status(args, password, palette)
    except ModemError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
