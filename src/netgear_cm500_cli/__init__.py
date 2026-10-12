"""Fetch and summarize status from a NETGEAR CM500 cable modem."""

from __future__ import annotations

from netgear_cm500_cli.cli import main
from netgear_cm500_cli.modem import (
    DownstreamChannel,
    EventLogEntry,
    GeneralStatus,
    ModemError,
    ModemStatus,
    Severity,
    UpstreamChannel,
    get_event_log,
    get_status,
    parse_event_log,
    parse_status,
)

__all__ = [
    "DownstreamChannel",
    "EventLogEntry",
    "GeneralStatus",
    "ModemError",
    "ModemStatus",
    "Severity",
    "UpstreamChannel",
    "get_event_log",
    "get_status",
    "main",
    "parse_event_log",
    "parse_status",
]
