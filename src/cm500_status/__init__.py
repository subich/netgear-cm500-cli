"""Fetch and summarize status from a NETGEAR CM500 cable modem."""

from __future__ import annotations

from cm500_status.cli import main
from cm500_status.modem import (
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
