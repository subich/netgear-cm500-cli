"""Fetch and summarize status from a NETGEAR CM500 cable modem."""

from __future__ import annotations

from netgear_cm500_cli.cli import main
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
    get_event_log,
    get_gateway_status,
    get_status,
    get_voice_status,
    parse_event_log,
    parse_gateway_status,
    parse_status,
    parse_voice_status,
)

__all__ = [
    "DownstreamChannel",
    "EventLogEntry",
    "GatewayStatus",
    "GeneralStatus",
    "ModemError",
    "ModemStatus",
    "Severity",
    "UpstreamChannel",
    "VoiceStatus",
    "get_event_log",
    "get_gateway_status",
    "get_status",
    "get_voice_status",
    "main",
    "parse_event_log",
    "parse_gateway_status",
    "parse_status",
    "parse_voice_status",
]
