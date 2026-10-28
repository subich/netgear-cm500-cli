"""Fetch and parse status data from a NETGEAR CM500 cable modem.

The CM500 web UI serves its DOCSIS status page (``DocsisStatus.htm``) with the
live values embedded in JavaScript variables as pipe-delimited strings. This
module fetches that page and parses those strings into structured dataclasses.

Auth note: the modem uses HTTP Basic auth, but its firmware only accepts the
request once an ``XSRF_TOKEN`` cookie (handed out on the first request) is
present. :func:`fetch_status_page` fetches the token first, then sends it with
the authenticated call.
"""

from __future__ import annotations

import base64
import html
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import IntEnum
from http.cookiejar import CookieJar
from xml.etree import ElementTree

DEFAULT_HOST = "192.168.100.1"
DEFAULT_USER = "admin"
_TIMEOUT_SECONDS = 15
_HTTP_UNAUTHORIZED = 401
_GATEWAY_REQUIRED_FIELDS = 17
_VOICE_REQUIRED_FIELDS = 6

# Matches the active (uncommented) assignment:
#   var tagValueList = '...';
# Commented example lines start with "//" and are skipped by the per-function
# scan in _extract_tag_values, which keeps the last match inside the function.
_ASSIGNMENT = re.compile(r"""var tagValueList = (?:'([^']*)'|"([^"]*)")""")

# The event log page embeds its rows as an XML document inside a JS string:
#   var xmlFormat = '<docsDevEventTable>...</docsDevEventTable>';
# The closing tags are escaped as <\/tag>; _parse_event_log unescapes them.
_XML_FORMAT = re.compile(r"var xmlFormat = '(.*?)';", re.DOTALL)


# DOCSIS event severity levels follow the RFC 5424 syslog scale (lower is more
# severe). Observed on this modem: 3 = Error, 5 = Notice, 6 = Information.
class Severity(IntEnum):
    """DOCSIS event severity on the syslog priority scale (lower is worse)."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATION = 6
    DEBUG = 7

    @property
    def label(self) -> str:
        """Return the title-cased display name (e.g. ``Error``)."""
        return self.name.title()

    @classmethod
    def from_name(cls, name: str) -> Severity:
        """Return the severity whose label matches ``name`` (case-insensitive).

        Raises :class:`ValueError` when the name is not a known severity.
        """
        try:
            return cls[name.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {name}") from None


class ModemError(RuntimeError):
    """Raised when the modem cannot be reached or its page cannot be parsed."""


@dataclass(frozen=True)
class GeneralStatus:
    """Top-level connection summary from the status page."""

    downstream_frequency_hz: str
    downstream_lock: str
    connectivity_state: str
    connectivity_comment: str
    boot_state: str
    boot_comment: str
    security: str
    security_comment: str
    current_system_time: str
    system_uptime: str


@dataclass(frozen=True)
class DownstreamChannel:
    """One downstream bonded channel."""

    channel: str
    lock_status: str
    modulation: str
    channel_id: str
    frequency: str
    power_dbmv: str
    snr_db: str
    corrected: str
    uncorrected: str


@dataclass(frozen=True)
class UpstreamChannel:
    """One upstream bonded channel."""

    channel: str
    lock_status: str
    channel_type: str
    channel_id: str
    symbol_rate: str
    frequency: str
    power_dbmv: str


@dataclass(frozen=True)
class EventLogEntry:
    """One row from the modem's DOCSIS event log.

    ``level`` is the raw numeric DOCSIS severity as a string (lower is more
    severe: 3 = Error, 5 = Notice, 6 = Information); ``severity`` is its
    human-readable name.
    """

    index: str
    first_time: str
    last_time: str
    count: str
    level: str
    severity: str
    event_id: str
    text: str

    @property
    def severity_level(self) -> Severity | None:
        """Return the parsed :class:`Severity`, or ``None`` for an unknown level.

        An unknown level cannot be ordered against a threshold, so severity
        filtering treats it as "always included" rather than silently dropping
        a potentially important event.
        """
        try:
            return Severity(int(self.level))
        except ValueError:
            return None


@dataclass(frozen=True)
class ModemStatus:
    """Full parsed status: general summary plus channel tables."""

    general: GeneralStatus
    downstream: list[DownstreamChannel]
    upstream: list[UpstreamChannel]


@dataclass(frozen=True)
class GatewayStatus:
    """Read-only gateway, LAN, and wireless details from the status page."""

    hardware_version: str
    firmware_version: str
    serial_number: str
    cm_certificate: str
    cable_mac: str
    cable_ip_mask: str
    cable_gateway: str
    cable_dns: str
    network_access: str
    internet_mac: str
    internet_ip_mask: str
    internet_dhcp: str
    internet_gateway: str
    internet_dns: str
    lan_mac: str
    lan_ip_mask: str
    lan_dhcp: str
    wireless_24_region: str
    wireless_24_channel: str
    wireless_24_mode: str
    wireless_24_access_point: str
    wireless_24_broadcast_name: str
    wireless_24_isolation: str
    wireless_5_region: str
    wireless_5_channel: str
    wireless_5_mode: str
    wireless_5_access_point: str
    wireless_5_broadcast_name: str
    wireless_5_isolation: str
    system_uptime: str
    current_system_time: str


@dataclass(frozen=True)
class VoiceStatus:
    """Read-only MTA line and provisioning details."""

    line_1_status: str | None
    line_2_status: str | None
    mta_mac: str | None
    mta_ip: str | None
    mta_fqdn: str | None
    telephony_signaling: str | None


def _basic_auth_header(user: str, password: str) -> str:
    """Return the HTTP Basic ``Authorization`` header value for the credentials.

    Credentials are supplied by the caller at runtime; nothing is stored here.
    """
    encoded = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
    return f"Basic {encoded}"


def _fetch_page(
    host: str, user: str, password: str, path: str, *, timeout: float
) -> str:
    """Return the raw HTML of a modem page at ``path``.

    Performs the two-step auth dance: an unauthenticated request to collect the
    ``XSRF_TOKEN`` cookie, followed by a Basic-auth request that sends the
    cookie back.
    """
    base = f"http://{host}/"
    page_url = f"http://{host}/{path}"

    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    # First request is expected to 401; it hands out the XSRF cookie.
    try:
        opener.open(base, timeout=timeout)
    except urllib.error.HTTPError:
        pass  # 401 is expected here; the cookie is captured regardless.
    except urllib.error.URLError as exc:
        raise ModemError(f"could not reach modem at {host}: {exc.reason}") from exc

    request = urllib.request.Request(page_url)
    request.add_header("Authorization", _basic_auth_header(user, password))
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code == _HTTP_UNAUTHORIZED:
            raise ModemError(
                "authentication failed: check username and password"
            ) from exc
        raise ModemError(f"request to {page_url} failed: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ModemError(f"could not reach modem at {host}: {exc.reason}") from exc


def fetch_status_page(
    host: str, user: str, password: str, *, timeout: float = _TIMEOUT_SECONDS
) -> str:
    """Return the raw HTML of the modem's DOCSIS status page."""
    return _fetch_page(host, user, password, "DocsisStatus.htm", timeout=timeout)


def fetch_event_log_page(
    host: str, user: str, password: str, *, timeout: float = _TIMEOUT_SECONDS
) -> str:
    """Return the raw HTML of the modem's event log page."""
    return _fetch_page(host, user, password, "eventLog.htm", timeout=timeout)


def fetch_gateway_status_page(
    host: str, user: str, password: str, *, timeout: float = _TIMEOUT_SECONDS
) -> str:
    """Return the raw HTML of the read-only gateway status page."""
    return _fetch_page(host, user, password, "RouterStatus.htm", timeout=timeout)


def fetch_voice_status_page(
    host: str, user: str, password: str, *, timeout: float = _TIMEOUT_SECONDS
) -> str:
    """Return the raw HTML of the read-only voice status page."""
    return _fetch_page(host, user, password, "MtaStatus.htm", timeout=timeout)


def _extract_tag_value_assignment(html: str, function_name: str) -> str | None:
    """Return the active tagValueList string from a JavaScript function.

    Each target function defines several commented-out example lists followed by
    the real one. This scans only within the named function body and ignores
    both JavaScript line and block comments.
    """
    in_function = False
    in_block_comment = False
    found: str | None = None
    func_marker = f"function {function_name}("

    for line in html.splitlines():
        stripped = line.strip()
        if func_marker in line:
            in_function = True
        if not in_function:
            continue
        if in_block_comment or stripped.startswith("/*"):
            in_block_comment = "*/" not in line
            continue
        if stripped.startswith("//"):
            continue  # commented-out example assignment
        match = _ASSIGNMENT.search(line)
        if match:
            found = match.group(1) if match.group(1) is not None else match.group(2)
        if stripped == "}":
            break

    return found


def _extract_tag_values(html: str, function_name: str) -> list[str]:
    """Return the pipe-split values of the active tagValueList in a JS function."""
    assignment = _extract_tag_value_assignment(html, function_name)
    if assignment is None:
        return []
    # The page's lists carry a trailing empty field from the terminal "|";
    # drop it so channel counts line up.
    parts = assignment.split("|")
    if assignment.endswith("|"):
        parts.pop()
    return parts


def _parse_general(values: list[str]) -> GeneralStatus:
    """Map the general tagValueList into :class:`GeneralStatus`.

    Field order comes from InitUpdateView in the page source:
    0 downstream freq, 1 lock, 2/3 connectivity, 4/5 boot, 8/9 security,
    10 current time, 14 uptime.
    """

    def at(index: int) -> str:
        return values[index] if index < len(values) else "?"

    return GeneralStatus(
        downstream_frequency_hz=at(0),
        downstream_lock=at(1),
        connectivity_state=at(2),
        connectivity_comment=at(3),
        boot_state=at(4),
        boot_comment=at(5),
        security=at(8),
        security_comment=at(9),
        current_system_time=at(10),
        system_uptime=at(14),
    )


def _parse_downstream(values: list[str]) -> list[DownstreamChannel]:
    """Parse the downstream table: a count followed by 9 fields per channel."""
    if not values:
        return []
    count = _safe_int(values[0])
    fields_per_channel = 9
    channels: list[DownstreamChannel] = []
    idx = 1
    for _ in range(count):
        row = values[idx : idx + fields_per_channel]
        if len(row) < fields_per_channel:
            break
        channels.append(
            DownstreamChannel(
                channel=row[0],
                lock_status=row[1],
                modulation=row[2],
                channel_id=row[3],
                frequency=row[4],
                power_dbmv=row[5],
                snr_db=row[6],
                corrected=row[7],
                uncorrected=row[8],
            )
        )
        idx += fields_per_channel
    return channels


def _parse_upstream(values: list[str]) -> list[UpstreamChannel]:
    """Parse the upstream table: a count followed by 7 fields per channel."""
    if not values:
        return []
    count = _safe_int(values[0])
    fields_per_channel = 7
    channels: list[UpstreamChannel] = []
    idx = 1
    for _ in range(count):
        row = values[idx : idx + fields_per_channel]
        if len(row) < fields_per_channel:
            break
        channels.append(
            UpstreamChannel(
                channel=row[0],
                lock_status=row[1],
                channel_type=row[2],
                channel_id=row[3],
                symbol_rate=row[4],
                frequency=row[5],
                power_dbmv=row[6],
            )
        )
        idx += fields_per_channel
    return channels


def _safe_int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0


def parse_status(html: str) -> ModemStatus:
    """Parse the full status page HTML into a :class:`ModemStatus`."""
    general_values = _extract_tag_values(html, "InitTagValue")
    if not general_values:
        raise ModemError(
            "could not parse status data from page (firmware layout may differ)"
        )
    return ModemStatus(
        general=_parse_general(general_values),
        downstream=_parse_downstream(_extract_tag_values(html, "InitDsTableTagValue")),
        upstream=_parse_upstream(_extract_tag_values(html, "InitUsTableTagValue")),
    )


def get_status(
    host: str = DEFAULT_HOST,
    user: str = DEFAULT_USER,
    password: str = "",
    *,
    timeout: float = _TIMEOUT_SECONDS,
) -> ModemStatus:
    """Fetch and parse the modem status in one call."""
    html = fetch_status_page(host, user, password, timeout=timeout)
    return parse_status(html)


def parse_gateway_status(html_text: str) -> GatewayStatus:
    """Parse read-only gateway details from the router status page."""
    values = _extract_tag_values(html_text, "InitTagValue")
    if len(values) < _GATEWAY_REQUIRED_FIELDS:
        raise ModemError(
            "could not parse gateway status data from page (firmware layout may differ)"
        )

    def at(index: int) -> str:
        if index >= len(values):
            return ""
        return html.unescape(values[index]).replace("\xa0", " ").strip()

    return GatewayStatus(
        hardware_version=at(0),
        firmware_version=at(1),
        serial_number=at(2),
        cm_certificate=at(3),
        cable_mac=at(4),
        cable_ip_mask=at(5),
        cable_gateway=at(6),
        cable_dns=at(7),
        network_access=at(8),
        internet_mac=at(9),
        internet_ip_mask=at(10),
        internet_dhcp=at(11),
        internet_gateway=at(12),
        internet_dns=at(13),
        lan_mac=at(14),
        lan_ip_mask=at(15),
        lan_dhcp=at(16),
        wireless_24_region=at(18),
        wireless_24_channel=at(19),
        wireless_24_mode=at(20),
        wireless_24_access_point=at(21),
        wireless_24_broadcast_name=at(22),
        wireless_24_isolation=at(23),
        wireless_5_region=at(25),
        wireless_5_channel=at(26),
        wireless_5_mode=at(27),
        wireless_5_access_point=at(28),
        wireless_5_broadcast_name=at(29),
        wireless_5_isolation=at(30),
        system_uptime=at(35),
        current_system_time=at(36),
    )


def get_gateway_status(
    host: str = DEFAULT_HOST,
    user: str = DEFAULT_USER,
    password: str = "",
    *,
    timeout: float = _TIMEOUT_SECONDS,
) -> GatewayStatus:
    """Fetch and parse read-only gateway details in one call."""
    page = fetch_gateway_status_page(host, user, password, timeout=timeout)
    return parse_gateway_status(page)


def parse_voice_status(html_text: str) -> VoiceStatus:
    """Parse read-only MTA line and provisioning details."""
    assignment = _extract_tag_value_assignment(html_text, "InitTagValue")
    if assignment is None:
        raise ModemError(
            "could not parse voice status data from page (firmware layout may differ)"
        )
    values = _extract_tag_values(html_text, "InitTagValue")
    if values == [""]:
        return VoiceStatus(
            line_1_status=None,
            line_2_status=None,
            mta_mac=None,
            mta_ip=None,
            mta_fqdn=None,
            telephony_signaling=None,
        )
    if len(values) < _VOICE_REQUIRED_FIELDS:
        raise ModemError(
            "could not parse voice status data from page (firmware layout may differ)"
        )

    def at(index: int) -> str:
        return html.unescape(values[index]).replace("\xa0", " ").strip()

    return VoiceStatus(
        line_1_status=at(0),
        line_2_status=at(1),
        mta_mac=at(2),
        mta_ip=at(3),
        mta_fqdn=at(4),
        telephony_signaling=at(5),
    )


def get_voice_status(
    host: str = DEFAULT_HOST,
    user: str = DEFAULT_USER,
    password: str = "",
    *,
    timeout: float = _TIMEOUT_SECONDS,
) -> VoiceStatus:
    """Fetch and parse read-only voice status in one call."""
    page = fetch_voice_status_page(host, user, password, timeout=timeout)
    return parse_voice_status(page)


def _severity_name(level: str) -> str:
    try:
        return Severity(int(level)).label
    except ValueError:
        return level


def parse_event_log(html: str) -> list[EventLogEntry]:
    """Parse the event log page HTML into a list of :class:`EventLogEntry`.

    Entries are returned newest-first, matching the modem's own ordering (it
    lists the highest ``docsDevEvIndex`` first).
    """
    match = _XML_FORMAT.search(html)
    if match is None:
        raise ModemError(
            "could not parse event log from page (firmware layout may differ)"
        )

    # The embedded XML escapes closing tags as <\/tag>; undo that before parsing.
    xml_text = match.group(1).replace("<\\/", "</")

    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise ModemError(f"event log XML is malformed: {exc}") from exc

    entries: list[EventLogEntry] = []
    for row in root.findall("tr"):
        level = _text(row, "docsDevEvLevel")
        entries.append(
            EventLogEntry(
                index=_text(row, "docsDevEvIndex"),
                first_time=_text(row, "docsDevEvFirstTime"),
                last_time=_text(row, "docsDevEvLastTime"),
                count=_text(row, "docsDevEvCounts"),
                level=level,
                severity=_severity_name(level),
                event_id=_text(row, "docsDevEvId"),
                text=_text(row, "docsDevEvText"),
            )
        )
    return entries


def _text(row: ElementTree.Element, tag: str) -> str:
    child = row.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def get_event_log(
    host: str = DEFAULT_HOST,
    user: str = DEFAULT_USER,
    password: str = "",
    *,
    timeout: float = _TIMEOUT_SECONDS,
) -> list[EventLogEntry]:
    """Fetch and parse the modem event log in one call (newest first)."""
    html = fetch_event_log_page(host, user, password, timeout=timeout)
    return parse_event_log(html)
