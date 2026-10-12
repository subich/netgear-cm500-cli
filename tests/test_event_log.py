"""Tests for the event log parser.

The HTML fixture mirrors the real CM500 eventLog.htm layout: the rows are an
XML document embedded in a JS string, with closing tags escaped as ``<\\/tag>``
and no XML declaration.
"""

from __future__ import annotations

import dataclasses

import pytest

from netgear_cm500_cli import modem
from netgear_cm500_cli.modem import ModemError, Severity, parse_event_log

# Two rows, newest first, matching the modem's escaped-XML embedding.
_SAMPLE_HTML = r"""
<html><head></head><body><script>
function InitTagValue()
{
    var xmlFormat = '<docsDevEventTable><tr><docsDevEvIndex>93<\/docsDevEvIndex><docsDevEvFirstTime>2026-10-12, 15:27:52.0<\/docsDevEvFirstTime><docsDevEvLastTime>2026-10-12, 15:33:00.0<\/docsDevEvLastTime><docsDevEvCounts>7<\/docsDevEvCounts><docsDevEvLevel>5<\/docsDevEvLevel><docsDevEvId>84020300<\/docsDevEvId><docsDevEvText>MDD message timeout;CM-MAC=b0:b9:8a:da:b4:f0;<\/docsDevEvText><\/tr><tr><docsDevEvIndex>78<\/docsDevEvIndex><docsDevEvFirstTime>2026-10-11, 03:17:24.0<\/docsDevEvFirstTime><docsDevEvLastTime>2026-10-11, 03:17:24.0<\/docsDevEvLastTime><docsDevEvCounts>2<\/docsDevEvCounts><docsDevEvLevel>3<\/docsDevEvLevel><docsDevEvId>82000200<\/docsDevEvId><docsDevEvText>No Ranging Response received - T3 time-out<\/docsDevEvText><\/tr><\/docsDevEventTable>';
    return xmlFormat;
}
</script></body></html>
"""


def test_parse_event_log_returns_all_rows_newest_first() -> None:
    events = parse_event_log(_SAMPLE_HTML)
    assert len(events) == 2
    assert events[0].index == "93"
    assert events[1].index == "78"


def test_parse_event_log_maps_fields_and_severity() -> None:
    first = parse_event_log(_SAMPLE_HTML)[0]
    assert first.first_time == "2026-10-12, 15:27:52.0"
    assert first.last_time == "2026-10-12, 15:33:00.0"
    assert first.count == "7"
    assert first.level == "5"
    assert first.severity == "Notice"
    assert first.event_id == "84020300"
    assert first.text.startswith("MDD message timeout")


def test_parse_event_log_maps_error_severity() -> None:
    # Level 3 is the DOCSIS "Error" severity.
    second = parse_event_log(_SAMPLE_HTML)[1]
    assert second.level == "3"
    assert second.severity == "Error"


def test_parse_event_log_raises_when_block_missing() -> None:
    with pytest.raises(ModemError, match="could not parse event log"):
        parse_event_log("<html><body>no xmlFormat here</body></html>")


def test_parse_event_log_raises_on_malformed_xml() -> None:
    broken = r"""
    <script>var xmlFormat = '<docsDevEventTable><tr><unclosed><\/tr>';</script>
    """
    with pytest.raises(ModemError, match="malformed"):
        parse_event_log(broken)


def test_unknown_severity_falls_back_to_raw_level() -> None:
    assert modem._severity_name("99") == "99"


def test_get_event_log_uses_fetch_and_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Stub the network boundary so get_event_log exercises real parsing offline.
    monkeypatch.setattr(
        modem, "fetch_event_log_page", lambda *args, **kwargs: _SAMPLE_HTML
    )
    events = modem.get_event_log("10.0.0.1", "admin", "secret")
    assert len(events) == 2
    assert events[0].severity == "Notice"


# --- Severity enum --------------------------------------------------------


def test_severity_ordering_lower_is_worse() -> None:
    assert Severity.ERROR < Severity.NOTICE < Severity.INFORMATION


def test_severity_label_is_title_case() -> None:
    assert Severity.ERROR.label == "Error"
    assert Severity.INFORMATION.label == "Information"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("error", Severity.ERROR),
        ("ERROR", Severity.ERROR),
        (" Notice ", Severity.NOTICE),
    ],
)
def test_severity_from_name(name: str, expected: Severity) -> None:
    assert Severity.from_name(name) == expected


def test_severity_from_name_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.from_name("bogus")


def test_event_entry_severity_level_parses_known() -> None:
    first = parse_event_log(_SAMPLE_HTML)[0]
    assert first.severity_level is Severity.NOTICE


def test_event_entry_severity_level_none_for_unknown() -> None:
    entry = parse_event_log(_SAMPLE_HTML)[0]
    unknown = dataclasses.replace(entry, level="999")
    assert unknown.severity_level is None
