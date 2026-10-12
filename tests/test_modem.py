"""Tests for the modem page parser.

The HTML fixture mirrors the real CM500 DocsisStatus.htm layout: each JS
function carries commented-out example assignments followed by the live one,
and every pipe-delimited list ends with a trailing empty field.
"""

from __future__ import annotations

import pytest

from cm500_status import modem
from cm500_status.modem import ModemError, parse_status

# Abridged but structurally faithful copy of the modem's status page. Includes
# the commented example assignments the parser must skip and the trailing "|".
_SAMPLE_HTML = """
<html><head></head><body><script>
function InitTagValue()
{
    //var tagValueList = "0|In Progress|In Progress|Not Synchronized";
    var tagValueList = '633000000|Locked|OK|Operational|OK|Operational|&nbsp;|&nbsp;|Disabled|Disabled|Mon Oct 12 15:53:43 2026|0|1|0|1 day 23:21:39|1|';
    return tagValueList.split("|");
}
function InitUsTableTagValue()
{
    //var tagValueList = "4|1|Not Locked|Unknown|0|0|0|0.0";
    var tagValueList = '2|1|Locked|ATDMA|7|5120|31000000 Hz|46.3|2|Not Locked|Unknown|0|0|0 Hz|0.0|';
    return tagValueList.split("|");
}
function InitDsTableTagValue()
{
    //var tagValueList = "8|...";
    var tagValueList = '2|1|Locked|QAM256|29|633000000 Hz|-18.3|33.6|3823138|99990|2|Not Locked|Unknown|4|483000000 Hz|0.0|0.0|0|0|';
    return tagValueList.split("|");
}
</script></body></html>
"""


def test_parse_general_maps_expected_fields() -> None:
    status = parse_status(_SAMPLE_HTML)
    general = status.general
    assert general.downstream_frequency_hz == "633000000"
    assert general.downstream_lock == "Locked"
    assert general.connectivity_state == "OK"
    assert general.connectivity_comment == "Operational"
    assert general.boot_state == "OK"
    assert general.security == "Disabled"
    assert general.current_system_time == "Mon Oct 12 15:53:43 2026"
    assert general.system_uptime == "1 day 23:21:39"


def test_parse_downstream_counts_and_fields() -> None:
    status = parse_status(_SAMPLE_HTML)
    assert len(status.downstream) == 2
    first = status.downstream[0]
    assert first.channel == "1"
    assert first.lock_status == "Locked"
    assert first.modulation == "QAM256"
    assert first.channel_id == "29"
    assert first.frequency == "633000000 Hz"
    assert first.power_dbmv == "-18.3"
    assert first.snr_db == "33.6"
    assert first.corrected == "3823138"
    assert first.uncorrected == "99990"
    assert status.downstream[1].lock_status == "Not Locked"


def test_parse_upstream_counts_and_fields() -> None:
    status = parse_status(_SAMPLE_HTML)
    assert len(status.upstream) == 2
    first = status.upstream[0]
    assert first.channel == "1"
    assert first.lock_status == "Locked"
    assert first.channel_type == "ATDMA"
    assert first.channel_id == "7"
    assert first.symbol_rate == "5120"
    assert first.frequency == "31000000 Hz"
    assert first.power_dbmv == "46.3"


def test_parse_status_raises_when_general_block_missing() -> None:
    with pytest.raises(ModemError, match="could not parse status data"):
        parse_status("<html><body>no data here</body></html>")


def test_extract_skips_commented_assignments() -> None:
    # The commented example in InitTagValue must not win over the live value.
    values = modem._extract_tag_values(_SAMPLE_HTML, "InitTagValue")
    assert values[0] == "633000000"
    assert "In Progress" not in values


def test_extract_drops_trailing_empty_field() -> None:
    values = modem._extract_tag_values(_SAMPLE_HTML, "InitDsTableTagValue")
    # Count field says 2 channels * 9 fields + 1 count = 19, no trailing "".
    assert values[-1] != ""
    assert len(values) == 1 + 2 * 9


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("16", 16), ("0", 0), ("", 0), ("notanumber", 0)],
)
def test_safe_int(raw: str, expected: int) -> None:
    assert modem._safe_int(raw) == expected


def test_get_status_uses_fetch_and_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    # Stub the network boundary so get_status exercises real parsing offline.
    monkeypatch.setattr(
        modem, "fetch_status_page", lambda *args, **kwargs: _SAMPLE_HTML
    )
    status = modem.get_status("10.0.0.1", "admin", "secret")
    assert status.general.connectivity_state == "OK"
    assert len(status.downstream) == 2
