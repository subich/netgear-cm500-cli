"""Tests for the modem page parser.

The HTML fixture mirrors the real CM500 DocsisStatus.htm layout: each JS
function carries commented-out example assignments followed by the live one,
and every pipe-delimited list ends with a trailing empty field.
"""

from __future__ import annotations

import pytest

from netgear_cm500_cli import modem
from netgear_cm500_cli.modem import ModemError, parse_status

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


def test_parse_gateway_status_maps_router_fields() -> None:
    values = [""] * 37
    values[0:17] = [
        "hardware",
        "firmware",
        "serial",
        "installed",
        "cable-mac",
        "cable-ip/mask",
        "cable-gateway",
        "cable-dns",
        "allowed",
        "internet-mac",
        "internet-ip/mask",
        "DHCP",
        "internet-gateway",
        "internet-dns",
        "lan-mac",
        "lan-ip/mask",
        "LAN DHCP",
    ]
    values[18:24] = ["region", "channel", "mode", "enabled", "ssid", "off"]
    values[25:31] = ["region5", "channel5", "mode5", "enabled5", "ssid5", "off5"]
    values[35:37] = ["uptime", "current-time"]
    page = (
        "<script>function InitTagValue(){\n"
        "/*\nvar tagValueList = 'commented|firmware|sample';\n*/\n"
        f'var tagValueList = "{"|".join(values)}";'
        "\nreturn tagValueList.split('|');\n}</script>"
    )

    status = modem.parse_gateway_status(page)

    assert status.hardware_version == "hardware"
    assert status.cable_mac == "cable-mac"
    assert status.internet_gateway == "internet-gateway"
    assert status.wireless_24_broadcast_name == "ssid"
    assert status.wireless_5_channel == "channel5"
    assert status.system_uptime == "uptime"


def test_parse_gateway_status_decodes_entities_and_rejects_missing_data() -> None:
    values = ["value"] * 17
    values[4] = "A&amp;B"
    page = (
        "<script>function InitTagValue(){"
        f"var tagValueList = '{'|'.join(values)}';"
        "return tagValueList.split('|');}</script>"
    )
    assert modem.parse_gateway_status(page).cable_mac == "A&B"
    with pytest.raises(ModemError, match="could not parse gateway status data"):
        modem.parse_gateway_status("<html></html>")


def test_parse_voice_status_maps_line_and_provisioning_fields() -> None:
    page = (
        "<script>function InitTagValue(){"
        'var tagValueList = "Connected|Disconnected|mta-mac|mta-ip|mta-fqdn|SIP";'
        "return tagValueList.split('|');}</script>"
    )

    status = modem.parse_voice_status(page)

    assert status.line_1_status == "Connected"
    assert status.line_2_status == "Disconnected"
    assert status.mta_mac == "mta-mac"
    assert status.mta_ip == "mta-ip"
    assert status.mta_fqdn == "mta-fqdn"
    assert status.telephony_signaling == "SIP"


def test_parse_voice_status_rejects_missing_data() -> None:
    with pytest.raises(ModemError, match="could not parse voice status data"):
        modem.parse_voice_status("<html></html>")


def test_parse_voice_status_accepts_empty_firmware_payload() -> None:
    page = (
        "<script>function InitTagValue(){"
        "var tagValueList = '';"
        "return tagValueList.split('|');}</script>"
    )

    status = modem.parse_voice_status(page)

    assert status.line_1_status is None
    assert status.line_2_status is None
    assert status.mta_mac is None
