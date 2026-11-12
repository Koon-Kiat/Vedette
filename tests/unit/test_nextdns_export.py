"""Reading a NextDNS log export (the CSV downloaded from the dashboard)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel.sources.nextdns import parse_log_entry
from sentinel.sources.nextdns_export import ExportFormatError, read_export

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "nextdns" / "export.csv"
HEADER = (
    "timestamp,domain,query_type,dnssec,protocol,client_ip,status,reasons,"
    "destination_country,root_domain,device_id,device_name,device_model,"
    "device_local_ip,matched_name,client_name"
)

ROW_START = "2026-03-15T04:33:59.001Z,www.example.org,A,false,DNS-over-HTTPS,198.51.100.7"


def write(tmp_path: Path, text: str, *, bom: bool = False) -> Path:
    path = tmp_path / "export.csv"
    path.write_text(text, encoding="utf-8-sig" if bom else "utf-8", newline="")
    return path


def test_rows_become_events_with_every_available_field() -> None:
    result = read_export(FIXTURE, "abc123", raw=False)

    blocked = next(e for e in result.events if e.fqdn == "telemetry.vendor.example")
    assert blocked.profile_id == "abc123"
    assert blocked.ts == datetime(2026, 3, 15, 4, 34, 5, 203000, tzinfo=UTC)
    assert blocked.root == "vendor.example"
    assert blocked.status == "blocked"
    assert [reason.id for reason in blocked.reasons] == ["blocklist:sample-list", "native:sample"]
    assert blocked.device_id == "8TD1G"
    assert blocked.device_name == "Living Room TV"
    assert blocked.client_ip == "198.51.100.7"
    assert blocked.protocol == "DNS-over-HTTPS"
    assert blocked.source == "nextdns"


def test_an_empty_status_means_the_default_action() -> None:
    result = read_export(FIXTURE, "abc123", raw=False)

    allowed = next(e for e in result.events if e.fqdn == "www.example.org")
    assert allowed.status == "default"
    assert allowed.reasons == ()


def test_empty_device_columns_mean_no_device() -> None:
    result = read_export(FIXTURE, "abc123", raw=False)

    mixed = next(e for e in result.events if e.fqdn == "www.mixed.example")
    assert mixed.device_id is None
    assert mixed.device_name is None


def test_a_file_event_has_the_same_id_as_the_same_event_from_the_api() -> None:
    from_api = parse_log_entry(
        "abc123",
        {
            "timestamp": "2026-03-15T04:33:59.001Z",
            "domain": "www.example.org",
            "root": "example.org",
            "encrypted": True,
            "protocol": "DNS-over-HTTPS",
            "clientIp": "198.51.100.7",
            "device": {"id": "8TD1G", "name": "Living Room TV"},
            "status": "default",
            "reasons": [],
        },
    )

    result = read_export(FIXTURE, "abc123", raw=False)

    assert from_api.event_id in {event.event_id for event in result.events}


def test_default_mode_keeps_navigational_queries_once_each() -> None:
    result = read_export(FIXTURE, "abc123", raw=False)

    assert sorted(event.fqdn for event in result.events) == [
        "telemetry.vendor.example",
        "www.example.org",
        "www.mixed.example",
    ]
    assert result.rows == 7
    assert result.skipped_other_types == 1, "the SRV query"
    assert result.skipped_malformed == 2, "the bad timestamp and the empty domain"
    assert result.merged_same_instant == 1, "A and HTTPS for one name at the same instant"


def test_raw_mode_keeps_every_query_type_as_its_own_event() -> None:
    result = read_export(FIXTURE, "abc123", raw=True)

    assert sorted(event.fqdn for event in result.events) == [
        "_ldap._tcp.corp.example",
        "telemetry.vendor.example",
        "telemetry.vendor.example",
        "www.example.org",
        "www.mixed.example",
    ]
    assert len({event.event_id for event in result.events}) == 5
    assert result.skipped_other_types == 0
    assert result.merged_same_instant == 0


def test_raw_mode_file_events_match_raw_api_events() -> None:
    from_api = parse_log_entry(
        "abc123",
        {
            "timestamp": "2026-03-15T04:34:05.203Z",
            "domain": "telemetry.vendor.example",
            "type": "HTTPS",
            "protocol": "DNS-over-HTTPS",
            "clientIp": "198.51.100.7",
            "device": {"id": "8TD1G", "name": "Living Room TV"},
            "status": "blocked",
        },
        raw=True,
    )

    result = read_export(FIXTURE, "abc123", raw=True)

    assert from_api.event_id in {event.event_id for event in result.events}


def test_api_query_type_changes_the_id_only_in_raw_mode() -> None:
    entry = {
        "timestamp": "2026-03-15T04:34:05.203Z",
        "domain": "telemetry.vendor.example",
        "status": "blocked",
    }
    a, https = {**entry, "type": "A"}, {**entry, "type": "HTTPS"}

    assert (
        parse_log_entry("abc123", a, raw=True).event_id
        != parse_log_entry("abc123", https, raw=True).event_id
    )
    assert parse_log_entry("abc123", a).event_id == parse_log_entry("abc123", https).event_id
    assert parse_log_entry("abc123", a).event_id == parse_log_entry("abc123", entry).event_id


def test_a_byte_order_mark_is_tolerated(tmp_path: Path) -> None:
    row = ROW_START + ",,,,example.org,,,,,,x"
    path = write(tmp_path, f"{HEADER}\r\n{row}\r\n", bom=True)

    assert [event.fqdn for event in read_export(path, "abc123", raw=False).events] == [
        "www.example.org"
    ]


def test_a_file_without_the_expected_columns_is_rejected(tmp_path: Path) -> None:
    path = write(tmp_path, "when,name\r\n2026-03-15,www.example.org\r\n")

    with pytest.raises(ExportFormatError, match="timestamp"):
        read_export(path, "abc123", raw=False)


def test_an_empty_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ExportFormatError):
        read_export(write(tmp_path, ""), "abc123", raw=False)


def test_overlong_untrusted_fields_are_truncated_not_dropped(tmp_path: Path) -> None:
    name = "N" * 5000
    row = ROW_START + f",,,,example.org,D1,{name},,,,x"
    path = write(tmp_path, f"{HEADER}\r\n{row}\r\n")

    (event,) = read_export(path, "abc123", raw=False).events

    assert event.device_name is not None
    assert len(event.device_name) == 256
