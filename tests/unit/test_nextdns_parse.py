import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from vedette.sources.nextdns import parse_log_entry

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "nextdns"


def fixture_entries() -> list[dict[str, Any]]:
    body = json.loads((FIXTURES / "logs_page.json").read_text(encoding="utf-8"))
    entries: list[dict[str, Any]] = body["data"]
    return entries


def test_full_entry_maps_every_field() -> None:
    event = parse_log_entry("abc123", fixture_entries()[0])

    assert event.profile_id == "abc123"
    assert event.ts == datetime(2026, 3, 15, 4, 34, 5, 203000, tzinfo=UTC)
    assert event.fqdn == "telemetry.vendor.example"
    assert event.root == "vendor.example"
    assert event.status == "blocked"
    assert [(r.id, r.name) for r in event.reasons] == [("blocklist:sample-list", "Sample List")]
    assert event.device_id == "8TD1G"
    assert event.device_name == "Living Room TV"
    assert event.client_ip == "198.51.100.7"
    assert event.protocol == "DNS-over-HTTPS"
    assert event.encrypted is True
    assert event.tracker == "vendor"
    assert event.source == "nextdns"
    assert len(event.event_id) == 64


def test_entry_without_optional_fields_still_parses() -> None:
    event = parse_log_entry("abc123", fixture_entries()[1])

    assert event.fqdn == "www.example.org"
    assert event.status == "default"
    assert event.root is None
    assert event.tracker is None
    assert event.device_id is None
    assert event.device_name is None
    assert event.reasons == ()


def test_timestamps_are_normalised_to_utc() -> None:
    entry = {**fixture_entries()[1], "timestamp": "2026-03-15T12:34:05.203+08:00"}

    event = parse_log_entry("abc123", entry)

    assert event.ts == datetime(2026, 3, 15, 4, 34, 5, 203000, tzinfo=UTC)
    assert event.ts.utcoffset() is not None


def test_domain_is_lowercased_and_trailing_dot_removed() -> None:
    entry = {**fixture_entries()[1], "domain": "WWW.Example.ORG."}

    assert parse_log_entry("abc123", entry).fqdn == "www.example.org"


def test_event_id_is_stable_for_the_same_entry() -> None:
    entry = fixture_entries()[0]

    assert parse_log_entry("abc123", entry).event_id == parse_log_entry("abc123", entry).event_id


def test_event_id_ignores_field_order_and_timestamp_spelling() -> None:
    entry = fixture_entries()[0]
    reordered = dict(reversed(list(entry.items())))
    reordered["timestamp"] = "2026-03-15T04:34:05.203000+00:00"

    assert (
        parse_log_entry("abc123", reordered).event_id == parse_log_entry("abc123", entry).event_id
    )


@pytest.mark.parametrize(
    "change",
    [
        {"timestamp": "2026-03-15T04:34:05.204Z"},
        {"domain": "other.vendor.example"},
        {"status": "allowed"},
        {"protocol": "DNS-over-TLS"},
        {"clientIp": "198.51.100.8"},
        {"device": {"id": "OTHER", "name": "Living Room TV"}},
    ],
)
def test_event_id_differs_when_an_identifying_field_differs(change: dict[str, Any]) -> None:
    entry = fixture_entries()[0]

    changed = parse_log_entry("abc123", {**entry, **change})

    assert changed.event_id != parse_log_entry("abc123", entry).event_id


def test_event_id_differs_between_profiles() -> None:
    entry = fixture_entries()[0]

    assert parse_log_entry("abc123", entry).event_id != parse_log_entry("zzz999", entry).event_id


@pytest.mark.parametrize("missing", ["timestamp", "domain", "status"])
def test_entry_missing_a_required_field_is_rejected(missing: str) -> None:
    entry = {k: v for k, v in fixture_entries()[0].items() if k != missing}

    with pytest.raises(ValueError, match=missing):
        parse_log_entry("abc123", entry)


def test_entry_with_an_unparseable_timestamp_is_rejected() -> None:
    with pytest.raises(ValueError, match="timestamp"):
        parse_log_entry("abc123", {**fixture_entries()[0], "timestamp": "yesterday"})


def test_overlong_untrusted_strings_are_truncated_not_dropped() -> None:
    entry = {
        **fixture_entries()[0],
        "device": {"id": "8TD1G", "name": "N" * 5000},
        "reasons": [{"id": "x", "name": "R" * 5000}],
    }

    event = parse_log_entry("abc123", entry)

    assert event.device_name is not None
    assert len(event.device_name) == 256
    assert len(event.reasons[0].name) == 256


def test_wrongly_typed_optional_fields_do_not_drop_the_event() -> None:
    entry = {**fixture_entries()[0], "device": "not-an-object", "reasons": "nope", "tracker": 7}

    event = parse_log_entry("abc123", entry)

    assert event.device_id is None
    assert event.reasons == ()
    assert event.tracker == "7"
