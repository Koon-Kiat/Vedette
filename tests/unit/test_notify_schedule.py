from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

import pytest

from sentinel.notify.schedule import QuietHours, latest_occurrence, next_occurrence

SGT = ZoneInfo("Asia/Singapore")


def local(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 3, day, hour, minute, tzinfo=SGT)


def test_quiet_hours_that_wrap_past_midnight() -> None:
    quiet = QuietHours.parse("23:00-07:00")
    assert quiet is not None

    assert quiet.contains(local(15, 23, 30), SGT)
    assert quiet.contains(local(16, 6, 59), SGT)
    assert not quiet.contains(local(16, 7, 0), SGT)
    assert not quiet.contains(local(15, 22, 59), SGT)


def test_quiet_hours_within_one_day() -> None:
    quiet = QuietHours.parse("12:00-14:00")
    assert quiet is not None

    assert quiet.contains(local(15, 13), SGT)
    assert not quiet.contains(local(15, 14), SGT)
    assert not quiet.contains(local(15, 11, 59), SGT)


def test_quiet_hours_are_judged_in_the_configured_time_zone() -> None:
    quiet = QuietHours.parse("23:00-07:00")
    assert quiet is not None

    assert quiet.contains(datetime(2026, 3, 15, 16, 0, tzinfo=UTC), SGT)  # 00:00 in Singapore
    assert not quiet.contains(datetime(2026, 3, 15, 4, 0, tzinfo=UTC), SGT)  # 12:00


def test_equal_start_and_end_means_no_quiet_hours() -> None:
    assert QuietHours.parse("00:00-00:00") is None


@pytest.mark.parametrize("text", ["", "23:00", "25:00-07:00", "23:00-07:60", "late"])
def test_malformed_quiet_hours_are_rejected(text: str) -> None:
    with pytest.raises(ValueError):
        QuietHours.parse(text)


def test_end_after_gives_the_next_end_of_quiet_hours() -> None:
    quiet = QuietHours.parse("23:00-07:00")
    assert quiet is not None

    assert quiet.end_after(local(16, 1), SGT) == local(16, 7)
    assert quiet.end_after(local(15, 23, 30), SGT) == local(16, 7)
    assert quiet.end_after(local(15, 23, 30), SGT).tzinfo is not None


def test_overlap_counts_only_time_inside_quiet_hours() -> None:
    quiet = QuietHours.parse("23:00-07:00")
    assert quiet is not None

    assert quiet.overlap(local(15, 22), local(16, 8), SGT) == timedelta(hours=8)
    assert quiet.overlap(local(15, 10), local(15, 12), SGT) == timedelta(0)
    assert quiet.overlap(local(15, 12), local(17, 12), SGT) == timedelta(hours=16)
    assert quiet.overlap(local(16, 6), local(16, 6, 30), SGT) == timedelta(minutes=30)


def test_next_occurrence_is_strictly_after() -> None:
    eight = time(8, 0)

    assert next_occurrence(eight, local(15, 7, 59), SGT) == local(15, 8)
    assert next_occurrence(eight, local(15, 8), SGT) == local(16, 8)
    assert next_occurrence(eight, local(15, 9), SGT) == local(16, 8)


def test_latest_occurrence_is_at_or_before() -> None:
    eight = time(8, 0)

    assert latest_occurrence(eight, local(15, 8), SGT) == local(15, 8)
    assert latest_occurrence(eight, local(15, 7, 59), SGT) == local(14, 8)
    assert latest_occurrence(eight, local(15, 20), SGT) == local(15, 8)
