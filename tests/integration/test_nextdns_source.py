import inspect
from datetime import timedelta

import httpx
import pytest

from tests.integration.conftest import SleepRecorder
from tests.integration.fake_nextdns import API_KEY, T0, FakeNextDns
from vedette.sources.base import (
    DnsEvent,
    SourceAuthError,
    SourceError,
    SourceUnavailable,
    StreamCursorRejected,
)
from vedette.sources.nextdns import NextDnsSource, parse_log_entry


async def collect_backfill(
    source: NextDnsSource, since: timedelta = timedelta(0)
) -> list[DnsEvent]:
    events: list[DnsEvent] = []
    async for page in source.backfill("abc123", T0 + since):
        events.extend(page.events)
    return events


def expected_ids(server: FakeNextDns, start: int = 0) -> set[str]:
    return {parse_log_entry("abc123", entry).event_id for entry in server.entries[start:]}


async def test_backfill_returns_every_entry_in_the_window(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(35)

    events = await collect_backfill(source)

    assert {event.event_id for event in events} == expected_ids(server)


async def test_backfill_follows_the_cursor_until_it_is_null(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(35)

    await collect_backfill(source)

    cursors = [request.url.params.get("cursor") for request in server.log_requests]
    assert cursors == [None, None, "25", "15", "5"]


async def test_first_page_asks_for_most_recent_logs_and_carries_the_stream_cursor(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(35)

    pages = [page async for page in source.backfill("abc123", T0)]

    assert "from" not in server.log_requests[0].url.params
    assert pages[0].stream_cursor == "s35"
    assert all(page.stream_cursor is None for page in pages[1:])


async def test_backfill_asks_only_for_entries_since_the_given_time(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(35)
    since = T0 + timedelta(seconds=30)

    pages = [page async for page in source.backfill("abc123", since)]

    assert server.log_requests[1].url.params["from"] == since.isoformat()
    windowed = {event.event_id for page in pages[1:] for event in page.events}
    assert windowed == expected_ids(server, start=30)


async def test_every_request_sends_the_api_key_header_and_page_size(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(25)

    await collect_backfill(source)
    _ = [item async for item in source.stream("abc123", "s25")]

    for request in [*server.log_requests, *server.stream_requests]:
        assert request.headers["X-Api-Key"] == API_KEY
    assert {request.url.params["limit"] for request in server.log_requests} == {"10"}


def test_a_silent_stream_is_reopened_after_five_minutes_by_default() -> None:
    default = inspect.signature(NextDnsSource).parameters["stream_idle_timeout"].default
    assert default == 300.0


async def test_raw_is_off_by_default(server: FakeNextDns, source: NextDnsSource) -> None:
    server.add_entries(5)

    await collect_backfill(source)
    _ = [item async for item in source.stream("abc123", "s5")]

    for request in [*server.log_requests, *server.stream_requests]:
        assert "raw" not in request.url.params


async def test_raw_mode_is_requested_everywhere_when_enabled(
    server: FakeNextDns, sleeps: SleepRecorder
) -> None:
    server.add_entries(15)
    source = NextDnsSource(API_KEY, raw=True, page_size=10, sleep=sleeps)
    try:
        await collect_backfill(source)
        _ = [item async for item in source.stream("abc123", "s15")]
    finally:
        await source.aclose()

    for request in [*server.log_requests, *server.stream_requests]:
        assert request.url.params["raw"] == "1"


async def test_429_waits_for_retry_after_then_succeeds(
    server: FakeNextDns, source: NextDnsSource, sleeps: SleepRecorder
) -> None:
    server.add_entries(5)
    server.log_failures.append(httpx.Response(429, headers={"Retry-After": "3"}))

    events = await collect_backfill(source)

    assert sleeps.delays == [3.0]
    assert len({event.event_id for event in events}) == 5


async def test_server_errors_are_retried_with_growing_delays(
    server: FakeNextDns, source: NextDnsSource, sleeps: SleepRecorder
) -> None:
    server.add_entries(5)
    server.log_failures.extend([httpx.Response(500), httpx.Response(502), httpx.Response(503)])

    await collect_backfill(source)

    assert sleeps.delays == [1.0, 2.0, 4.0]


async def test_network_errors_are_retried(
    server: FakeNextDns, source: NextDnsSource, sleeps: SleepRecorder
) -> None:
    server.add_entries(5)
    server.log_failures.append(httpx.ConnectError("no route"))

    events = await collect_backfill(source)

    assert len(sleeps.delays) == 1
    assert len({event.event_id for event in events}) == 5


async def test_persistent_failure_gives_up_as_unavailable(
    server: FakeNextDns, source: NextDnsSource, sleeps: SleepRecorder
) -> None:
    server.log_failures.extend([httpx.Response(503)] * 20)

    with pytest.raises(SourceUnavailable):
        await collect_backfill(source)

    assert len(server.log_requests) == 6
    assert len(sleeps.delays) == 5


async def test_rejected_api_key_is_an_auth_error_and_is_not_retried(
    server: FakeNextDns, sleeps: SleepRecorder
) -> None:
    source = NextDnsSource("wrong-key-value", sleep=sleeps)
    try:
        with pytest.raises(SourceAuthError) as excinfo:
            await collect_backfill(source)
    finally:
        await source.aclose()

    assert len(server.log_requests) == 1
    assert sleeps.delays == []
    assert "wrong-key-value" not in str(excinfo.value)


async def test_other_client_errors_are_not_retried_and_report_the_status(
    server: FakeNextDns, source: NextDnsSource, sleeps: SleepRecorder
) -> None:
    server.log_failures.append(httpx.Response(404, json={"errors": [{"code": "notFound"}]}))

    with pytest.raises(SourceError, match="404") as excinfo:
        await collect_backfill(source)

    assert "notFound" in str(excinfo.value)
    assert not isinstance(excinfo.value, SourceUnavailable)
    assert sleeps.delays == []


async def test_errors_reported_with_status_200_are_raised(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.log_failures.append(httpx.Response(200, json={"errors": [{"code": "invalid"}]}))

    with pytest.raises(SourceError, match="invalid"):
        await collect_backfill(source)


async def test_a_non_json_body_is_an_error(server: FakeNextDns, source: NextDnsSource) -> None:
    server.log_failures.append(httpx.Response(200, text="<html>oops</html>"))

    with pytest.raises(SourceError):
        await collect_backfill(source)


async def test_missing_stream_id_is_an_error_rather_than_a_silent_gap(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(5)
    server.omit_stream_id = True

    with pytest.raises(SourceError, match="stream id"):
        await collect_backfill(source)


async def test_malformed_entries_in_a_page_are_skipped(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(3)
    server.entries.insert(1, {"domain": "no-timestamp.example", "status": "default"})

    events = await collect_backfill(source)

    assert len({event.event_id for event in events}) == 3


async def test_stream_yields_events_after_the_cursor_with_their_own_cursors(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(8)

    items = [item async for item in source.stream("abc123", "s5")]

    assert server.stream_requests[0].url.params["id"] == "s5"
    assert [item.cursor for item in items] == ["s6", "s7", "s8"]
    assert {item.event.event_id for item in items} == expected_ids(server, start=5)


async def test_stream_and_backfill_give_the_same_event_the_same_id(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(6)

    from_backfill = {event.event_id for event in await collect_backfill(source)}
    from_stream = {item.event.event_id async for item in source.stream("abc123", "s0")}

    assert from_backfill == from_stream


async def test_stream_with_a_rejected_id_raises_cursor_rejected(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.rejected_stream_ids.add("s5")

    with pytest.raises(StreamCursorRejected):
        _ = [item async for item in source.stream("abc123", "s5")]


async def test_stream_that_answers_without_sse_is_treated_as_rejected(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.stream_failures.append(httpx.Response(200, json={"errors": [{"code": "invalid"}]}))

    with pytest.raises(StreamCursorRejected):
        _ = [item async for item in source.stream("abc123", "s5")]


async def test_stream_server_error_is_unavailable(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.stream_failures.append(httpx.Response(503))

    with pytest.raises(SourceUnavailable):
        _ = [item async for item in source.stream("abc123", "s5")]


async def test_stream_429_exposes_retry_after(server: FakeNextDns, source: NextDnsSource) -> None:
    server.stream_failures.append(httpx.Response(429, headers={"Retry-After": "12"}))

    with pytest.raises(SourceUnavailable) as excinfo:
        _ = [item async for item in source.stream("abc123", "s5")]

    assert excinfo.value.retry_after == 12.0


async def test_stream_with_a_bad_key_is_an_auth_error(
    server: FakeNextDns, sleeps: SleepRecorder
) -> None:
    source = NextDnsSource("wrong-key-value", sleep=sleeps)
    try:
        with pytest.raises(SourceAuthError):
            _ = [item async for item in source.stream("abc123", "s0")]
    finally:
        await source.aclose()


async def test_stream_connection_failure_is_unavailable(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.stream_failures.append(httpx.ConnectError("no route"))

    with pytest.raises(SourceUnavailable):
        _ = [item async for item in source.stream("abc123", "s5")]


async def test_stream_dropped_midway_delivers_what_arrived_then_is_unavailable(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(6)
    server.break_stream_after = 2
    stream = aiter(source.stream("abc123", "s0"))

    assert [(await anext(stream)).cursor for _ in range(2)] == ["s1", "s2"]
    with pytest.raises(SourceUnavailable):
        await anext(stream)


async def test_malformed_stream_events_are_skipped(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(2)
    server.stream_prefix_chunks = [
        b"id: bad1\ndata: {not json\n\n",
        b'id: bad2\ndata: {"domain": "no-timestamp.example"}\n\n',
        b"id: bad3\ndata: [1, 2, 3]\n\n",
        b": keep-alive comment\n\n",
    ]

    items = [item async for item in source.stream("abc123", "s0")]

    assert [item.cursor for item in items] == ["s1", "s2"]
