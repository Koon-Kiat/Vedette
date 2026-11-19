"""NextDNS log source: paginated history plus the resumable live stream.

API facts (https://nextdns.github.io/api, checked 2026-11-12):

* every call carries the ``X-Api-Key`` header;
* ``GET /profiles/:profile/logs`` pages newest-first via
  ``meta.pagination.cursor`` (``null`` on the last page) and returns
  ``meta.stream.id`` when asked for the most recent logs;
* ``GET /profiles/:profile/logs/stream`` is Server-Sent Events, resumable by
  passing the last event id as ``id``;
* log entries carry no id of their own, so :func:`parse_log_entry` derives one.

Rate limits are not documented; 429 and ``Retry-After`` are honoured anyway.
"""

import asyncio
import hashlib
import json
import random
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
import structlog
from httpx_sse import aconnect_sse

from sentinel.retry import backoff_delay, parse_retry_after
from sentinel.sources.base import (
    DnsEvent,
    LogPage,
    LogSource,
    Reason,
    SourceAuthError,
    SourceError,
    SourceUnavailable,
    StreamCursorRejected,
    StreamedEvent,
    StreamIdle,
)

log = structlog.get_logger(__name__)

SOURCE_NAME = "nextdns"
DEFAULT_BASE_URL = "https://api.nextdns.io"

_MAX_NAME = 255
_MAX_TEXT = 256
_MAX_SHORT = 64


def _text(value: object, limit: int) -> str | None:
    """Coerce an untrusted optional value to a length-capped string."""
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value)[:limit]
    return text or None


def _required(entry: Mapping[str, Any], field: str) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"log entry has no usable {field!r} field")
    return value


def compute_event_id(
    profile_id: str,
    ts: datetime,
    fqdn: str,
    status: str,
    protocol: str | None,
    device_id: str | None,
    client_ip: str | None,
    query_type: str | None = None,
) -> str:
    """Deterministic id for a log entry, identical for history and stream copies.

    NextDNS gives log entries no id, so the fields that identify a query are
    hashed instead. Storing the same entry twice then collapses to one row.

    ``query_type`` is part of the id only in raw mode, where NextDNS reports the
    A, AAAA and HTTPS lookups for one name as separate entries with the same
    timestamp. In the default (deduplicated) view entries carry no type.
    """
    parts = [
        profile_id,
        ts.astimezone(UTC).isoformat(timespec="microseconds"),
        fqdn,
        status,
        protocol or "",
        device_id or "",
        client_ip or "",
    ]
    if query_type is not None:
        parts.append(query_type)
    key = json.dumps(parts, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def parse_log_entry(profile_id: str, entry: Mapping[str, Any], *, raw: bool = False) -> DnsEvent:
    """Convert one NextDNS log entry into a :class:`DnsEvent`.

    Optional fields (``root``, ``tracker``, ``client``, ``device``) may be
    absent. Over-long strings are truncated rather than rejected, so an
    attacker cannot make an event disappear by inflating a field.

    Args:
        profile_id: Profile the entry belongs to.
        entry: The log entry as returned by the API.
        raw: Whether the profile is collected in raw mode; if so the entry's
            query ``type`` is part of the event id.

    Raises:
        ValueError: ``timestamp``, ``domain`` or ``status`` is missing or unusable.
    """
    raw_ts = _required(entry, "timestamp")
    domain = _required(entry, "domain")
    status = _required(entry, "status")[:32]
    try:
        ts = datetime.fromisoformat(raw_ts)
    except ValueError:
        raise ValueError("log entry has an unparseable 'timestamp' field") from None
    ts = ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)

    fqdn = domain.strip().lower().rstrip(".")[:_MAX_NAME]
    if not fqdn:
        raise ValueError("log entry has no usable 'domain' field")
    device = entry.get("device")
    if not isinstance(device, Mapping):
        device = {}
    raw_reasons = entry.get("reasons")
    reasons = tuple(
        Reason(id=reason_id, name=reason_name)
        for item in (raw_reasons if isinstance(raw_reasons, list) else [])
        if isinstance(item, Mapping)
        and (reason_id := _text(item.get("id"), _MAX_TEXT)) is not None
        and (reason_name := _text(item.get("name"), _MAX_TEXT)) is not None
    )
    encrypted = entry.get("encrypted")
    protocol = _text(entry.get("protocol"), _MAX_SHORT)
    device_id = _text(device.get("id"), _MAX_TEXT)
    client_ip = _text(entry.get("clientIp"), _MAX_SHORT)

    return DnsEvent(
        event_id=compute_event_id(
            profile_id,
            ts,
            fqdn,
            status,
            protocol,
            device_id,
            client_ip,
            _text(entry.get("type"), 16) if raw else None,
        ),
        profile_id=profile_id,
        ts=ts,
        fqdn=fqdn,
        root=_text(entry.get("root"), _MAX_NAME),
        status=status,
        reasons=reasons,
        device_id=device_id,
        device_name=_text(device.get("name"), _MAX_TEXT),
        client_ip=client_ip,
        protocol=protocol,
        encrypted=encrypted if isinstance(encrypted, bool) else None,
        tracker=_text(entry.get("tracker"), _MAX_TEXT),
        source=SOURCE_NAME,
    )


def _error_codes(response: httpx.Response) -> str:
    """Pull the API's error codes out of a response body, if it has any."""
    try:
        body = response.json()
    except ValueError:
        return ""
    errors = body.get("errors") if isinstance(body, dict) else None
    if not isinstance(errors, list):
        return ""
    codes = [str(item.get("code"))[:64] for item in errors if isinstance(item, dict)]
    return ", ".join(codes[:5])


class NextDnsSource(LogSource):
    """Reads query logs for NextDNS profiles. Never writes to NextDNS."""

    def __init__(
        self,
        api_key: str,
        *,
        raw: bool = False,
        page_size: int = 1000,
        base_url: str = DEFAULT_BASE_URL,
        max_attempts: int = 6,
        stream_idle_timeout: float = 300.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rng: Callable[[], float] = random.random,
    ) -> None:
        """Create a client.

        Args:
            api_key: NextDNS API key, sent only in the ``X-Api-Key`` header.
            raw: Ask for every DNS query instead of the deduplicated default.
            page_size: Entries per history page (the API allows 10 to 1000).
            base_url: API root; overridden only by tests.
            max_attempts: Tries per history request before giving up as unavailable.
            stream_idle_timeout: Seconds of stream silence before reconnecting.
                NextDNS documents no heartbeat, so silence cannot be told apart
                from a dead connection.
            sleep: Awaitable used to wait between retries.
            rng: Random source for backoff jitter.
        """
        self._raw = raw
        self._page_size = page_size
        self._max_attempts = max_attempts
        self._stream_timeout = httpx.Timeout(30.0, read=stream_idle_timeout)
        self._sleep = sleep
        self._rng = rng
        # TLS certificate verification is httpx's default and is never disabled.
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"X-Api-Key": api_key, "Accept": "application/json"},
            timeout=httpx.Timeout(30.0),
        )

    async def aclose(self) -> None:
        """Close the underlying HTTP connections."""
        await self._client.aclose()

    def _base_params(self) -> dict[str, str]:
        return {"raw": "1"} if self._raw else {}

    @staticmethod
    def _logs_path(profile_id: str) -> str:
        return f"/profiles/{quote(profile_id, safe='')}/logs"

    def _error_for(self, response: httpx.Response) -> SourceError:
        status = response.status_code
        codes = _error_codes(response)
        detail = f"NextDNS answered HTTP {status}" + (f" ({codes})" if codes else "")
        if status in (401, 403):
            return SourceAuthError(detail)
        if status == 429 or status >= 500:
            retry_after = parse_retry_after(response.headers.get("Retry-After"))
            return SourceUnavailable(detail, retry_after=retry_after)
        return SourceError(detail)

    async def _get_json(self, path: str, params: Mapping[str, str]) -> dict[str, Any]:
        """GET a JSON document, retrying transient failures with backoff."""
        for attempt in range(self._max_attempts):
            failure: SourceUnavailable
            try:
                response = await self._client.get(path, params=params)
            except httpx.TransportError as exc:
                failure = SourceUnavailable(f"NextDNS request failed: {type(exc).__name__}")
            else:
                if response.status_code == 200:
                    return self._decode(response)
                error = self._error_for(response)
                if not isinstance(error, SourceUnavailable):
                    raise error
                failure = error
            if attempt + 1 >= self._max_attempts:
                raise failure
            delay = (
                failure.retry_after
                if failure.retry_after is not None
                else backoff_delay(attempt, rng=self._rng)
            )
            log.warning(
                "nextdns_request_retry", reason=str(failure), attempt=attempt + 1, delay=delay
            )
            await self._sleep(delay)
        raise SourceUnavailable("NextDNS request failed")  # pragma: no cover - loop always exits

    @staticmethod
    def _decode(response: httpx.Response) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError:
            raise SourceError("NextDNS answered HTTP 200 with a body that is not JSON") from None
        if not isinstance(body, dict):
            raise SourceError("NextDNS answered HTTP 200 with an unexpected JSON shape")
        if "errors" in body:
            raise SourceError(f"NextDNS reported errors ({_error_codes(response)})")
        return body

    def _parse_page(self, profile_id: str, body: Mapping[str, Any]) -> tuple[DnsEvent, ...]:
        data = body.get("data")
        events: list[DnsEvent] = []
        skipped = 0
        for entry in data if isinstance(data, list) else []:
            try:
                if not isinstance(entry, Mapping):
                    raise ValueError("log entry is not an object")
                events.append(parse_log_entry(profile_id, entry, raw=self._raw))
            except ValueError:
                skipped += 1
        if skipped:
            log.warning("nextdns_entries_skipped", profile_id=profile_id, count=skipped)
        return tuple(events)

    async def backfill(self, profile_id: str, since: datetime) -> AsyncIterator[LogPage]:
        """Yield history pages from ``since`` until now, newest first.

        The first request asks for the most recent logs, because that is the
        only request documented to return ``meta.stream.id``. Taking the
        stream position *before* reading history means anything that arrives
        during the backfill is delivered by the stream afterwards; overlap is
        removed by the deterministic event ids.
        """
        path = self._logs_path(profile_id)
        common = {**self._base_params(), "limit": str(self._page_size)}

        latest = await self._get_json(path, common)
        meta = latest.get("meta")
        stream = meta.get("stream") if isinstance(meta, dict) else None
        stream_id = stream.get("id") if isinstance(stream, dict) else None
        if not isinstance(stream_id, str) or not stream_id:
            raise SourceError("NextDNS returned no stream id with the most recent logs")
        yield LogPage(events=self._parse_page(profile_id, latest), stream_cursor=stream_id)

        params = {**common, "from": since.astimezone(UTC).isoformat()}
        while True:
            body = await self._get_json(path, params)
            yield LogPage(events=self._parse_page(profile_id, body))
            meta = body.get("meta")
            pagination = meta.get("pagination") if isinstance(meta, dict) else None
            cursor = pagination.get("cursor") if isinstance(pagination, dict) else None
            if not isinstance(cursor, str) or not cursor:
                return
            params = {**params, "cursor": cursor}

    async def stream(
        self, profile_id: str, cursor: str, *, on_open: Callable[[], None] | None = None
    ) -> AsyncIterator[StreamedEvent]:
        """Yield live events following ``cursor`` until the connection ends.

        A read timeout after the stream opened means the profile was quiet,
        not that NextDNS failed, and is reported as :class:`StreamIdle`.
        """
        path = f"{self._logs_path(profile_id)}/stream"
        params = {**self._base_params(), "id": cursor}
        opened = False
        try:
            async with aconnect_sse(
                self._client, "GET", path, params=params, timeout=self._stream_timeout
            ) as source:
                response = source.response
                content_type = response.headers.get("Content-Type", "")
                if response.status_code != 200 or "text/event-stream" not in content_type:
                    await response.aread()
                    status = response.status_code
                    if status in (401, 403, 429) or status >= 500:
                        raise self._error_for(response)
                    # Undocumented territory: any other refusal is treated as
                    # "this cursor is no longer accepted".
                    raise StreamCursorRejected(f"NextDNS refused the stream cursor (HTTP {status})")
                opened = True
                if on_open is not None:
                    on_open()
                async for message in source.aiter_sse():
                    if not message.data:
                        continue
                    try:
                        entry = json.loads(message.data)
                        if not isinstance(entry, Mapping):
                            raise ValueError("stream event is not an object")
                        event = parse_log_entry(profile_id, entry, raw=self._raw)
                    except ValueError:
                        log.warning("nextdns_stream_event_skipped", profile_id=profile_id)
                        continue
                    yield StreamedEvent(event=event, cursor=message.id or None)
        except httpx.ReadTimeout as exc:
            if opened:
                raise StreamIdle("no stream data within the idle timeout") from exc
            raise SourceUnavailable(f"NextDNS stream failed: {type(exc).__name__}") from exc
        except httpx.TransportError as exc:
            raise SourceUnavailable(f"NextDNS stream failed: {type(exc).__name__}") from exc
