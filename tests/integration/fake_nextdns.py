"""An in-process stand-in for the NextDNS logs API, mounted on a respx router.

It follows the documented contract: ``X-Api-Key`` auth, ``/logs`` with ``from``,
``limit`` and ``cursor`` (newest first, ``meta.pagination.cursor`` null on the
last page, ``meta.stream.id`` only when asking for the most recent logs), and
``/logs/stream`` as Server-Sent Events resumable by ``id``. All data is synthetic.
"""

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import respx

BASE_URL = "https://api.nextdns.io"
API_KEY = "test-key-not-real"
T0 = datetime(2026, 3, 15, 4, 0, 0, tzinfo=UTC)


class _SseBody(httpx.AsyncByteStream):
    def __init__(self, server: FakeNextDns, start: int) -> None:
        self._server = server
        self._next = start

    async def __aiter__(self) -> AsyncIterator[bytes]:
        server = self._server
        for chunk in server.stream_prefix_chunks:
            yield chunk
        sent = 0
        while True:
            while self._next < len(server.entries):
                if server.break_stream_after is not None and sent >= server.break_stream_after:
                    raise httpx.ReadError("connection reset by fake server")
                entry = server.entries[self._next]
                self._next += 1
                sent += 1
                yield f"id: s{self._next}\ndata: {json.dumps(entry)}\n\n".encode()
            if not server.hold_stream_open:
                return
            await asyncio.sleep(0.005)


class FakeNextDns:
    """Synthetic NextDNS account with one profile."""

    def __init__(self, profile_id: str = "abc123") -> None:
        self.profile_id = profile_id
        self.entries: list[dict[str, Any]] = []  # oldest first
        self.log_requests: list[httpx.Request] = []
        self.stream_requests: list[httpx.Request] = []
        self.log_failures: list[httpx.Response | Exception] = []
        self.stream_failures: list[httpx.Response | Exception] = []
        self.rejected_stream_ids: set[str] = set()
        self.stream_prefix_chunks: list[bytes] = []
        self.break_stream_after: int | None = None
        self.hold_stream_open = False
        self.omit_stream_id = False
        self.block_logs_after: int | None = None
        self.unblock_logs = asyncio.Event()

    def add_entries(self, count: int) -> None:
        """Append ``count`` new log entries, one second apart."""
        for _ in range(count):
            n = len(self.entries)
            entry: dict[str, Any] = {
                "timestamp": (T0 + timedelta(seconds=n)).isoformat().replace("+00:00", "Z"),
                "domain": f"host{n}.site{n % 7}.example",
                "root": f"site{n % 7}.example",
                "encrypted": True,
                "protocol": "DNS-over-HTTPS",
                "clientIp": "198.51.100.7",
                "status": "blocked" if n % 5 == 0 else "default",
                "reasons": [{"id": "blocklist:sample", "name": "Sample"}] if n % 5 == 0 else [],
            }
            if n % 3:
                entry["device"] = {"id": f"DEV{n % 3}", "name": f"Device {n % 3}"}
            self.entries.append(entry)

    @property
    def latest_stream_id(self) -> str:
        return f"s{len(self.entries)}"

    def mount(self, router: respx.MockRouter) -> None:
        base = f"{BASE_URL}/profiles/{self.profile_id}"
        router.get(f"{base}/logs/stream").mock(side_effect=self._stream)
        router.get(f"{base}/logs").mock(side_effect=self._logs)

    def _authorised(self, request: httpx.Request) -> bool:
        return bool(request.headers.get("X-Api-Key") == API_KEY)

    async def _logs(self, request: httpx.Request) -> httpx.Response:
        self.log_requests.append(request)
        if self.block_logs_after is not None and len(self.log_requests) > self.block_logs_after:
            await self.unblock_logs.wait()
        if self.log_failures:
            failure = self.log_failures.pop(0)
            if isinstance(failure, Exception):
                raise failure
            return failure
        if not self._authorised(request):
            return httpx.Response(403, json={"errors": [{"code": "forbidden"}]})
        params = request.url.params
        limit = int(params.get("limit", "100"))
        end = int(params["cursor"]) if "cursor" in params else len(self.entries)
        start = 0
        if "from" in params:
            since = datetime.fromisoformat(params["from"])
            start = next(
                (
                    i
                    for i, entry in enumerate(self.entries)
                    if "timestamp" not in entry
                    or datetime.fromisoformat(entry["timestamp"]) >= since
                ),
                len(self.entries),
            )
        first = max(start, end - limit)
        page = list(reversed(self.entries[first:end]))
        meta: dict[str, Any] = {"pagination": {"cursor": str(first) if first > start else None}}
        if "from" not in params and "cursor" not in params and not self.omit_stream_id:
            meta["stream"] = {"id": self.latest_stream_id}
        return httpx.Response(200, json={"data": page, "meta": meta})

    async def _stream(self, request: httpx.Request) -> httpx.Response:
        self.stream_requests.append(request)
        if self.stream_failures:
            failure = self.stream_failures.pop(0)
            if isinstance(failure, Exception):
                raise failure
            return failure
        if not self._authorised(request):
            return httpx.Response(403, json={"errors": [{"code": "forbidden"}]})
        stream_id = request.url.params.get("id", "")
        if stream_id in self.rejected_stream_ids or not stream_id.startswith("s"):
            return httpx.Response(400, json={"errors": [{"code": "invalid", "source": "id"}]})
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            stream=_SseBody(self, int(stream_id[1:])),
        )
