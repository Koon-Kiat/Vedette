"""The Live page and its server-sent event stream."""

import asyncio
import json
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from starlette.exceptions import HTTPException

from vedette.web.dashboard import DashboardDep, ViewDep

router = APIRouter()


@router.get("/live")
async def live_page(view: ViewDep, request: Request, dashboard: DashboardDep) -> HTMLResponse:
    """The Live page: the latest queries and the counters."""
    now = dashboard.ctx.clock()
    return await dashboard.page(
        "live.html",
        request,
        nav="live",
        title="Live",
        csrf=view.session.csrf,
        recent=[dashboard.feed_item(item) for item in await view.live.recent(60)],
        stats=await view.live.stats(now),
    )


def _message(event: str, data: Any) -> bytes:
    # "<" is escaped too, so even a raw view of the stream shows no markup.
    body = json.dumps(data, ensure_ascii=True).replace("<", "\\u003c")
    return f"event: {event}\ndata: {body}\n\n".encode()


@router.get("/live/stream")
async def live_stream(view: ViewDep, dashboard: DashboardDep) -> Response:
    """Server-sent events: new queries every second, counters every few seconds."""
    ctx = dashboard.ctx
    session = view.session
    if dashboard.open_streams >= ctx.live_max_streams:
        raise HTTPException(429, "Too many live views are open. Close one and reload.")

    async def stream() -> AsyncIterator[bytes]:
        dashboard.open_streams += 1
        try:
            started = time.monotonic()
            cursor = view.live.start(ctx.clock())
            last_stats = 0.0
            last_finding: int | None = None
            last_open: int | None = None
            yield b"retry: 3000\n\n"
            # Starlette cancels this generator when the browser disconnects.
            while time.monotonic() - started < ctx.live_max_seconds:
                if dashboard.sessions.get(session.id) is None:  # logged out or expired
                    yield _message("bye", {"reason": "session ended"})
                    break
                fresh = await view.live.poll(cursor)
                if fresh:
                    yield _message("queries", [dashboard.feed_item(item) for item in fresh])
                if time.monotonic() - last_stats >= ctx.live_stats_seconds:
                    last_stats = time.monotonic()
                    now = ctx.clock()
                    stats = await dashboard.scoped_stats(view, now)
                    yield _message("stats", dashboard.stats_item(stats, now))
                    if last_open is not None and (
                        stats.open_findings != last_open or stats.newest_finding_id != last_finding
                    ):
                        yield _message("findings", {"open": stats.open_findings})
                    last_open, last_finding = stats.open_findings, stats.newest_finding_id
                await asyncio.sleep(ctx.live_poll_seconds)
        finally:
            dashboard.open_streams -= 1

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
