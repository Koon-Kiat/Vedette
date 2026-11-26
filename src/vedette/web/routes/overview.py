"""The Overview page, the profile switch, and the decisions table it refreshes."""

from collections.abc import Sequence
from datetime import datetime
from datetime import time as dt_time
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException

from vedette.notify.digest import DigestBuilder
from vedette.shared.models import Severity
from vedette.web.charts import hourly_chart
from vedette.web.dashboard import (
    ALL,
    SCOPE_COOKIE,
    Dashboard,
    DashboardDep,
    SessionDep,
    View,
    ViewDep,
    safe_next,
)

router = APIRouter()


async def overview_chart(
    dashboard: Dashboard, view: View, now: datetime, alerts: Sequence[Any]
) -> Any:
    """The day's digest figures and the server-drawn chart pages show without JavaScript."""
    ctx = dashboard.ctx
    digest = await DigestBuilder(
        ctx.engine, profiles=view.profiles, tz=ctx.tz, specs=ctx.specs
    ).build(now)
    averages = [v.avg_queries for v in digest.volumes if v.avg_queries is not None]
    usual = sum(averages) / 24 if averages else None
    chart = hourly_chart(
        await view.queries.hourly_queries(now),
        ctx.tz,
        usual=usual,
        markers=[(row.finding.id, row.finding.last_ts) for row in alerts],
    )
    return digest, chart


@router.get("/")
async def overview(view: ViewDep, request: Request, dashboard: DashboardDep) -> HTMLResponse:
    """The Overview page."""
    ctx = dashboard.ctx
    now = ctx.clock()
    alerts = await view.queries.open_alerts()
    digest, chart = await overview_chart(dashboard, view, now, alerts)
    return await dashboard.page(
        "overview.html",
        request,
        nav="overview",
        title="Overview",
        csrf=view.session.csrf,
        digest=digest,
        levels=[level.value for level in sorted(Severity, key=lambda s: -s.rank)],
        chart=chart,
        alerts=alerts,
        recent=[dashboard.feed_item(item) for item in await view.live.recent(8)],
        stats=await view.live.stats(now),
        new_devices_avg=await view.queries.new_devices_per_day(now),
        revisions_today=await view.queries.revisions_since(
            datetime.combine(now.astimezone(ctx.tz).date(), dt_time(0), tzinfo=ctx.tz)
        ),
        next_url="/",
    )


@router.get("/scope")
async def set_scope(session: SessionDep, request: Request, dashboard: DashboardDep) -> Response:
    """Choose which profiles every page shows; remembered for this browser."""
    wanted = request.query_params.get("to") or ALL
    if wanted != ALL and wanted not in dashboard.labels:
        raise HTTPException(422, "There is no such profile.")
    response = RedirectResponse(safe_next(request.query_params.get("next") or "/"), 303)
    response.set_cookie(
        SCOPE_COOKIE,
        wanted,
        max_age=365 * 24 * 3600,
        path="/",
        httponly=True,
        samesite="strict",
    )
    return response


@router.get("/partials/decide")
async def decide_partial(view: ViewDep, dashboard: DashboardDep) -> HTMLResponse:
    """The open high and critical findings, fetched again when they change."""
    return dashboard.render(
        "_findings_table.html",
        rows=await view.queries.open_alerts(),
        csrf=view.session.csrf,
        next_url="/",
        empty_text="No open high or critical findings.",
        table_id="decide",
    )
