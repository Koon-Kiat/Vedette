"""Data for the interactive charts: query series and what happened in a period."""

import json
from datetime import timedelta

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response
from starlette.exceptions import HTTPException

from vedette.storage.series import MAX_POINTS
from vedette.web.dashboard import DashboardDep, ViewDep

router = APIRouter()


@router.get("/api/series")
async def series_api(view: ViewDep, request: Request, dashboard: DashboardDep) -> Response:
    """Queries per bar over a span, per profile, with the findings in it."""
    start, end = dashboard.span_of(request, default=timedelta(hours=24))
    try:  # how many bars the chart's width suits; choose_step keeps it in range
        points = int(request.query_params.get("points") or MAX_POINTS)
    except ValueError:
        raise HTTPException(422, "The number of bars was not valid.") from None
    result = await view.series.series(start, end, points=points)
    body = {
        "start": result.start,
        "end": result.end,
        "step": result.step,
        "t": result.t,
        "allowed": result.allowed,
        "blocked": result.blocked,
        "usual": result.usual,
        # Each profile drawn as its own layer; labels are our own config.
        "layers": [
            {
                "label": dashboard.labels[layer.profile_id],
                "ink": dashboard.layers[layer.profile_id],
                "allowed": layer.allowed,
                "blocked": layer.blocked,
            }
            for layer in result.layers
        ],
        "findings": [dashboard.finding_item(item) for item in result.findings],
        "now": int(dashboard.ctx.clock().timestamp()),
    }
    return Response(
        json.dumps(body, ensure_ascii=True).replace("<", "\\u003c"),
        media_type="application/json",
    )


@router.get("/partials/window")
async def window_partial(view: ViewDep, request: Request, dashboard: DashboardDep) -> HTMLResponse:
    """What happened in one period of a chart: totals, findings and queries."""
    start, end = dashboard.span_of(request, default=timedelta(hours=1))
    window = await view.series.window(start, end)
    return dashboard.render(
        "_window.html",
        window=window,
        found=[dashboard.finding_item(item) for item in window.findings],
        latest=[dashboard.feed_item(item) for item in window.latest],
    )
