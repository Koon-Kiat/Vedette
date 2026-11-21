"""The Findings list, a finding's page, and the triage actions."""

import json
from collections.abc import Awaitable, Callable
from typing import Any

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException

from vedette.rules.model import Severity
from vedette.storage.store import StoredFinding
from vedette.storage.triage import STATUSES, TriageStore
from vedette.web.dashboard import DashboardDep, SessionDep, ViewDep, is_htmx, safe_next

log = structlog.get_logger(__name__)
router = APIRouter()


@router.get("/findings")
async def findings_page(view: ViewDep, request: Request, dashboard: DashboardDep) -> HTMLResponse:
    """The Findings page, or only its table when htmx changes a filter."""
    ctx = dashboard.ctx
    wanted = dashboard.parse_filter(request)
    rows = await view.queries.findings(wanted, tz=ctx.tz)
    values: dict[str, Any] = {
        "csrf": view.session.csrf,
        "rows": rows,
        "next_url": view.here,
        "table_id": "findings",
    }
    if is_htmx(request):
        return dashboard.render("_findings_table.html", **values)
    return await dashboard.page(
        "findings.html",
        request,
        nav="findings",
        title="Findings",
        wanted=wanted,
        devices=await view.queries.devices_in_findings(),
        days=await view.queries.finding_days(tz=ctx.tz),
        today=ctx.clock().astimezone(ctx.tz).date(),
        rules=sorted(dashboard.specs, key=lambda rule_id: dashboard.rule_names[rule_id].lower()),
        severities=[level.value for level in Severity],
        statuses=[*STATUSES, "all"],
        **values,
    )


@router.get("/findings/{finding_id}")
async def finding_page(
    view: ViewDep, request: Request, finding_id: int, dashboard: DashboardDep
) -> HTMLResponse:
    """One finding: its explanation, evidence, cached facts, queries and history."""
    # Looked up across every profile: a link from an alert or a digest works
    # whichever profiles the pages are showing.
    queries = dashboard.queries
    row = await queries.finding(finding_id)
    if row is None:
        raise HTTPException(404)
    now = dashboard.ctx.clock()
    previous, following = await view.queries.neighbours(finding_id)
    return await dashboard.page(
        "finding.html",
        request,
        nav="findings",
        title=f"Finding {finding_id:04d}",
        csrf=view.session.csrf,
        row=row,
        spec=dashboard.specs.get(row.finding.rule_id),
        enrichment=await queries.enrichment(row.finding, now),
        queries=await queries.recent_queries(row.finding),
        audit=await dashboard.triage.audit_for([finding_id]),
        previous_id=previous,
        next_id=following,
        next_url=f"/findings/{finding_id}",
    )


def _actions(
    triage: TriageStore,
) -> dict[str, Callable[..., Awaitable[StoredFinding | None]]]:
    return {
        "acknowledge": triage.acknowledge,
        "benign": triage.mark_benign,
        "reopen": triage.reopen,
    }


@router.post("/findings/{finding_id}/{action}")
async def act(
    session: SessionDep, finding_id: int, action: str, request: Request, dashboard: DashboardDep
) -> Response:
    """Acknowledge, mark benign or reopen a finding; htmx gets the new row back."""
    form = await dashboard.checked_form(request, session)
    handler = _actions(dashboard.triage).get(action)
    if (
        handler is None
        or await handler(finding_id, actor="dashboard", now=dashboard.ctx.clock()) is None
    ):
        raise HTTPException(404)
    log.info("dashboard_action", action=action, finding_id=finding_id)
    next_url = safe_next(form.get("next"))
    if is_htmx(request):
        row = await dashboard.queries.finding(finding_id)
        response = dashboard.render(
            "_finding_row.html", row=row, csrf=session.csrf, next_url=next_url
        )
        # Every open count on the page follows the decision at once.
        shell = await dashboard.queries.shell()
        response.headers["HX-Trigger"] = json.dumps(
            {"vedette-counts": {"layers": dashboard.open_by_layer(shell.open_by_profile)}}
        )
        return response
    return RedirectResponse(next_url, status_code=303)
