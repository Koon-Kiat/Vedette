"""The Allowlist page: what the rules skip, and taking back an entry Mark benign made."""

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException

from vedette.web.dashboard import DashboardDep, SessionDep, is_htmx

log = structlog.get_logger(__name__)
router = APIRouter()


@router.get("/allowlist")
async def allowlist_page(
    session: SessionDep, request: Request, dashboard: DashboardDep
) -> HTMLResponse:
    """Entries made by marking findings benign, and those from config.yaml."""
    stored = await dashboard.triage.stored_allowlist()
    existing = {
        entry.finding_id
        for entry in stored
        if entry.finding_id is not None
        and await dashboard.queries.finding(entry.finding_id) is not None
    }
    return await dashboard.page(
        "allowlist.html",
        request,
        nav="allowlist",
        title="Allowlist",
        csrf=session.csrf,
        stored=stored,
        linked=existing,
        configured=dashboard.ctx.allowlist,
    )


@router.post("/allowlist/{entry_id}/remove")
async def remove_entry(
    session: SessionDep, entry_id: int, request: Request, dashboard: DashboardDep
) -> Response:
    """Take an entry back: the rules flag its root again within about 30 seconds."""
    await dashboard.checked_form(request, session)
    removed = await dashboard.triage.remove_allowlist_entry(
        entry_id, actor="dashboard", now=dashboard.ctx.clock()
    )
    if removed is None:
        raise HTTPException(404)
    log.info("dashboard_allowlist_removed", entry_id=entry_id)
    if is_htmx(request):  # posted through htmx for its confirm dialog: reload the page
        return Response(status_code=204, headers={"HX-Redirect": "/allowlist"})
    return RedirectResponse("/allowlist", status_code=303)
