"""Domains, Devices, Digests, Health and Evaluation: pages that only read."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from starlette.exceptions import HTTPException

from vedette.storage.evaluation import EvalStore
from vedette.web.dashboard import PERIODS, DashboardDep, SessionDep, ViewDep

router = APIRouter()


@router.get("/domains")
async def domains_page(
    view: ViewDep, request: Request, dashboard: DashboardDep, period: str = "24h"
) -> HTMLResponse:
    """Most allowed, most blocked, new and recently registered domains."""
    if period not in PERIODS:
        raise HTTPException(422, "Unknown period.")
    return await dashboard.page(
        "domains.html",
        request,
        nav="domains",
        title="Domains",
        csrf=view.session.csrf,
        period=period,
        page=await view.queries.domains(dashboard.ctx.clock(), PERIODS[period]),
    )


@router.get("/devices")
async def devices_page(view: ViewDep, request: Request, dashboard: DashboardDep) -> HTMLResponse:
    """Devices seen in the last seven days."""
    return await dashboard.page(
        "devices.html",
        request,
        nav="devices",
        title="Devices",
        csrf=view.session.csrf,
        profiles=await view.queries.devices(dashboard.ctx.clock()),
    )


@router.get("/digests")
async def digests_page(
    session: SessionDep, request: Request, dashboard: DashboardDep
) -> HTMLResponse:
    """Every digest produced, newest first."""
    return await dashboard.page(
        "digests.html",
        request,
        nav="digests",
        title="Digests",
        csrf=session.csrf,
        digests=await dashboard.queries.digests(),
        digest_time=dashboard.ctx.digest_time,
    )


@router.get("/digests/{digest_id}")
async def digest_page(
    session: SessionDep, request: Request, digest_id: int, dashboard: DashboardDep
) -> HTMLResponse:
    """One digest, as it was sent."""
    digest = await dashboard.queries.digest(digest_id)
    if digest is None:
        raise HTTPException(404)
    return await dashboard.page(
        "digest.html",
        request,
        nav="digests",
        title=digest.title,
        csrf=session.csrf,
        digest=digest,
    )


@router.get("/health")
async def health_page(
    session: SessionDep, request: Request, dashboard: DashboardDep
) -> HTMLResponse:
    """Each health check, the newest events and the local model's figures."""
    return await dashboard.page(
        "health.html",
        request,
        nav="health",
        title="Health",
        csrf=session.csrf,
        health=await dashboard.queries.health(dashboard.ctx.clock()),
    )


@router.get("/evaluation")
async def evaluation_page(
    session: SessionDep, request: Request, dashboard: DashboardDep
) -> HTMLResponse:
    """The latest results of `vedette eval`."""
    return await dashboard.page(
        "evaluation.html",
        request,
        nav="evaluation",
        title="Evaluation",
        csrf=session.csrf,
        run=await EvalStore(dashboard.ctx.engine).latest(),
    )
