"""Logging in with the token from DASHBOARD_TOKEN, and logging out."""

import hmac
import secrets

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException

from vedette.web.auth import LOGIN_COOKIE, SESSION_COOKIE
from vedette.web.dashboard import Dashboard, DashboardDep, SessionDep

log = structlog.get_logger(__name__)
router = APIRouter()


def login_page(
    dashboard: Dashboard, *, status: int = 200, error: str | None = None
) -> HTMLResponse:
    """The login form, with a one-time nonce that must come back in a cookie."""
    nonce = secrets.token_urlsafe(16)
    response = dashboard.render(
        "login.html", status=status, nonce=nonce, error=error, title="Log in"
    )
    response.set_cookie(
        LOGIN_COOKIE, nonce, max_age=600, path="/login", httponly=True, samesite="strict"
    )
    return response


@router.get("/login")
async def login_form(dashboard: DashboardDep) -> HTMLResponse:
    """The login form."""
    return login_page(dashboard)


@router.post("/login")
async def login(request: Request, dashboard: DashboardDep) -> Response:
    """Check the token and start a session."""
    form = await request.form()
    nonce = form.get("login_nonce")
    cookie = request.cookies.get(LOGIN_COOKIE)
    if not (isinstance(nonce, str) and cookie and hmac.compare_digest(nonce, cookie)):
        raise HTTPException(400, "The login form expired. Load it again.")
    if dashboard.limiter.blocked():
        return login_page(
            dashboard, status=429, error="Too many attempts. Wait a minute and try again."
        )
    token = form.get("token")
    expected = dashboard.ctx.token
    if not (isinstance(token, str) and hmac.compare_digest(token.encode(), expected.encode())):
        dashboard.limiter.failed()
        log.warning("dashboard_login_failed")
        return login_page(
            dashboard,
            status=401,
            error="That token is not right. It must match DASHBOARD_TOKEN in your .env "
            "file exactly, capital letters included.",
        )
    session = dashboard.sessions.create()
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        session.id,
        max_age=int(dashboard.sessions.lifetime.total_seconds()),
        path="/",
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(LOGIN_COOKIE, path="/login")
    log.info("dashboard_login")
    return response


@router.post("/logout")
async def logout(session: SessionDep, request: Request, dashboard: DashboardDep) -> Response:
    """End the session."""
    await dashboard.checked_form(request, session)
    dashboard.sessions.end(session.id)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
