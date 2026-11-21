"""The local dashboard: server-rendered pages, HTMX for filtering and actions.

Security, because the pages show attacker-controlled text:

* every page needs a session started with the token from ``DASHBOARD_TOKEN``;
  the session cookie is HttpOnly and SameSite=Strict;
* every state-changing request needs the session's CSRF token;
* templates escape everything, untrusted names are defanged, and no link is
  ever built from log data;
* a strict Content-Security-Policy allows only this site's own scripts and
  styles, with no inline code, and framing is refused;
* only the configured host names are answered, which blocks DNS rebinding.

This module builds the app; the routes live in :mod:`vedette.web.routes`, what
they share in :mod:`vedette.web.dashboard`, and the template filters in
:mod:`vedette.web.templating`.
"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import MutableHeaders
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from vedette.web.dashboard import Dashboard, DashboardContext
from vedette.web.routes import errors, findings, live, login, overview, pages, series
from vedette.web.templating import TEMPLATE_ENV, _average

__all__ = ["CSP", "HTMX_SHA256", "TEMPLATE_ENV", "DashboardContext", "_average", "create_app"]

HTMX_SHA256 = "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "object-src 'none'"
)


class SecurityHeaders:
    """Adds the security headers to every response, errors included."""

    def __init__(self, app: ASGIApp) -> None:
        """Wrap ``app``."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Add the headers as the response starts."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        static = str(scope.get("path", "")).startswith("/static/")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = CSP
                headers["X-Frame-Options"] = "DENY"
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Cross-Origin-Opener-Policy"] = "same-origin"
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
                # Pages are never stored. Static files may be kept, but the browser
                # asks again each time (a cheap 304 on this machine), so after an
                # upgrade new pages never meet a stale stylesheet or script.
                headers["Cache-Control"] = "no-cache" if static else "no-store"
            await send(message)

        await self.app(scope, receive, send_with_headers)


def create_app(ctx: DashboardContext) -> FastAPI:
    """Build the dashboard application."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.dashboard = Dashboard(ctx)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(ctx.allowed_hosts))
    app.add_middleware(SecurityHeaders)
    app.mount("/static", StaticFiles(packages=[("vedette.web", "static")]), name="static")
    errors.install(app)
    for module in (login, overview, series, live, findings, pages):
        app.include_router(module.router)
    return app
