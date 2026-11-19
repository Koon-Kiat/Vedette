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
"""

import hmac
import secrets
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any
from zoneinfo import ZoneInfo

import jinja2
import structlog
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.datastructures import FormData, MutableHeaders
from starlette.exceptions import HTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinel.config import ProfileConfig
from sentinel.health.monitor import duration
from sentinel.notify.digest import DigestBuilder
from sentinel.notify.render import prose, safe
from sentinel.rules.model import RuleSpec, Severity
from sentinel.storage.dashboard import DashboardQueries, FindingFilter
from sentinel.storage.store import StoredFinding
from sentinel.storage.triage import DOMAIN_RULES, STATUSES, TriageStore
from sentinel.web.auth import LOGIN_COOKIE, SESSION_COOKIE, LoginLimiter, Session, SessionStore
from sentinel.web.charts import hourly_chart, span

log = structlog.get_logger(__name__)

HTMX_SHA256 = "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "object-src 'none'"
)
PERIODS = {"24h": timedelta(hours=24), "7d": timedelta(days=7)}


def _local(moment: datetime | None, tz: ZoneInfo) -> str:
    return "never" if moment is None else f"{moment.astimezone(tz):%Y-%m-%d %H:%M}"


def _clock(moment: datetime | None, tz: ZoneInfo) -> str:
    return "" if moment is None else f"{moment.astimezone(tz):%H:%M}"


def _since(moment: datetime | None, now: datetime) -> str:
    if moment is None:
        return "no events yet"
    elapsed = now - moment
    if elapsed < timedelta(minutes=1):
        return "under a minute ago"
    return f"{duration(elapsed)} ago"


TEMPLATE_ENV = jinja2.Environment(
    loader=jinja2.PackageLoader("sentinel.web", "templates"),
    autoescape=True,
    undefined=jinja2.StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)
TEMPLATE_ENV.filters.update(
    {
        "domain": lambda value: safe(value, limit=255),
        "text": lambda value: safe(value, limit=300),
        "prose": lambda value: prose(value, limit=600),
        "local": _local,
        "clock": _clock,
        "since": _since,
        "span": lambda finding, tz: span(finding.first_ts, finding.last_ts, tz),
        "ago": duration,
        "num": lambda value: f"{value:,}",
        "pct": lambda value: f"{value:.0%}",
        "secs": lambda value: f"{value / 1000:.1f} s",
        "avg": lambda value: "n/a" if value is None else f"{value:,.1f}".removesuffix(".0"),
    }
)


@dataclass(frozen=True, slots=True)
class DashboardContext:
    """Everything the dashboard needs from the running service."""

    engine: AsyncEngine
    profiles: Sequence[ProfileConfig]
    tz: ZoneInfo
    token: str
    specs: Sequence[RuleSpec]
    session_lifetime: timedelta
    allowed_hosts: Sequence[str]
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)


class LoginRequired(Exception):
    """The request has no live session."""


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
                if not static:
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


def _safe_next(value: object) -> str:
    """A redirect target inside the dashboard; anything else becomes the findings page."""
    if isinstance(value, str) and value.startswith("/") and not value.startswith("//"):
        if "\\" not in value and "\r" not in value and "\n" not in value:
            return value
    return "/findings"


def create_app(ctx: DashboardContext) -> FastAPI:
    """Build the dashboard application."""
    sessions = SessionStore(ctx.session_lifetime, ctx.clock)
    limiter = LoginLimiter(ctx.clock)
    queries = DashboardQueries(ctx.engine, profiles=ctx.profiles)
    triage = TriageStore(ctx.engine)
    labels = {profile.id: profile.label for profile in ctx.profiles}
    specs = {spec.id: spec for spec in ctx.specs}

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(ctx.allowed_hosts))
    app.add_middleware(SecurityHeaders)
    app.mount("/static", StaticFiles(packages=[("sentinel.web", "static")]), name="static")

    def render(name: str, *, status: int = 200, **values: Any) -> HTMLResponse:
        context = {"tz": ctx.tz, "labels": labels, "nav": "", "domain_rules": DOMAIN_RULES}
        context.update(values)
        return HTMLResponse(TEMPLATE_ENV.get_template(name).render(**context), status_code=status)

    async def page(name: str, **values: Any) -> HTMLResponse:
        """A full page with the navigation rail's live status."""
        return render(name, shell=await queries.shell(), now=ctx.clock(), **values)

    def session_of(request: Request) -> Session:
        session = sessions.get(request.cookies.get(SESSION_COOKIE))
        if session is None:
            raise LoginRequired
        return session

    SessionDep = Annotated[Session, Depends(session_of)]

    async def checked_form(request: Request, session: Session) -> FormData:
        form = await request.form()
        given = request.headers.get("X-CSRF-Token") or form.get("csrf_token")
        if not isinstance(given, str) or not hmac.compare_digest(
            given.encode(), session.csrf.encode()
        ):
            raise HTTPException(403, "The page was out of date. Reload it and try again.")
        return form

    @app.exception_handler(LoginRequired)
    async def to_login(request: Request, exc: LoginRequired) -> Response:
        if _is_htmx(request):
            return Response(status_code=401, headers={"HX-Redirect": "/login"})
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(HTTPException)
    async def error_page(request: Request, exc: HTTPException) -> Response:
        message = exc.detail if exc.status_code in (400, 403, 422) else "Not found."
        if exc.status_code == 405:
            message = "That is not allowed here."
        return render(
            "error.html",
            status=exc.status_code,
            code=exc.status_code,
            message=message,
            title=str(exc.status_code),
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> Response:
        return render(
            "error.html", status=422, code=422, message="That request was not valid.", title="422"
        )

    # --- login ------------------------------------------------------------------------

    def login_page(*, status: int = 200, error: str | None = None) -> HTMLResponse:
        nonce = secrets.token_urlsafe(16)
        response = render("login.html", status=status, nonce=nonce, error=error, title="Log in")
        response.set_cookie(
            LOGIN_COOKIE, nonce, max_age=600, path="/login", httponly=True, samesite="strict"
        )
        return response

    @app.get("/login")
    async def login_form() -> HTMLResponse:
        return login_page()

    @app.post("/login")
    async def login(request: Request) -> Response:
        form = await request.form()
        nonce = form.get("login_nonce")
        cookie = request.cookies.get(LOGIN_COOKIE)
        if not (isinstance(nonce, str) and cookie and hmac.compare_digest(nonce, cookie)):
            raise HTTPException(400, "The login form expired. Load it again.")
        if limiter.blocked():
            return login_page(status=429, error="Too many attempts. Wait a minute and try again.")
        token = form.get("token")
        if not (isinstance(token, str) and hmac.compare_digest(token.encode(), ctx.token.encode())):
            limiter.failed()
            log.warning("dashboard_login_failed")
            return login_page(status=401, error="That token is not right.")
        session = sessions.create()
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            session.id,
            max_age=int(sessions.lifetime.total_seconds()),
            path="/",
            httponly=True,
            samesite="strict",
        )
        response.delete_cookie(LOGIN_COOKIE, path="/login")
        log.info("dashboard_login")
        return response

    @app.post("/logout")
    async def logout(session: SessionDep, request: Request) -> Response:
        await checked_form(request, session)
        sessions.end(session.id)
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # --- pages ------------------------------------------------------------------------

    @app.get("/")
    async def overview(session: SessionDep) -> HTMLResponse:
        now = ctx.clock()
        digest = await DigestBuilder(
            ctx.engine, profiles=ctx.profiles, tz=ctx.tz, specs=ctx.specs
        ).build(now)
        alerts = await queries.open_alerts()
        averages = [v.avg_queries for v in digest.volumes if v.avg_queries is not None]
        usual = sum(averages) / 24 if averages else None
        chart = hourly_chart(
            await queries.hourly_queries(now),
            ctx.tz,
            usual=usual,
            markers=[(row.finding.id, row.finding.last_ts) for row in alerts],
        )
        return await page(
            "overview.html",
            nav="overview",
            title="Overview",
            csrf=session.csrf,
            digest=digest,
            levels=[level.value for level in sorted(Severity, key=lambda s: -s.rank)],
            chart=chart,
            alerts=alerts,
            new_devices_avg=await queries.new_devices_per_day(now),
            next_url="/",
        )

    def parse_filter(request: Request) -> FindingFilter:
        params = request.query_params
        profile = params.get("profile") or None
        rule = params.get("rule") or None
        device = (params.get("device") or None) and params["device"][:256]
        status = params.get("status") or "open"
        try:
            severity = Severity(params["severity"]) if params.get("severity") else None
            day = date.fromisoformat(params["date"]) if params.get("date") else None
        except ValueError:
            raise HTTPException(422, "A filter value was not valid.") from None
        if (
            (profile is not None and profile not in labels)
            or (rule is not None and rule not in specs)
            or status not in (*STATUSES, "all")
        ):
            raise HTTPException(422, "A filter value was not valid.")
        return FindingFilter(
            profile_id=profile,
            device=device,
            rule_id=rule,
            min_severity=severity,
            status=None if status == "all" else status,
            day=day,
        )

    @app.get("/findings")
    async def findings_page(session: SessionDep, request: Request) -> HTMLResponse:
        wanted = parse_filter(request)
        rows = await queries.findings(wanted, tz=ctx.tz)
        values: dict[str, Any] = {
            "csrf": session.csrf,
            "rows": rows,
            "next_url": str(request.url.path)
            + (f"?{request.url.query}" if request.url.query else ""),
        }
        if _is_htmx(request):
            return render("_findings_table.html", **values)
        return await page(
            "findings.html",
            nav="findings",
            title="Findings",
            wanted=wanted,
            devices=await queries.devices_in_findings(),
            rules=sorted(specs),
            severities=[level.value for level in Severity],
            statuses=[*STATUSES, "all"],
            **values,
        )

    @app.get("/findings/{finding_id}")
    async def finding_page(session: SessionDep, finding_id: int) -> HTMLResponse:
        row = await queries.finding(finding_id)
        if row is None:
            raise HTTPException(404)
        now = ctx.clock()
        return await page(
            "finding.html",
            nav="findings",
            title=f"Finding #{finding_id}",
            csrf=session.csrf,
            row=row,
            spec=specs.get(row.finding.rule_id),
            enrichment=await queries.enrichment(row.finding, now),
            queries=await queries.recent_queries(row.finding),
            audit=await triage.audit_for([finding_id]),
            next_url=f"/findings/{finding_id}",
        )

    actions: dict[str, Callable[..., Awaitable[StoredFinding | None]]] = {
        "acknowledge": triage.acknowledge,
        "benign": triage.mark_benign,
        "reopen": triage.reopen,
    }

    @app.post("/findings/{finding_id}/{action}")
    async def act(session: SessionDep, finding_id: int, action: str, request: Request) -> Response:
        form = await checked_form(request, session)
        handler = actions.get(action)
        if handler is None or await handler(finding_id, actor="dashboard", now=ctx.clock()) is None:
            raise HTTPException(404)
        log.info("dashboard_action", action=action, finding_id=finding_id)
        next_url = _safe_next(form.get("next"))
        if _is_htmx(request):
            row = await queries.finding(finding_id)
            return render("_finding_row.html", row=row, csrf=session.csrf, next_url=next_url)
        return RedirectResponse(next_url, status_code=303)

    @app.get("/domains")
    async def domains_page(session: SessionDep, period: str = "24h") -> HTMLResponse:
        if period not in PERIODS:
            raise HTTPException(422, "Unknown period.")
        return await page(
            "domains.html",
            nav="domains",
            title="Domains",
            csrf=session.csrf,
            period=period,
            page=await queries.domains(ctx.clock(), PERIODS[period]),
        )

    @app.get("/devices")
    async def devices_page(session: SessionDep) -> HTMLResponse:
        return await page(
            "devices.html",
            nav="devices",
            title="Devices",
            csrf=session.csrf,
            profiles=await queries.devices(ctx.clock()),
        )

    @app.get("/digests")
    async def digests_page(session: SessionDep) -> HTMLResponse:
        return await page(
            "digests.html",
            nav="digests",
            title="Digests",
            csrf=session.csrf,
            digests=await queries.digests(),
        )

    @app.get("/digests/{digest_id}")
    async def digest_page(session: SessionDep, digest_id: int) -> HTMLResponse:
        digest = await queries.digest(digest_id)
        if digest is None:
            raise HTTPException(404)
        return await page(
            "digest.html", nav="digests", title=digest.title, csrf=session.csrf, digest=digest
        )

    @app.get("/health")
    async def health_page(session: SessionDep) -> HTMLResponse:
        return await page(
            "health.html",
            nav="health",
            title="Health",
            csrf=session.csrf,
            health=await queries.health(ctx.clock()),
        )

    @app.get("/evaluation")
    async def evaluation_page(session: SessionDep) -> HTMLResponse:
        return await page(
            "evaluation.html", nav="evaluation", title="Evaluation", csrf=session.csrf
        )

    return app
