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

import asyncio
import dataclasses
import functools
import hashlib
import hmac
import importlib.resources
import json
import re
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from datetime import time as dt_time
from typing import Annotated, Any
from zoneinfo import ZoneInfo

import jinja2
import structlog
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from markupsafe import Markup, escape
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.datastructures import FormData, MutableHeaders
from starlette.exceptions import HTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinel.config import ProfileConfig
from sentinel.health.monitor import CATCHING_UP, OK, duration
from sentinel.notify.defang import clean_text, defang_names
from sentinel.notify.digest import DigestBuilder
from sentinel.notify.render import about_text, prose, safe
from sentinel.rules.model import RuleSpec, Severity
from sentinel.storage.dashboard import DashboardQueries, FindingFilter
from sentinel.storage.evaluation import EvalStore
from sentinel.storage.live import LiveEvent, LiveQueries, LiveStats
from sentinel.storage.series import MAX_POINTS, SeriesFinding, SeriesQueries
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
FINDING_PATH = re.compile(r"/findings/(\d{1,9})")
#: Error pages are titled by what went wrong; the status code is a field below.
ERROR_TITLES = {
    400: "Request not valid",
    403: "Page out of date",
    404: "Page not found",
    405: "Not allowed",
    422: "Request not valid",
    429: "Too many live views",
}
#: Which profiles the pages show: "all" or one profile id, remembered per browser.
SCOPE_COOKIE = "sentinel_scope"
ALL = "all"


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


def _status_word(value: object) -> str:
    """NextDNS calls a query it let through "default"; the dashboard says "allowed"."""
    return "allowed" if value == "default" else safe(value, limit=40)


def _detail(value: object) -> str:
    """A message the pipeline wrote: names defanged, numbers left as numbers."""
    return defang_names(clean_text(str(value), limit=300))


#: Evidence fields in the order a finding's page lists them, in plain words.
EVIDENCE_LABELS = {
    "fqdn": "Name queried",
    "sample_fqdn": "Example name",
    "root": "Domain",
    "status": "NextDNS status",
    "domain_age_days": "Domain age, days",
    "popularity_rank": "Top-sites rank",
    "threat_feeds": "Threat feeds",
    "threat_match": "Matched on",
    "label": "Leftmost label",
    "label_length": "Label length",
    "entropy": "Entropy, bits per character",
    "digit_ratio": "Share of digits",
    "unique_subdomains": "Distinct subdomains",
    "blocked_in_window": "Blocked in the window",
    "window_minutes": "Window, minutes",
    "queries_this_hour": "Queries this hour",
    "baseline_per_hour": "Usual queries per hour",
    "factor": "Times the usual",
    "category": "Category",
    "category_name": "Category name",
    "device_id": "Device",
    "device_name": "Device name",
    "client_ip": "Client address",
    "attribution": "Device attribution",
    "instruction_tokens": "Instruction-like words",
}


def _evidence_value(key: str, value: Any) -> str:
    if key == "status":
        return _status_word(value)
    if value is None:  # only the rank is kept when empty: no rank made the rule fire
        return "not ranked"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.2f}".rstrip("0").rstrip(".")
    return safe(value, limit=300)


#: Evidence fields whose values came from outside: names from DNS traffic, the
#: listed name a feed matched, device names, and NextDNS's reason ids and names.
#: The page sets them as outside names.
OUTSIDE_FIELDS = frozenset(
    {
        "fqdn",
        "sample_fqdn",
        "root",
        "label",
        "threat_match",
        "device_name",
        "category",
        "category_name",
    }
)


def _evidence(evidence: Mapping[str, Any]) -> list[tuple[str, str, bool]]:
    """A finding's evidence as (label, value, from outside) rows.

    Every string is cleaned and defanged.
    """
    order = {key: index for index, key in enumerate(EVIDENCE_LABELS)}
    rows = []
    for key in sorted(evidence, key=lambda name: (order.get(name, len(order)), name)):
        value = evidence[key]
        if value is None and key != "popularity_rank":
            continue
        words = key.replace("_", " ")
        label = EVIDENCE_LABELS.get(key) or safe(words[:1].upper() + words[1:], limit=60)
        rows.append((label, _evidence_value(key, value), key in OUTSIDE_FIELDS))
    return rows


def _about(finding: StoredFinding) -> str:
    """What a finding is about, cleaned: a reason's name where NextDNS gave one, else its target."""
    return about_text(finding.rule_id, finding.target, finding.evidence, limit=255)


def _check_state(check: Any) -> tuple[str, str]:
    """A health check's state as (style, word).

    A passing check that is still working something out reads "Retrying" or
    "Catching up", not "OK".
    """
    if not check.ok:
        return "problem", "Problem"
    if check.detail == CATCHING_UP:
        return "watch", "Catching up"
    if check.key.startswith("api:") and check.detail != OK:
        return "watch", "Retrying"
    return "ok", "OK"


def _average(value: float | None) -> str:
    """A daily or hourly average: tenths below 100, whole numbers above."""
    if value is None:
        return "n/a"
    if abs(value) >= 100:
        return f"{value:,.0f}"
    return f"{value:,.1f}".removesuffix(".0")


def _breakable(value: str) -> Markup:
    """An already-cleaned name that may wrap only after its defanged dots."""
    return Markup("[.]<wbr>").join(escape(part) for part in value.split("[.]"))


@functools.cache
def _version(path: str) -> str:
    """A short hash of one of our static files, for its URL (``?v=``).

    A changed file gets a new URL, so after an upgrade no browser can pair new
    pages with an old stylesheet or script from its cache. Vendored files carry
    their version in the file name instead.
    """
    content = (importlib.resources.files("sentinel.web") / "static" / path).read_bytes()
    return hashlib.sha256(content).hexdigest()[:12]


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
        "domain_wrap": lambda value: _breakable(safe(value, limit=255)),
        "about": _about,
        "check_state": _check_state,
        "text": lambda value: safe(value, limit=300),
        "prose": lambda value: prose(value, limit=600),
        "detail": _detail,
        "status_word": _status_word,
        "evidence": _evidence,
        "local": _local,
        "clock": _clock,
        "since": _since,
        "span": lambda finding, tz: span(finding.first_ts, finding.last_ts, tz),
        "ago": duration,
        "num": lambda value: f"{value:,}",
        "pct": lambda value: f"{value:.0%}",
        "secs": lambda value: f"{value / 1000:.1f} s",
        "avg": _average,
    }
)
TEMPLATE_ENV.globals["version"] = _version


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
    #: Live feed: how often to look for new events and to send counters, how
    #: long one stream lasts before the browser reconnects, and how many
    #: streams may be open at once.
    live_poll_seconds: float = 1.0
    live_stats_seconds: float = 5.0
    live_max_seconds: float = 900.0
    live_max_streams: int = 8
    #: When the daily digest is produced (HH:MM, local), for the Digests page.
    digest_time: str | None = None


class LoginRequired(Exception):
    """The request has no live session."""


@dataclass(frozen=True, slots=True)
class View:
    """One request's session and the profiles it shows, with reads limited to them."""

    session: Session
    scope: str  # ALL or a profile id
    profiles: tuple[ProfileConfig, ...]
    queries: DashboardQueries
    live: LiveQueries
    series: SeriesQueries
    here: str  # this page's path and query, to come back to


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
    live = LiveQueries(ctx.engine, profiles=ctx.profiles)
    series = SeriesQueries(ctx.engine, profiles=ctx.profiles)
    triage = TriageStore(ctx.engine)
    labels = {profile.id: profile.label for profile in ctx.profiles}
    #: Each profile's layer: its position picks its ink (``layer-1``, ``layer-2``...).
    layers = {profile.id: index + 1 for index, profile in enumerate(ctx.profiles)}
    specs = {spec.id: spec for spec in ctx.specs}
    #: Each rule's plain name; the id stands in for a rule without one.
    rule_names = {spec.id: spec.name or spec.id for spec in ctx.specs}

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(ctx.allowed_hosts))
    app.add_middleware(SecurityHeaders)
    app.mount("/static", StaticFiles(packages=[("sentinel.web", "static")]), name="static")

    def render(name: str, *, status: int = 200, **values: Any) -> HTMLResponse:
        context = {
            "tz": ctx.tz,
            "labels": labels,
            "layers": layers,
            "label_inks": {labels[pid]: ink for pid, ink in layers.items()},
            "nav": "",
            "domain_rules": DOMAIN_RULES,
            "rule_names": rule_names,
        }
        context.update(values)
        return HTMLResponse(TEMPLATE_ENV.get_template(name).render(**context), status_code=status)

    def scope_of(request: Request) -> tuple[str, tuple[ProfileConfig, ...]]:
        wanted = request.cookies.get(SCOPE_COOKIE, ALL)
        chosen = tuple(profile for profile in ctx.profiles if profile.id == wanted)
        return (wanted, chosen) if chosen else (ALL, tuple(ctx.profiles))

    def here_of(request: Request) -> str:
        return request.url.path + (f"?{request.url.query}" if request.url.query else "")

    async def page(name: str, request: Request, **values: Any) -> HTMLResponse:
        """A full page with the navigation rail: live status and the profile switch."""
        shell = await queries.shell()
        scope, _ = scope_of(request)
        here = here_of(request)
        switch = [
            {
                "id": ALL,
                "label": "Both" if len(ctx.profiles) == 2 else "All profiles",
                "open": shell.open_findings,
                "current": scope == ALL,
            }
        ]
        switch += [
            {
                "id": profile.id,
                "label": profile.label,
                "open": shell.open_by_profile.get(profile.id, 0),
                "current": scope == profile.id,
            }
            for profile in ctx.profiles
        ]
        return render(
            name,
            shell=shell,
            now=ctx.clock(),
            scope=scope,
            scope_label=next(item["label"] for item in switch if item["current"]),
            switch=switch if len(ctx.profiles) > 1 else [],
            here=here,
            **values,
        )

    def session_of(request: Request) -> Session:
        session = sessions.get(request.cookies.get(SESSION_COOKIE))
        if session is None:
            raise LoginRequired
        return session

    SessionDep = Annotated[Session, Depends(session_of)]

    def view_of(request: Request, session: SessionDep) -> View:
        scope, chosen = scope_of(request)
        return View(
            session=session,
            scope=scope,
            profiles=chosen,
            queries=queries if scope == ALL else DashboardQueries(ctx.engine, profiles=chosen),
            live=live if scope == ALL else LiveQueries(ctx.engine, profiles=chosen),
            series=series if scope == ALL else SeriesQueries(ctx.engine, profiles=chosen),
            here=here_of(request),
        )

    ViewDep = Annotated[View, Depends(view_of)]

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
        message = (
            exc.detail if exc.status_code in (400, 403, 422, 429) else "That page does not exist."
        )
        heading = ERROR_TITLES.get(exc.status_code, "Something went wrong")
        if exc.status_code == 405:
            message = "That is not allowed here."
        elif exc.status_code == 404 and (found := FINDING_PATH.fullmatch(request.url.path)):
            heading = f"Finding {int(found[1]):04d} not found"
            message = (
                f"There is no finding {int(found[1]):04d}. Findings are deleted once they are "
                "older than the retention period, so a link from an old digest or alert "
                "can outlive its finding."
            )
        values: dict[str, Any] = {
            "status": exc.status_code,
            "code": exc.status_code,
            "message": message,
            "heading": heading,
            "title": heading,
        }
        # A logged-in owner keeps the menu, so the error is not a dead end.
        session = sessions.get(request.cookies.get(SESSION_COOKIE))
        if session is not None and not _is_htmx(request):
            return await page("error.html", request, csrf=session.csrf, **values)
        return render("error.html", **values)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> Response:
        return render(
            "error.html",
            status=422,
            code=422,
            message="That request was not valid.",
            heading=ERROR_TITLES[422],
            title=ERROR_TITLES[422],
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
            return login_page(
                status=401,
                error="That token is not right. It must match DASHBOARD_TOKEN in your .env "
                "file exactly, capital letters included.",
            )
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

    async def overview_chart(view: View, now: datetime, alerts: Sequence[Any]) -> Any:
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

    @app.get("/")
    async def overview(view: ViewDep, request: Request) -> HTMLResponse:
        now = ctx.clock()
        alerts = await view.queries.open_alerts()
        digest, chart = await overview_chart(view, now, alerts)
        return await page(
            "overview.html",
            request,
            nav="overview",
            title="Overview",
            csrf=view.session.csrf,
            digest=digest,
            levels=[level.value for level in sorted(Severity, key=lambda s: -s.rank)],
            chart=chart,
            alerts=alerts,
            recent=[feed_item(item) for item in await view.live.recent(8)],
            stats=await view.live.stats(now),
            new_devices_avg=await view.queries.new_devices_per_day(now),
            revisions_today=await view.queries.revisions_since(
                datetime.combine(now.astimezone(ctx.tz).date(), dt_time(0), tzinfo=ctx.tz)
            ),
            next_url="/",
        )

    @app.get("/scope")
    async def set_scope(session: SessionDep, request: Request) -> Response:
        """Choose which profiles every page shows; remembered for this browser."""
        wanted = request.query_params.get("to") or ALL
        if wanted != ALL and wanted not in labels:
            raise HTTPException(422, "There is no such profile.")
        response = RedirectResponse(_safe_next(request.query_params.get("next") or "/"), 303)
        response.set_cookie(
            SCOPE_COOKIE,
            wanted,
            max_age=365 * 24 * 3600,
            path="/",
            httponly=True,
            samesite="strict",
        )
        return response

    @app.get("/partials/decide")
    async def decide_partial(view: ViewDep) -> HTMLResponse:
        return render(
            "_findings_table.html",
            rows=await view.queries.open_alerts(),
            csrf=view.session.csrf,
            next_url="/",
            empty_text="No open high or critical findings.",
            table_id="decide",
        )

    # --- interactive charts -----------------------------------------------------------

    def span_of(request: Request, *, default: timedelta) -> tuple[datetime, datetime]:
        now = ctx.clock()
        params = request.query_params
        try:
            end = datetime.fromtimestamp(int(params["to"]), UTC) if params.get("to") else now
            start = (
                datetime.fromtimestamp(int(params["from"]), UTC)
                if params.get("from")
                else end - default
            )
        except ValueError, OverflowError, OSError:
            raise HTTPException(422, "A time value was not valid.") from None
        return SeriesQueries.clamp(start, end, now)

    def finding_item(item: SeriesFinding) -> dict[str, Any]:
        about = labels.get(item.profile_id, "") if item.about == item.profile_id else item.about
        return {
            "id": item.id,
            "t": item.t,
            "priority": item.priority,
            "rule": item.rule,
            "about": safe(about, limit=120),
            "status": item.status,
            "profile": labels.get(item.profile_id, ""),
            "ink": layers.get(item.profile_id, 0),
        }

    @app.get("/api/series")
    async def series_api(view: ViewDep, request: Request) -> Response:
        start, end = span_of(request, default=timedelta(hours=24))
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
                    "label": labels[layer.profile_id],
                    "ink": layers[layer.profile_id],
                    "allowed": layer.allowed,
                    "blocked": layer.blocked,
                }
                for layer in result.layers
            ],
            "findings": [finding_item(item) for item in result.findings],
            "now": int(ctx.clock().timestamp()),
        }
        return Response(
            json.dumps(body, ensure_ascii=True).replace("<", "\\u003c"),
            media_type="application/json",
        )

    @app.get("/partials/window")
    async def window_partial(view: ViewDep, request: Request) -> HTMLResponse:
        start, end = span_of(request, default=timedelta(hours=1))
        window = await view.series.window(start, end)
        return render(
            "_window.html",
            window=window,
            found=[finding_item(item) for item in window.findings],
            latest=[feed_item(item) for item in window.latest],
        )

    # --- live feed --------------------------------------------------------------------

    def feed_item(item: LiveEvent) -> dict[str, Any]:
        """One event as the browser receives it: every string cleaned and defanged."""
        return {
            "id": item.event_id[:64],
            "t": int(item.ts.timestamp()),
            "time": f"{item.ts.astimezone(ctx.tz):%H:%M:%S}",
            "profile": labels.get(item.profile_id, item.profile_id),
            "ink": layers.get(item.profile_id, 0),
            "device": safe(item.device, limit=64) if item.device else None,
            "domain": safe(item.fqdn, limit=255),
            "status": "blocked" if item.status == "blocked" else "allowed",
            "reason": safe(item.reason, limit=80) if item.reason else None,
        }

    def open_by_layer(by_profile: Mapping[str, int]) -> dict[str, int]:
        """Open findings keyed by switch layer.

        "0" counts every profile, then each profile has its layer number, so the
        page never needs a profile id.
        """
        counts = {str(layers[pid]): by_profile.get(pid, 0) for pid in layers}
        counts["0"] = sum(by_profile.get(pid, 0) for pid in layers)
        return counts

    def stats_item(stats: LiveStats, now: datetime) -> dict[str, Any]:
        age = (now - stats.newest_event).total_seconds() if stats.newest_event else None
        return {
            "last_minute": stats.last_minute,
            "blocked_last_minute": stats.blocked_last_minute,
            "per_minute": stats.per_minute,
            "open_findings": stats.open_findings,
            "open_by_layer": open_by_layer(stats.open_by_profile),
            "newest_finding_id": stats.newest_finding_id,
            "checks_ok": stats.checks_ok,
            "checks_total": stats.checks_total,
            "newest_event": _since(stats.newest_event, now),
            "newest_event_age_s": None if age is None else max(int(age), 0),
        }

    @app.get("/live")
    async def live_page(view: ViewDep, request: Request) -> HTMLResponse:
        now = ctx.clock()
        return await page(
            "live.html",
            request,
            nav="live",
            title="Live",
            csrf=view.session.csrf,
            recent=[feed_item(item) for item in await view.live.recent(60)],
            stats=await view.live.stats(now),
        )

    streams = {"open": 0}

    async def scoped_stats(view: View, now: datetime) -> LiveStats:
        """The view's traffic figures, with the open findings of every profile.

        The open count feeds the rail, which always counts every profile, so a
        finding on a profile not shown is never hidden.
        """
        stats = await view.live.stats(now)
        if view.scope == ALL:
            return stats
        everything = await live.stats(now)
        return dataclasses.replace(
            stats,
            open_findings=everything.open_findings,
            newest_finding_id=everything.newest_finding_id,
            open_by_profile=everything.open_by_profile,
        )

    @app.get("/live/stream")
    async def live_stream(view: ViewDep) -> Response:
        session = view.session
        if streams["open"] >= ctx.live_max_streams:
            raise HTTPException(429, "Too many live views are open. Close one and reload.")

        def message(event: str, data: Any) -> bytes:
            # "<" is escaped too, so even a raw view of the stream shows no markup.
            body = json.dumps(data, ensure_ascii=True).replace("<", "\\u003c")
            return f"event: {event}\ndata: {body}\n\n".encode()

        async def stream() -> AsyncIterator[bytes]:
            streams["open"] += 1
            try:
                started = time.monotonic()
                cursor = view.live.start(ctx.clock())
                last_stats = 0.0
                last_finding: int | None = None
                last_open: int | None = None
                yield b"retry: 3000\n\n"
                # Starlette cancels this generator when the browser disconnects.
                while time.monotonic() - started < ctx.live_max_seconds:
                    if sessions.get(session.id) is None:  # logged out or expired
                        yield message("bye", {"reason": "session ended"})
                        break
                    fresh = await view.live.poll(cursor)
                    if fresh:
                        yield message("queries", [feed_item(item) for item in fresh])
                    if time.monotonic() - last_stats >= ctx.live_stats_seconds:
                        last_stats = time.monotonic()
                        now = ctx.clock()
                        stats = await scoped_stats(view, now)
                        yield message("stats", stats_item(stats, now))
                        if last_open is not None and (
                            stats.open_findings != last_open
                            or stats.newest_finding_id != last_finding
                        ):
                            yield message("findings", {"open": stats.open_findings})
                        last_open, last_finding = stats.open_findings, stats.newest_finding_id
                    await asyncio.sleep(ctx.live_poll_seconds)
            finally:
                streams["open"] -= 1

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
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
    async def findings_page(view: ViewDep, request: Request) -> HTMLResponse:
        wanted = parse_filter(request)
        rows = await view.queries.findings(wanted, tz=ctx.tz)
        values: dict[str, Any] = {
            "csrf": view.session.csrf,
            "rows": rows,
            "next_url": view.here,
            "table_id": "findings",
        }
        if _is_htmx(request):
            return render("_findings_table.html", **values)
        return await page(
            "findings.html",
            request,
            nav="findings",
            title="Findings",
            wanted=wanted,
            devices=await view.queries.devices_in_findings(),
            days=await view.queries.finding_days(tz=ctx.tz),
            today=ctx.clock().astimezone(ctx.tz).date(),
            rules=sorted(specs, key=lambda rule_id: rule_names[rule_id].lower()),
            severities=[level.value for level in Severity],
            statuses=[*STATUSES, "all"],
            **values,
        )

    @app.get("/findings/{finding_id}")
    async def finding_page(view: ViewDep, request: Request, finding_id: int) -> HTMLResponse:
        # Looked up across every profile: a link from an alert or a digest works
        # whichever profiles the pages are showing.
        row = await queries.finding(finding_id)
        if row is None:
            raise HTTPException(404)
        now = ctx.clock()
        previous, following = await view.queries.neighbours(finding_id)
        return await page(
            "finding.html",
            request,
            nav="findings",
            title=f"Finding {finding_id:04d}",
            csrf=view.session.csrf,
            row=row,
            spec=specs.get(row.finding.rule_id),
            enrichment=await queries.enrichment(row.finding, now),
            queries=await queries.recent_queries(row.finding),
            audit=await triage.audit_for([finding_id]),
            previous_id=previous,
            next_id=following,
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
            response = render("_finding_row.html", row=row, csrf=session.csrf, next_url=next_url)
            # Every open count on the page follows the decision at once.
            shell = await queries.shell()
            response.headers["HX-Trigger"] = json.dumps(
                {"sentinel-counts": {"layers": open_by_layer(shell.open_by_profile)}}
            )
            return response
        return RedirectResponse(next_url, status_code=303)

    @app.get("/domains")
    async def domains_page(view: ViewDep, request: Request, period: str = "24h") -> HTMLResponse:
        if period not in PERIODS:
            raise HTTPException(422, "Unknown period.")
        return await page(
            "domains.html",
            request,
            nav="domains",
            title="Domains",
            csrf=view.session.csrf,
            period=period,
            page=await view.queries.domains(ctx.clock(), PERIODS[period]),
        )

    @app.get("/devices")
    async def devices_page(view: ViewDep, request: Request) -> HTMLResponse:
        return await page(
            "devices.html",
            request,
            nav="devices",
            title="Devices",
            csrf=view.session.csrf,
            profiles=await view.queries.devices(ctx.clock()),
        )

    @app.get("/digests")
    async def digests_page(session: SessionDep, request: Request) -> HTMLResponse:
        return await page(
            "digests.html",
            request,
            nav="digests",
            title="Digests",
            csrf=session.csrf,
            digests=await queries.digests(),
            digest_time=ctx.digest_time,
        )

    @app.get("/digests/{digest_id}")
    async def digest_page(session: SessionDep, request: Request, digest_id: int) -> HTMLResponse:
        digest = await queries.digest(digest_id)
        if digest is None:
            raise HTTPException(404)
        return await page(
            "digest.html",
            request,
            nav="digests",
            title=digest.title,
            csrf=session.csrf,
            digest=digest,
        )

    @app.get("/health")
    async def health_page(session: SessionDep, request: Request) -> HTMLResponse:
        return await page(
            "health.html",
            request,
            nav="health",
            title="Health",
            csrf=session.csrf,
            health=await queries.health(ctx.clock()),
        )

    @app.get("/evaluation")
    async def evaluation_page(session: SessionDep, request: Request) -> HTMLResponse:
        return await page(
            "evaluation.html",
            request,
            nav="evaluation",
            title="Evaluation",
            csrf=session.csrf,
            run=await EvalStore(ctx.engine).latest(),
        )

    return app
