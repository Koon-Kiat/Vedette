"""What every dashboard route shares: settings, stores, sessions and page rendering.

One :class:`Dashboard` is built per app and kept on ``app.state``. Routes reach
it, the session and the request's view through the dependencies at the end of
this module.
"""

import dataclasses
import hmac
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException

from vedette.config import ProfileConfig
from vedette.notify.render import safe
from vedette.rules.model import RuleSpec, Severity
from vedette.storage.dashboard import DashboardQueries, FindingFilter
from vedette.storage.live import LiveEvent, LiveQueries, LiveStats
from vedette.storage.series import SeriesFinding, SeriesQueries
from vedette.storage.triage import DOMAIN_RULES, STATUSES, TriageStore
from vedette.web.auth import SESSION_COOKIE, LoginLimiter, Session, SessionStore
from vedette.web.templating import TEMPLATE_ENV, _since

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
SCOPE_COOKIE = "vedette_scope"
ALL = "all"


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


def is_htmx(request: Request) -> bool:
    """Whether htmx sent the request (it then wants a partial, not a page)."""
    return request.headers.get("HX-Request") == "true"


def safe_next(value: object) -> str:
    """A redirect target inside the dashboard; anything else becomes the findings page.

    Browsers delete tabs and line breaks from a URL, so ``/<tab>/evil.example``
    would read as ``//evil.example``. Starlette percent-encodes the Location
    header, which already prevents that, but this check does not rely on it:
    control characters and spaces are refused outright.
    """
    if (
        isinstance(value, str)
        and value.startswith("/")
        and not value.startswith("//")
        and "\\" not in value
        and not any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value)
    ):
        parts = urlsplit(value)
        if not parts.scheme and not parts.netloc:
            return value
    return "/findings"


class Dashboard:
    """The shared state of one dashboard app and the helpers its routes use."""

    def __init__(self, ctx: DashboardContext) -> None:
        """Open the stores and session handling for ``ctx``."""
        self.ctx = ctx
        self.sessions = SessionStore(ctx.session_lifetime, ctx.clock)
        self.limiter = LoginLimiter(ctx.clock)
        self.queries = DashboardQueries(ctx.engine, profiles=ctx.profiles)
        self.live = LiveQueries(ctx.engine, profiles=ctx.profiles)
        self.series = SeriesQueries(ctx.engine, profiles=ctx.profiles)
        self.triage = TriageStore(ctx.engine)
        self.labels = {profile.id: profile.label for profile in ctx.profiles}
        #: Each profile's layer: its position picks its ink (``layer-1``, ``layer-2``...).
        self.layers = {profile.id: index + 1 for index, profile in enumerate(ctx.profiles)}
        self.specs = {spec.id: spec for spec in ctx.specs}
        #: Each rule's plain name; the id stands in for a rule without one.
        self.rule_names = {spec.id: spec.name or spec.id for spec in ctx.specs}
        #: Live streams open right now, held under ``ctx.live_max_streams``.
        self.open_streams = 0

    # --- pages ----------------------------------------------------------------------------

    def render(self, name: str, *, status: int = 200, **values: Any) -> HTMLResponse:
        """A template with the values every page and partial needs."""
        context = {
            "tz": self.ctx.tz,
            "labels": self.labels,
            "layers": self.layers,
            "label_inks": {self.labels[pid]: ink for pid, ink in self.layers.items()},
            "nav": "",
            "domain_rules": DOMAIN_RULES,
            "rule_names": self.rule_names,
        }
        context.update(values)
        return HTMLResponse(TEMPLATE_ENV.get_template(name).render(**context), status_code=status)

    def scope_of(self, request: Request) -> tuple[str, tuple[ProfileConfig, ...]]:
        """The profiles this browser chose to see: all, or one."""
        wanted = request.cookies.get(SCOPE_COOKIE, ALL)
        chosen = tuple(profile for profile in self.ctx.profiles if profile.id == wanted)
        return (wanted, chosen) if chosen else (ALL, tuple(self.ctx.profiles))

    @staticmethod
    def here_of(request: Request) -> str:
        """This page's path and query, to come back to."""
        return request.url.path + (f"?{request.url.query}" if request.url.query else "")

    async def page(self, name: str, request: Request, **values: Any) -> HTMLResponse:
        """A full page with the navigation rail: live status and the profile switch."""
        ctx = self.ctx
        shell = await self.queries.shell()
        scope, _ = self.scope_of(request)
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
        return self.render(
            name,
            shell=shell,
            now=ctx.clock(),
            scope=scope,
            scope_label=next(item["label"] for item in switch if item["current"]),
            switch=switch if len(ctx.profiles) > 1 else [],
            here=self.here_of(request),
            **values,
        )

    def view(self, request: Request, session: Session) -> View:
        """The request's view: reads limited to the profiles it shows."""
        ctx = self.ctx
        scope, chosen = self.scope_of(request)
        whole = scope == ALL
        return View(
            session=session,
            scope=scope,
            profiles=chosen,
            queries=self.queries if whole else DashboardQueries(ctx.engine, profiles=chosen),
            live=self.live if whole else LiveQueries(ctx.engine, profiles=chosen),
            series=self.series if whole else SeriesQueries(ctx.engine, profiles=chosen),
            here=self.here_of(request),
        )

    @staticmethod
    async def checked_form(request: Request, session: Session) -> FormData:
        """The posted form, if it carries this session's CSRF token."""
        form = await request.form()
        given = request.headers.get("X-CSRF-Token") or form.get("csrf_token")
        if not isinstance(given, str) or not hmac.compare_digest(
            given.encode(), session.csrf.encode()
        ):
            raise HTTPException(403, "The page was out of date. Reload it and try again.")
        return form

    # --- shapes the browser receives ------------------------------------------------------

    def feed_item(self, item: LiveEvent) -> dict[str, Any]:
        """One event as the browser receives it: every string cleaned and defanged."""
        return {
            "id": item.event_id[:64],
            "t": int(item.ts.timestamp()),
            "time": f"{item.ts.astimezone(self.ctx.tz):%H:%M:%S}",
            "profile": self.labels.get(item.profile_id, item.profile_id),
            "ink": self.layers.get(item.profile_id, 0),
            "device": safe(item.device, limit=64) if item.device else None,
            "domain": safe(item.fqdn, limit=255),
            "status": "blocked" if item.status == "blocked" else "allowed",
            "reason": safe(item.reason, limit=80) if item.reason else None,
        }

    def finding_item(self, item: SeriesFinding) -> dict[str, Any]:
        """A finding marked on a chart."""
        about = (
            self.labels.get(item.profile_id, "") if item.about == item.profile_id else item.about
        )
        return {
            "id": item.id,
            "t": item.t,
            "priority": item.priority,
            "rule": item.rule,
            "about": safe(about, limit=120),
            "status": item.status,
            "profile": self.labels.get(item.profile_id, ""),
            "ink": self.layers.get(item.profile_id, 0),
        }

    def open_by_layer(self, by_profile: Mapping[str, int]) -> dict[str, int]:
        """Open findings keyed by switch layer.

        "0" counts every profile, then each profile has its layer number, so the
        page never needs a profile id.
        """
        counts = {str(self.layers[pid]): by_profile.get(pid, 0) for pid in self.layers}
        counts["0"] = sum(by_profile.get(pid, 0) for pid in self.layers)
        return counts

    def stats_item(self, stats: LiveStats, now: datetime) -> dict[str, Any]:
        """The live counters as the browser receives them."""
        age = (now - stats.newest_event).total_seconds() if stats.newest_event else None
        return {
            "last_minute": stats.last_minute,
            "blocked_last_minute": stats.blocked_last_minute,
            "per_minute": stats.per_minute,
            "open_findings": stats.open_findings,
            "open_by_layer": self.open_by_layer(stats.open_by_profile),
            "newest_finding_id": stats.newest_finding_id,
            "checks_ok": stats.checks_ok,
            "checks_total": stats.checks_total,
            "newest_event": _since(stats.newest_event, now),
            "newest_event_age_s": None if age is None else max(int(age), 0),
        }

    async def scoped_stats(self, view: View, now: datetime) -> LiveStats:
        """The view's traffic figures, with the open findings of every profile.

        The open count feeds the rail, which always counts every profile, so a
        finding on a profile not shown is never hidden.
        """
        stats = await view.live.stats(now)
        if view.scope == ALL:
            return stats
        everything = await self.live.stats(now)
        return dataclasses.replace(
            stats,
            open_findings=everything.open_findings,
            newest_finding_id=everything.newest_finding_id,
            open_by_profile=everything.open_by_profile,
        )

    # --- reading requests -----------------------------------------------------------------

    def span_of(self, request: Request, *, default: timedelta) -> tuple[datetime, datetime]:
        """The ``from`` and ``to`` of a chart request, clamped to what may be asked."""
        now = self.ctx.clock()
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

    def parse_filter(self, request: Request) -> FindingFilter:
        """The Findings page's filters, each checked against what exists."""
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
            (profile is not None and profile not in self.labels)
            or (rule is not None and rule not in self.specs)
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


# --- dependencies -------------------------------------------------------------------------


def dashboard_of(request: Request) -> Dashboard:
    """The app's dashboard state."""
    dashboard: Dashboard = request.app.state.dashboard
    return dashboard


DashboardDep = Annotated[Dashboard, Depends(dashboard_of)]


def session_of(request: Request, dashboard: DashboardDep) -> Session:
    """The live session, or a redirect to the login page."""
    session = dashboard.sessions.get(request.cookies.get(SESSION_COOKIE))
    if session is None:
        raise LoginRequired
    return session


SessionDep = Annotated[Session, Depends(session_of)]


def view_of(request: Request, session: SessionDep, dashboard: DashboardDep) -> View:
    """The session and the profiles this request shows."""
    return dashboard.view(request, session)


ViewDep = Annotated[View, Depends(view_of)]
