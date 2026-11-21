"""Health monitor: periodic checks, stored results and alerts when something changes.

Checks, in this order:

* per enabled profile, events arriving (silence beyond the window, not counting
  the profile's quiet hours) and the NextDNS API answering;
* the local model (Ollama reachable and the model downloaded);
* the backlog of events waiting for the rules;
* free disk space where the database lives.

A check that turns bad raises one health alert. It counts as recovered only
after two good results in a row, which absorbs flapping, and then a "resolved"
message follows. What the user was last told is read back from the outbox, so a
restart neither repeats a problem alert nor forgets to say it was resolved.
Details are our own wording with numbers and profile labels, never log data.
"""

import asyncio
import re
import shutil
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from zoneinfo import ZoneInfo

import httpx
import structlog

from vedette.config import HealthConfig, ProfileConfig
from vedette.health.state import HealthState
from vedette.notify.render import render_health
from vedette.notify.schedule import QuietHours
from vedette.storage.health import HealthCheck, HealthStore
from vedette.storage.notifications import NotificationStore
from vedette.storage.store import Store

log = structlog.get_logger(__name__)

OK = "OK"
UNEXPECTED_RETRY_SECONDS = 30.0
STALLED_AFTER_INTERVALS = 3
RESOLVE_AFTER_CHECKS = 2
PROBLEM_PREFIX = "Health problem: "
# After a start-up, a profile's silence is not judged until its collector has
# caught up, or until this long has passed if it never reports that.
CATCH_UP_GRACE = timedelta(minutes=10)
CATCHING_UP = "Catching up after start-up"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def duration(span: timedelta) -> str:
    """``45 min``, ``3 h 0 min`` or ``2 d 5 h``."""
    minutes = int(span.total_seconds() // 60)
    days, rest = divmod(minutes, 24 * 60)
    hours, mins = divmod(rest, 60)
    if days:
        return f"{days} d {hours} h"
    if hours:
        return f"{hours} h {mins} min"
    return f"{mins} min"


_HTTP_STATUS = re.compile(r"HTTP (\d{3})")


def api_problem(reason: str) -> tuple[str, int | None]:
    """A NextDNS error in words, and its HTTP status when the reason names one.

    A reason that is not a rate limit, a refused key or a server error is
    returned as it was recorded.
    """
    found = _HTTP_STATUS.search(reason)
    status = int(found[1]) if found else None
    if status == 429:
        return "NextDNS is rate-limiting Vedette", status
    if status in (401, 403):
        return "NextDNS refused the API key", status
    if status is not None and status >= 500:
        return "NextDNS answered with a server error", status
    return reason, status


class Probe(Protocol):
    """Something that can say whether the local model is usable."""

    async def check(self) -> str | None:
        """``None`` when usable, otherwise a short description of the problem."""
        ...


class OllamaProbe:
    """Asks Ollama which models it has."""

    def __init__(
        self, base_url: str, model: str, *, client: httpx.AsyncClient | None = None
    ) -> None:
        """Probe the Ollama server at ``base_url`` for ``model``."""
        self._model = model if ":" in model else f"{model}:latest"
        self._client = client or httpx.AsyncClient(base_url=base_url, timeout=httpx.Timeout(5.0))

    async def aclose(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def check(self) -> str | None:
        """``None`` if Ollama answers and has the model, otherwise the problem."""
        try:
            response = await self._client.get("/api/tags")
            body = response.json() if response.status_code == 200 else None
        except httpx.HTTPError, ValueError:
            body = None
        models = body.get("models") if isinstance(body, dict) else None
        if not isinstance(models, list):
            return "Local model unreachable"
        names = {
            str(item.get(field))
            for item in models
            if isinstance(item, dict)
            for field in ("name", "model")
            if item.get(field)
        }
        if self._model not in names:
            return f"Model {self._model} is not downloaded"
        return None


class HealthMonitor:
    """Runs the health checks and reports changes."""

    def __init__(
        self,
        *,
        store: Store,
        state: HealthState,
        health_store: HealthStore,
        notifications: NotificationStore,
        profiles: Sequence[ProfileConfig],
        config: HealthConfig,
        ollama: Probe,
        data_path: Path | None,
        tz: ZoneInfo,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        disk_usage: Callable[[Path], Any] = shutil.disk_usage,
        started_at: datetime | None = None,
    ) -> None:
        """Create the monitor.

        Args:
            store: Event storage (latest event times, backlog).
            state: Reports from the collectors.
            health_store: Where results are kept for the digest and dashboard.
            notifications: The outbox for health alerts.
            profiles: Enabled profiles.
            config: Windows and thresholds.
            ollama: Probe for the local model.
            data_path: Directory holding the database, for the disk check.
            tz: Time zone of profile quiet hours and of alert text.
            clock: Returns the current time (UTC).
            sleep: Awaitable used between runs.
            disk_usage: Returns total, used and free bytes for a path.
            started_at: When the service started (for profiles with no events yet).
        """
        self._store = store
        self._state = state
        self._health_store = health_store
        self._notifications = notifications
        self._profiles = list(profiles)
        self._config = config
        self._ollama = ollama
        self._data_path = data_path
        self._tz = tz
        self._clock = clock
        self._sleep = sleep
        self._disk_usage = disk_usage
        self._started_at = started_at or clock()
        self._ollama_down_since: datetime | None = None
        self._backlog_since: datetime | None = None
        # Problems the user has been told about: check key -> (since, detail).
        self._problems: dict[str, tuple[datetime, str]] = {}
        self._ok_streak: dict[str, int] = {}
        self._recalled: set[str] = set()
        self.last_run_at: datetime | None = None
        self.last_checks: list[HealthCheck] = []

    async def run(self) -> None:
        """Check forever. Cancel the task to stop."""
        while True:
            try:
                await self.run_once()
            except Exception:  # must keep running unattended; logged with traceback
                log.exception("health_monitor_unexpected_error")
                await self._sleep(UNEXPECTED_RETRY_SECONDS)
                continue
            await self._sleep(self._config.check_interval_seconds)

    async def run_once(self) -> list[HealthCheck]:
        """Run every check once, store the results and alert on changes."""
        now = self._clock()
        checks: list[HealthCheck] = []
        for profile in self._profiles:
            checks.append(await self._events_check(profile, now))
            checks.append(self._api_check(profile, now))
        checks.append(await self._ollama_check(now))
        checks.append(await self._backlog_check(now))
        checks.append(self._disk_check())
        await self._health_store.save(checks, now=now)
        await self._alert_changes(checks, now)
        self.last_run_at = now
        self.last_checks = checks
        return checks

    async def _events_check(self, profile: ProfileConfig, now: datetime) -> HealthCheck:
        key, label = f"events:{profile.id}", f"Events from {profile.label}"
        window = (
            profile.stale_after_minutes
            if profile.stale_after_minutes is not None
            else self._config.stale_after_minutes
        )
        if window == 0:
            return HealthCheck(key, label, True, "Check switched off for this profile")
        last = await self._store.latest_event_ts(profile.id)
        since = last if last is not None else self._started_at
        quiet = QuietHours.parse(profile.quiet_hours) if profile.quiet_hours else None
        silence = now - since - (quiet.overlap(since, now, self._tz) if quiet else timedelta(0))
        if silence < timedelta(minutes=window):
            return HealthCheck(key, label, True, OK)
        if (
            last is not None
            and last < self._started_at
            and not self._state.is_caught_up(profile.id)
            and now - self._started_at < CATCH_UP_GRACE
        ):
            # The silence began while Vedette itself was off; the collector is
            # still reading what the profile sent meanwhile.
            return HealthCheck(key, label, True, CATCHING_UP, pending=True)
        if last is None:
            return HealthCheck(key, label, False, f"No events received from {profile.label} yet")
        return HealthCheck(
            key, label, False, f"No events from {profile.label} for {duration(now - last)}"
        )

    def _api_check(self, profile: ProfileConfig, now: datetime) -> HealthCheck:
        key, label = f"api:{profile.id}", f"NextDNS API ({profile.label})"
        failing = self._state.failing_since(profile.id)
        if failing is None:
            return HealthCheck(key, label, True, OK)
        since, reason = failing
        phrase, status = api_problem(reason)
        if now - since < timedelta(minutes=self._config.api_error_minutes):
            return HealthCheck(
                key,
                label,
                True,
                f"{phrase} since {since.astimezone(self._tz):%H:%M}. "
                "Vedette waits and tries again.",
            )
        code = f" (HTTP {status})" if status is not None and phrase != reason else ""
        return HealthCheck(
            key,
            label,
            False,
            f"NextDNS API failing for {duration(now - since)} ({profile.label}): {phrase}{code}",
        )

    async def _ollama_check(self, now: datetime) -> HealthCheck:
        key, label = "ollama", "Local model"
        problem = await self._ollama.check()
        if problem is None:
            self._ollama_down_since = None
            return HealthCheck(key, label, True, OK)
        if self._ollama_down_since is None:
            self._ollama_down_since = now
        down_for = now - self._ollama_down_since
        if down_for < timedelta(minutes=self._config.ollama_down_minutes):
            return HealthCheck(key, label, True, f"{problem} (for {duration(down_for)})")
        return HealthCheck(key, label, False, f"{problem} for {duration(down_for)}")

    async def _backlog_check(self, now: datetime) -> HealthCheck:
        key, label = "backlog", "Processing backlog"
        waiting = 0
        for profile in self._profiles:
            waiting += await self._store.count_unprocessed(profile.id)
        if waiting <= self._config.max_backlog_events:
            self._backlog_since = None
            return HealthCheck(key, label, True, f"{waiting} events waiting")
        if self._backlog_since is None:
            self._backlog_since = now
        lasting = now - self._backlog_since
        if lasting < timedelta(minutes=self._config.backlog_minutes):
            return HealthCheck(key, label, True, f"{waiting} events waiting")
        return HealthCheck(
            key, label, False, f"{waiting} events waiting for the rules for {duration(lasting)}"
        )

    def _disk_check(self) -> HealthCheck:
        key, label = "disk", "Disk space"
        if self._data_path is None:
            return HealthCheck(key, label, True, "Not checked")
        try:
            usage = self._disk_usage(self._data_path)
        except OSError:
            return HealthCheck(key, label, False, "Disk usage could not be read")
        percent = 100.0 * usage.used / usage.total if usage.total else 0.0
        free_gb = usage.free / 2**30
        detail = f"Disk {percent:.0f}% full ({free_gb:.1f} GB free)"
        return HealthCheck(key, label, percent < self._config.max_disk_percent, detail)

    async def _recall(self, key: str) -> None:
        """Once per check, learn from the outbox whether an open problem was announced."""
        if key in self._recalled:
            return
        self._recalled.add(key)
        last = await self._notifications.last_health_message(key)
        if last is not None and last[0] == "problem":
            _, title, created_at = last
            self._problems[key] = (created_at, title.removeprefix(PROBLEM_PREFIX))

    async def _alert_changes(self, checks: Sequence[HealthCheck], now: datetime) -> None:
        for check in checks:
            if check.pending:
                continue
            await self._recall(check.key)
            told = self._problems.get(check.key)
            if not check.ok:
                self._ok_streak.pop(check.key, None)
                if told is not None:
                    continue
                await self._notifications.enqueue(
                    kind="health",
                    key=f"health|{check.key}",
                    message=render_health(check.detail, resolved=False, since=now, tz=self._tz),
                    now=now,
                )
                self._problems[check.key] = (now, check.detail)
                log.warning("health_problem", check=check.key, detail=check.detail)
            elif told is not None:
                streak = self._ok_streak.get(check.key, 0) + 1
                if streak < RESOLVE_AFTER_CHECKS:
                    self._ok_streak[check.key] = streak
                    continue
                since, detail = self._problems.pop(check.key)
                self._ok_streak.pop(check.key, None)
                await self._notifications.enqueue(
                    kind="health",
                    key=f"health|{check.key}|resolved",
                    message=render_health(detail, resolved=True, since=since, tz=self._tz),
                    now=now,
                )
                log.info("health_resolved", check=check.key)

    def snapshot(self) -> tuple[int, dict[str, Any]]:
        """HTTP status and JSON body for ``/healthz``.

        503 until the first check has run, or when checks have stopped running;
        otherwise 200 with ``ok`` or ``degraded`` and every check's result.
        """
        if self.last_run_at is None:
            return 503, {"status": "starting"}
        now = self._clock()
        stalled_after = timedelta(
            seconds=self._config.check_interval_seconds * STALLED_AFTER_INTERVALS
        )
        if now - self.last_run_at > stalled_after:
            return 503, {"status": "stalled", "last_check": self.last_run_at.isoformat()}
        problems = any(not check.ok for check in self.last_checks)
        return 200, {
            "status": "degraded" if problems else "ok",
            "last_check": self.last_run_at.isoformat(),
            "checks": [
                {"check": check.key, "label": check.label, "ok": check.ok, "detail": check.detail}
                for check in self.last_checks
            ],
        }
