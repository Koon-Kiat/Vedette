"""A heartbeat for a dead man's switch: proof that Vedette runs and its alerts get out.

Every interval it sends a plain GET to ``HEARTBEAT_URL``, a check at a service
such as healthchecks.io or Uptime Kuma that raises its own alert when the pings
stop. It pings only while the health checks are running and the alert delivery
check is fine. So the outside service also hears about a channel that stopped
working, which an alert through that very channel could never report, and
about a computer or Docker that is off. The request carries nothing but the
URL, and the URL is a secret: it never reaches a log line.
"""

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import httpx
import structlog

from vedette.health.monitor import HealthMonitor

log = structlog.get_logger(__name__)

PING_TIMEOUT_SECONDS = 10.0
# Before the first health check there is nothing to vouch for; look again this often.
STARTUP_POLL_SECONDS = 1.0


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Heartbeat:
    """Pings a dead man's switch while Vedette is healthy enough to warn you itself."""

    def __init__(
        self,
        monitor: HealthMonitor,
        url: str,
        *,
        client: httpx.AsyncClient,
        interval: timedelta,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Create the heartbeat.

        Args:
            monitor: The health monitor whose latest results decide each ping.
            url: The dead man's switch to ping (a secret).
            client: HTTP client for the ping; it carries no other credential.
            interval: Time between pings.
            clock: Returns the current time (UTC).
            sleep: Awaitable used between pings.
        """
        self._monitor = monitor
        self._url = url
        self._client = client
        self._interval = interval
        self._clock = clock
        self._sleep = sleep

    async def run(self) -> None:
        """Ping on every interval, from the first health check on. Cancel the task to stop."""
        while self._monitor.last_run_at is None:
            await self._sleep(STARTUP_POLL_SECONDS)
        while True:
            await self.beat_once()
            await self._sleep(self._interval.total_seconds())

    async def beat_once(self) -> bool:
        """Ping if Vedette is healthy enough; return whether a ping got through."""
        if self._monitor.last_run_at is None:
            log.info("heartbeat_withheld", reason="health checks have not run yet")
            return False
        if not self._monitor.checks_running(self._clock()):
            log.warning("heartbeat_withheld", reason="health checks have stopped running")
            return False
        delivery = next(
            (check for check in self._monitor.last_checks if check.key == "delivery"), None
        )
        if delivery is not None and not delivery.ok:
            log.warning("heartbeat_withheld", reason="alerts are not being delivered")
            return False
        try:
            response = await self._client.get(self._url, timeout=PING_TIMEOUT_SECONDS)
        except httpx.HTTPError as exc:
            log.warning("heartbeat_failed", error=type(exc).__name__)
            return False
        if response.is_error:
            log.warning("heartbeat_failed", status=response.status_code)
            return False
        return True
