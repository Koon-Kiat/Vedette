"""Notifier stage: instant alerts, delivery through the outbox, and the daily digest.

* :class:`AlertWorker` decides which findings deserve an instant alert and
  writes each decision to the outbox (queued, too old, or within the cooldown).
* :class:`DeliveryWorker` sends queued messages through the configured channel,
  holding non-critical alerts during quiet hours and retrying failures.
* :class:`DigestScheduler` builds and queues the daily digest once a day.

Every decision is stored before anything is sent, so restarts lose nothing and
nothing is sent twice for the same finding.
"""

import asyncio
import random
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

import structlog

from sentinel.notify.channels import Channel, DeliveryError, OutgoingMessage
from sentinel.notify.digest import DAY, DigestBuilder, render_digest
from sentinel.notify.render import alert_key, render_alert
from sentinel.notify.schedule import QuietHours, latest_occurrence
from sentinel.retry import backoff_delay
from sentinel.rules.model import RuleSpec, Severity
from sentinel.storage.notifications import NotificationStore

log = structlog.get_logger(__name__)

UNEXPECTED_RETRY_SECONDS = 30.0
_HELD_IN_QUIET_HOURS = frozenset({"alert", "health"})


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AlertWorker:
    """Turns high and critical findings into outbox entries."""

    def __init__(
        self,
        store: NotificationStore,
        *,
        specs: Sequence[RuleSpec],
        labels: Mapping[str, str],
        tz: ZoneInfo,
        cooldown: timedelta,
        max_age: timedelta,
        analysis_wait: timedelta,
        interval: float = 2.0,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Create the worker.

        Args:
            store: The outbox.
            specs: Rule definitions, for the description of unexplained findings.
            labels: Profile id to label.
            tz: Time zone for times shown in alerts.
            cooldown: No second alert about the same thing within this period.
            max_age: Findings whose last event is older go to the digest only.
            analysis_wait: How long a high or critical finding may wait for the
                local model's explanation before it is sent without one.
            interval: Seconds between passes.
            clock: Returns the current time (UTC).
            sleep: Awaitable used between passes.
        """
        self._store = store
        self._specs = {spec.id: spec for spec in specs}
        self._labels = dict(labels)
        self._tz = tz
        self._cooldown = cooldown
        self._max_age = max_age
        self._analysis_wait = analysis_wait
        self._interval = interval
        self._clock = clock
        self._sleep = sleep

    async def run(self) -> None:
        """Run forever. Cancel the task to stop."""
        while True:
            try:
                await self.run_once()
            except Exception:  # must keep running unattended; logged with traceback
                log.exception("alert_worker_unexpected_error")
                await self._sleep(UNEXPECTED_RETRY_SECONDS)
                continue
            await self._sleep(self._interval)

    async def run_once(self) -> int:
        """Decide on every waiting candidate; return how many alerts were queued."""
        now = self._clock()
        queued = 0
        for candidate in await self._store.alert_candidates():
            finding, analysis = candidate.finding, candidate.analysis
            floor_alerts = finding.severity.rank >= Severity.HIGH.rank
            if analysis is None and floor_alerts and now - finding.first_ts < self._analysis_wait:
                continue
            message = render_alert(
                finding,
                analysis,
                spec=self._specs.get(finding.rule_id),
                profile_label=self._labels.get(finding.profile_id, finding.profile_id),
                tz=self._tz,
            )
            key = alert_key(finding)
            status, reason = "pending", None
            if now - finding.last_ts > self._max_age:
                status, reason = "skipped", "too_old"
            elif self._cooldown > timedelta(0) and await self._store.recently_notified(
                key, since=now - self._cooldown
            ):
                status, reason = "suppressed", "cooldown"
            await self._store.enqueue(
                kind="alert",
                key=key,
                message=message,
                now=now,
                finding_id=finding.id,
                status=status,
                reason=reason,
            )
            log.info(
                "alert_decided",
                finding_id=finding.id,
                rule_id=finding.rule_id,
                priority=message.priority.value,
                status=status,
                reason=reason,
            )
            queued += status == "pending"
        return queued


class DeliveryWorker:
    """Sends due outbox messages through the channel."""

    def __init__(
        self,
        store: NotificationStore,
        channel: Channel | None,
        *,
        quiet_hours: QuietHours | None,
        tz: ZoneInfo,
        max_attempts: int = 10,
        interval: float = 2.0,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rng: Callable[[], float] = random.random,
    ) -> None:
        """Create the worker.

        Args:
            store: The outbox.
            channel: Where to send, or ``None`` when no channel is configured
                (messages are then recorded as skipped).
            quiet_hours: Non-critical alerts and health messages are held until
                these end. Digests are sent at the time chosen for them.
            tz: Time zone of the quiet hours.
            max_attempts: Give up on a message after this many failed tries.
            interval: Seconds between passes.
            clock: Returns the current time (UTC).
            sleep: Awaitable used between passes.
            rng: Random source for backoff jitter.
        """
        self._store = store
        self._channel = channel
        self._quiet = quiet_hours
        self._tz = tz
        self._max_attempts = max_attempts
        self._interval = interval
        self._clock = clock
        self._sleep = sleep
        self._rng = rng

    async def run(self) -> None:
        """Run forever. Cancel the task to stop."""
        while True:
            try:
                await self.run_once()
            except Exception:  # must keep running unattended; logged with traceback
                log.exception("delivery_worker_unexpected_error")
                await self._sleep(UNEXPECTED_RETRY_SECONDS)
                continue
            await self._sleep(self._interval)

    def _held_until(self, kind: str, priority: Severity, now: datetime) -> datetime | None:
        """End of quiet hours if this message must wait for it, else ``None``."""
        quiet = self._quiet
        if (
            quiet is None
            or kind not in _HELD_IN_QUIET_HOURS
            or priority.rank >= Severity.CRITICAL.rank
            or not quiet.contains(now, self._tz)
        ):
            return None
        return quiet.end_after(now, self._tz)

    async def run_once(self) -> int:
        """Handle every due message once; return how many were handled."""
        now = self._clock()
        due = await self._store.due(now)
        for item in due:
            if self._channel is None:
                await self._store.finish(item.id, status="skipped", reason="no_channel")
                continue
            until = self._held_until(item.kind, item.priority, now)
            if until is not None:
                await self._store.defer(item.id, until=until, reason="quiet_hours")
                continue
            attempts = item.attempts + 1
            try:
                await self._channel.send(item.message)
            except DeliveryError as exc:
                reason = str(exc)
                if not exc.retryable or attempts >= self._max_attempts:
                    await self._store.finish(
                        item.id, status="failed", reason=reason, attempts=attempts
                    )
                    log.warning(
                        "notification_failed",
                        id=item.id,
                        kind=item.kind,
                        channel=self._channel.name,
                        reason=reason,
                        attempts=attempts,
                    )
                    continue
                delay = (
                    exc.retry_after
                    if exc.retry_after is not None
                    else backoff_delay(item.attempts, base=30.0, cap=3600.0, rng=self._rng)
                )
                await self._store.reschedule(
                    item.id, at=now + timedelta(seconds=delay), attempts=attempts, reason=reason
                )
                log.warning(
                    "notification_retry",
                    id=item.id,
                    kind=item.kind,
                    channel=self._channel.name,
                    reason=reason,
                    retry_in=delay,
                )
                continue
            await self._store.mark_sent(item.id, now=now, attempts=attempts)
            log.info("notification_sent", id=item.id, kind=item.kind, channel=self._channel.name)
        return len(due)


class DigestScheduler:
    """Builds and queues the daily digest at the configured local time."""

    def __init__(
        self,
        store: NotificationStore,
        builder: DigestBuilder,
        *,
        digest_time: time,
        tz: ZoneInfo,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        started_at: datetime | None = None,
        poll_seconds: float = 60.0,
        oldest_data: Callable[[], Awaitable[datetime | None]] | None = None,
    ) -> None:
        """Create the scheduler.

        Args:
            store: The outbox and digest archive.
            builder: Gathers the digest's numbers.
            digest_time: Local time of day for the digest.
            tz: Time zone of ``digest_time``.
            clock: Returns the current time (UTC).
            sleep: Awaitable used between checks.
            started_at: When the service started. The very first digest is
                produced at the first digest time after this, or late, at
                start-up, when there is data from before the latest one.
            poll_seconds: How often to check whether a digest is due.
            oldest_data: Returns the time of the oldest stored event, if any.
        """
        self._store = store
        self._builder = builder
        self._digest_time = digest_time
        self._tz = tz
        self._clock = clock
        self._sleep = sleep
        self._started_at = started_at or clock()
        self._poll = poll_seconds
        self._oldest_data = oldest_data

    async def run(self) -> None:
        """Run forever. Cancel the task to stop."""
        while True:
            try:
                await self.run_once()
            except Exception:  # must keep running unattended; logged with traceback
                log.exception("digest_unexpected_error")
            await self._sleep(self._poll)

    async def _has_data_before(self, moment: datetime) -> bool:
        if self._oldest_data is None:
            return False
        oldest = await self._oldest_data()
        return oldest is not None and oldest < moment

    async def run_once(self) -> bool:
        """Produce the digest if one is due; return whether one was produced.

        If digests were missed while the service was down, only the most
        recent one is produced, late. That includes the very first: a
        computer that is always off at the digest time still gets one.
        """
        now = self._clock()
        due = latest_occurrence(self._digest_time, now, self._tz)
        last = await self._store.last_digest_end()
        if last is not None and due <= last:
            return False
        if last is None and due <= self._started_at and not await self._has_data_before(due):
            return False
        digest = await self._builder.build(due)
        title, body = render_digest(digest)
        await self._store.record_digest(
            period_start=due - DAY,
            period_end=due,
            now=now,
            message=OutgoingMessage(
                title=title, body=body, priority=Severity.MEDIUM, tags=("newspaper",)
            ),
            data=digest.model_dump(mode="json"),
        )
        log.info(
            "digest_generated",
            period_end=due.isoformat(),
            late=(now - due).total_seconds() > self._poll * 2,
        )
        return True
