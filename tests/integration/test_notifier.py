"""Instant alerts and delivery: what is sent, when, and what is held back."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from sentinel.llm.schema import Analysis
from sentinel.notify.channels import Channel, DeliveryError, OutgoingMessage
from sentinel.notify.schedule import QuietHours
from sentinel.pipeline.notifier import AlertWorker, DeliveryWorker
from sentinel.rules.loader import load_rules
from sentinel.rules.model import Finding, Severity
from sentinel.storage.analysis import AnalysisStore
from sentinel.storage.notifications import NotificationStore
from sentinel.storage.store import Store

SGT = ZoneInfo("Asia/Singapore")
NOON = datetime(2026, 3, 15, 4, 0, tzinfo=UTC)  # 12:00 in Singapore
LABELS = {"abc123": "router"}


class Clock:
    def __init__(self, now: datetime = NOON) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class FakeChannel(Channel):
    name = "fake"

    def __init__(self) -> None:
        self.sent: list[OutgoingMessage] = []
        self.failures: list[DeliveryError] = []

    async def send(self, message: OutgoingMessage) -> None:
        if self.failures:
            raise self.failures.pop(0)
        self.sent.append(message)

    async def aclose(self) -> None:
        return


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def outbox(store: Store) -> NotificationStore:
    return NotificationStore(store.engine)


def alert_worker(outbox: NotificationStore, clock: Clock, **kw: Any) -> AlertWorker:
    values: dict[str, Any] = {
        "specs": load_rules(),
        "labels": LABELS,
        "tz": SGT,
        "cooldown": timedelta(minutes=60),
        "max_age": timedelta(minutes=60),
        # Tests about waiting for the model pass their own value.
        "analysis_wait": timedelta(0),
        "clock": clock,
    }
    values.update(kw)
    return AlertWorker(outbox, **values)


def delivery_worker(
    outbox: NotificationStore, channel: Channel | None, clock: Clock, **kw: Any
) -> DeliveryWorker:
    values: dict[str, Any] = {
        "quiet_hours": QuietHours.parse("23:00-07:00"),
        "tz": SGT,
        "clock": clock,
        "rng": lambda: 1.0,
    }
    values.update(kw)
    return DeliveryWorker(outbox, channel, **values)


async def add_finding(
    store: Store,
    *,
    rule: str = "threat-intel-allowed",
    severity: str = "critical",
    target: str = "bad.example",
    at: datetime = NOON,
    key: str | None = None,
    subject: str | None = None,
) -> int:
    await store.commit_processed(
        [],
        [
            Finding(
                rule_id=rule,
                severity=Severity(severity),
                profile_id="abc123",
                subject=subject,
                device_mode=subject is not None,
                target=target,
                ts=at,
                dedupe_key=key or f"{rule}|{target}|{at.isoformat()}",
                evidence={"fqdn": f"x.{target}", "status": "default"},
                event_id="e" * 64,
            )
        ],
    )
    found = await store.list_findings(rule_id=rule, limit=1000)
    return max(f.id for f in found if f.target == target)


async def explain(store: Store, finding_id: int, priority: Severity, at: datetime = NOON) -> None:
    analysis = Analysis(
        finding_id=finding_id,
        summary="The model's summary.",
        likely_cause="A cause.",
        recommended_action="An action.",
        priority=priority,
        group_key="g",
        confidence=0.5,
        source="llm",
        model="qwen3:8b",
    )
    await AnalysisStore(store.engine).save_analyses([analysis], now=at)


def statuses(items: Iterable[Any]) -> list[tuple[str, str, str | None]]:
    return [(item.kind, item.status, item.reason) for item in items]


# --- deciding what to alert ----------------------------------------------------------------


async def test_a_fresh_critical_finding_is_queued_once(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    finding_id = await add_finding(store)
    await explain(store, finding_id, Severity.CRITICAL)
    worker = alert_worker(outbox, clock)

    await worker.run_once()
    await worker.run_once()

    (item,) = await outbox.recent(limit=10)
    assert (item.kind, item.status, item.finding_id) == ("alert", "pending", finding_id)
    assert item.priority is Severity.CRITICAL
    assert item.title.startswith("CRITICAL: Threat-feed domain allowed, bad[.]example")
    assert "The model's summary." in item.body


async def test_an_unexplained_high_finding_waits_briefly_for_the_model(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    await add_finding(store, rule="young-domain", severity="high", target="fresh.example")
    worker = alert_worker(outbox, clock, analysis_wait=timedelta(seconds=60))

    clock.now = NOON + timedelta(seconds=30)
    await worker.run_once()
    assert await outbox.recent(limit=10) == []

    clock.now = NOON + timedelta(seconds=61)
    await worker.run_once()
    (item,) = await outbox.recent(limit=10)
    assert item.status == "pending"
    assert "not explained yet" in item.body


async def test_lower_findings_alert_only_if_the_model_raises_them(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    kept_low = await add_finding(store, rule="volume-spike", severity="low", target="abc123")
    raised = await add_finding(store, rule="dga-like", severity="medium", target="c2.example")
    await explain(store, kept_low, Severity.LOW)
    await explain(store, raised, Severity.HIGH)

    await alert_worker(outbox, clock).run_once()

    (item,) = await outbox.recent(limit=10)
    assert item.finding_id == raised
    assert item.priority is Severity.HIGH


async def test_old_findings_go_to_the_digest_not_to_an_alert(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    await add_finding(store, at=NOON - timedelta(hours=3))

    await alert_worker(outbox, clock).run_once()

    assert statuses(await outbox.recent(limit=10)) == [("alert", "skipped", "too_old")]


async def test_repeats_within_the_cooldown_are_suppressed(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    worker = alert_worker(outbox, clock)
    await add_finding(store, key="row-1")
    await worker.run_once()

    clock.now = NOON + timedelta(minutes=30)
    await add_finding(store, key="row-2", at=clock.now)
    await worker.run_once()

    clock.now = NOON + timedelta(minutes=95)
    await add_finding(store, key="row-3", at=clock.now)
    await worker.run_once()

    assert statuses(reversed(await outbox.recent(limit=10))) == [
        ("alert", "pending", None),
        ("alert", "suppressed", "cooldown"),
        ("alert", "pending", None),
    ]


async def test_cooldown_is_per_target_and_device(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    await add_finding(store, target="one.example")
    await add_finding(store, target="two.example")
    await add_finding(store, target="one.example", key="other-device", subject="D2")

    await alert_worker(outbox, clock).run_once()

    assert {item.status for item in await outbox.recent(limit=10)} == {"pending"}


# --- delivering ---------------------------------------------------------------------------


async def test_pending_alerts_are_delivered_and_marked_sent(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    await add_finding(store)
    await alert_worker(outbox, clock).run_once()
    channel = FakeChannel()

    await delivery_worker(outbox, channel, clock).run_once()

    (sent,) = channel.sent
    assert sent.priority is Severity.CRITICAL
    (item,) = await outbox.recent(limit=10)
    assert (item.status, item.sent_at) == ("sent", NOON)


async def test_without_a_channel_alerts_are_recorded_but_not_sent(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    await add_finding(store)
    await alert_worker(outbox, clock).run_once()

    await delivery_worker(outbox, None, clock).run_once()

    assert statuses(await outbox.recent(limit=10)) == [("alert", "skipped", "no_channel")]


async def test_high_alerts_wait_for_quiet_hours_to_end_but_critical_ones_do_not(
    store: Store, outbox: NotificationStore
) -> None:
    night = datetime(2026, 3, 15, 15, 30, tzinfo=UTC)  # 23:30 in Singapore
    clock = Clock(night)
    await add_finding(store, rule="young-domain", severity="high", target="h.example", at=night)
    await add_finding(store, rule="threat-intel-allowed", target="c.example", at=night)
    clock.now = night + timedelta(minutes=2)
    await alert_worker(outbox, clock).run_once()
    channel = FakeChannel()
    deliver = delivery_worker(outbox, channel, clock)

    await deliver.run_once()
    assert [m.priority for m in channel.sent] == [Severity.CRITICAL]
    held = [item for item in await outbox.recent(limit=10) if item.status == "pending"]
    assert [item.next_attempt_at for item in held] == [datetime(2026, 3, 15, 23, 0, tzinfo=UTC)]

    clock.now = datetime(2026, 3, 15, 23, 0, tzinfo=UTC)  # 07:00 in Singapore
    await deliver.run_once()
    assert [m.priority for m in channel.sent] == [Severity.CRITICAL, Severity.HIGH]


async def test_digests_are_sent_even_during_quiet_hours(
    outbox: NotificationStore,
) -> None:
    night = datetime(2026, 3, 15, 15, 30, tzinfo=UTC)
    clock = Clock(night)
    message = OutgoingMessage(title="Digest", body="b", priority=Severity.MEDIUM)
    await outbox.enqueue(kind="digest", key="digest|x", message=message, now=night)
    channel = FakeChannel()

    await delivery_worker(outbox, channel, clock).run_once()

    assert [m.title for m in channel.sent] == ["Digest"]


async def test_a_temporary_failure_is_retried_with_backoff(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    await add_finding(store)
    await alert_worker(outbox, clock).run_once()
    channel = FakeChannel()
    channel.failures.append(DeliveryError("down", retryable=True))
    deliver = delivery_worker(outbox, channel, clock)

    await deliver.run_once()
    (item,) = await outbox.recent(limit=10)
    assert (item.status, item.attempts, item.reason) == ("pending", 1, "down")
    assert item.next_attempt_at == NOON + timedelta(seconds=30)

    clock.now = NOON + timedelta(seconds=10)
    await deliver.run_once()
    assert channel.sent == [], "not due yet"

    clock.now = NOON + timedelta(seconds=30)
    await deliver.run_once()
    assert len(channel.sent) == 1
    assert (await outbox.recent(limit=10))[0].status == "sent"


async def test_retry_after_from_the_channel_is_honoured(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    await add_finding(store)
    await alert_worker(outbox, clock).run_once()
    channel = FakeChannel()
    channel.failures.append(DeliveryError("slow down", retryable=True, retry_after=120.0))

    await delivery_worker(outbox, channel, clock).run_once()

    (item,) = await outbox.recent(limit=10)
    assert item.next_attempt_at == NOON + timedelta(seconds=120)


async def test_a_permanent_failure_is_not_retried(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    await add_finding(store)
    await alert_worker(outbox, clock).run_once()
    channel = FakeChannel()
    channel.failures.append(DeliveryError("webhook gone", retryable=False))

    await delivery_worker(outbox, channel, clock).run_once()

    assert statuses(await outbox.recent(limit=10)) == [("alert", "failed", "webhook gone")]


async def test_delivery_gives_up_after_the_attempt_limit(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    await add_finding(store)
    await alert_worker(outbox, clock).run_once()
    channel = FakeChannel()
    channel.failures.extend(DeliveryError("down", retryable=True) for _ in range(3))
    deliver = delivery_worker(outbox, channel, clock, max_attempts=3)

    for _ in range(3):
        await deliver.run_once()
        clock.now += timedelta(hours=2)

    assert statuses(await outbox.recent(limit=10)) == [("alert", "failed", "down")]


async def test_pending_alerts_survive_a_restart(
    store: Store, outbox: NotificationStore, clock: Clock
) -> None:
    await add_finding(store)
    await alert_worker(outbox, clock).run_once()

    reopened = NotificationStore(store.engine)
    channel = FakeChannel()
    await delivery_worker(reopened, channel, clock).run_once()

    assert len(channel.sent) == 1
