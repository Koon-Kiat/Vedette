"""Marking a finding benign stops the running rule engine flagging that domain."""

import asyncio
import contextlib
from datetime import timedelta

from sentinel.enrich.model import EnrichedEvent
from sentinel.pipeline.processor import Batch, RuleWorker
from sentinel.pipeline.queue import MemoryQueue
from sentinel.rules.allowlist import Allowlist, AllowlistEntry
from sentinel.rules.engine import RuleEngine
from sentinel.rules.loader import load_rules
from sentinel.storage.store import Store
from sentinel.storage.triage import TriageStore
from tests.integration.conftest import wait_until
from tests.unit.rule_helpers import T0, enriched, event


def young(n: int) -> EnrichedEvent:
    return enriched(
        event(fqdn=f"a{n}.fresh-site.example", root="fresh-site.example", n=n),
        popularity_rank=None,
        domain_age_days=5,
    )


def test_an_allowlist_can_be_replaced_in_place() -> None:
    allowlist = Allowlist([], labels={"abc123": "router"})
    assert not allowlist.allows("abc123", None, "x.site.example", "site.example")

    allowlist.replace([AllowlistEntry(root="site.example", profile="abc123")])

    assert allowlist.allows("abc123", None, "x.site.example", "site.example")


async def test_the_rule_worker_reloads_the_stored_allowlist(store: Store) -> None:
    allowlist = Allowlist([], labels={"abc123": "router"})
    engine = RuleEngine(load_rules(), allowlist=allowlist, learning=timedelta(0))
    queue: MemoryQueue[Batch] = MemoryQueue()
    triage = TriageStore(store.engine)
    configured = [AllowlistEntry(root="config.example")]

    async def refresh() -> None:
        allowlist.replace([*configured, *await triage.allowlist_entries()])

    worker = RuleWorker(
        ["abc123"],
        store,
        engine,
        queue,
        warm_up=timedelta(0),
        clock=lambda: T0,
        allowlist_refresh=refresh,
        refresh_seconds=0,
    )
    task = asyncio.create_task(worker.run())
    try:
        await queue.publish([young(1)])

        async def first_found() -> bool:
            return len(await store.list_findings(rule_id="young-domain")) == 1

        await wait_until(first_found)
        (finding,) = await store.list_findings(rule_id="young-domain")
        await triage.mark_benign(finding.id, actor="dashboard", now=T0)

        await queue.publish([young(2)])

        async def drained() -> bool:
            return await queue.depth() == 0

        await wait_until(drained)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    (only,) = await store.list_findings(rule_id="young-domain")
    assert only.event_count == 1, "the second query was not flagged"
    assert allowlist.allows("abc123", None, "x.config.example", "config.example")
