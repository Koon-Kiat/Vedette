"""The rule worker stops on an unexpected error instead of carrying on with stale state."""

import asyncio
from datetime import timedelta

import pytest

from tests.unit.rule_helpers import T0, enriched, event
from vedette.enrich.model import EnrichedEvent
from vedette.pipeline.processor import Batch, RuleWorker
from vedette.pipeline.queue import MemoryQueue
from vedette.rules.allowlist import Allowlist
from vedette.rules.engine import RuleEngine
from vedette.rules.loader import load_rules
from vedette.shared.models import Finding
from vedette.storage.store import Store


async def test_an_unexpected_error_in_the_rule_worker_ends_it(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = RuleEngine(load_rules(), allowlist=Allowlist([]), learning=timedelta(0))

    def broken(item: EnrichedEvent) -> list[Finding]:
        raise RuntimeError("engine state no longer matches storage")

    monkeypatch.setattr(engine, "evaluate", broken)
    queue: MemoryQueue[Batch] = MemoryQueue()
    worker = RuleWorker(["abc123"], store, engine, queue, warm_up=timedelta(0), clock=lambda: T0)
    await queue.publish([enriched(event(n=1))])

    with pytest.raises(RuntimeError, match="no longer matches"):
        await asyncio.wait_for(worker.run(), timeout=5)
    assert await store.list_findings() == []
