"""The digest fixture plus what the dashboard pages also show."""

from datetime import timedelta

from tests.digest_fixture import PERIOD_END, PERIOD_START, PROFILES, TZ, _event, build_fixture
from vedette.llm.schema import Analysis
from vedette.notify.channels import OutgoingMessage
from vedette.notify.digest import DigestBuilder, render_digest
from vedette.rules.model import Severity
from vedette.storage.analysis import AnalysisStore
from vedette.storage.notifications import NotificationStore
from vedette.storage.reference import DomainAgeRecord, FirstSeenRow, ReferenceStore
from vedette.storage.store import Store


async def build_web_fixture(store: Store) -> None:
    """Fill a migrated, empty database with everything the dashboard tests use."""
    await build_fixture(store)
    await store.save_events(
        [
            *(
                _event("abc123", PERIOD_START + timedelta(hours=2, minutes=n), "pay.bad.example")
                for n in range(3)
            ),
            _event(
                "def456",
                PERIOD_START + timedelta(hours=5),
                "login.fresh-site.example",
                device=("D1", "Laptop"),
            ),
        ]
    )
    reference = ReferenceStore(store.engine)
    await reference.replace_popularity(
        [("site0.example", 50), ("site1.example", 1200), ("ads.example", 900)], PERIOD_START
    )
    await reference.save_domain_ages(
        [
            DomainAgeRecord(
                "fresh-site.example", "found", PERIOD_END - timedelta(days=5), PERIOD_START
            ),
            DomainAgeRecord(
                "site3.example", "found", PERIOD_END - timedelta(days=4000), PERIOD_START
            ),
        ]
    )
    await reference.save_first_seen(
        [
            FirstSeenRow("def456", "device", "", "D1", PERIOD_START - timedelta(days=7), "e1"),
            FirstSeenRow("def456", "device", "", "D2", PERIOD_START + timedelta(hours=20), "e2"),
            FirstSeenRow(
                "def456", "root", "", "recipes.example", PERIOD_START + timedelta(hours=20), "e3"
            ),
            FirstSeenRow(
                "abc123", "root", "", "site0.example", PERIOD_START - timedelta(days=7), "e4"
            ),
        ]
    )
    analyses = AnalysisStore(store.engine)
    for n, duration in enumerate((1000, 2000, 3000, 4000, 5000)):
        await analyses.record_call(
            started_at=PERIOD_START + timedelta(hours=n),
            duration_ms=duration,
            findings=1,
            outcome="ok",
            model="qwen3:8b",
        )
    dga = next(f for f in await store.list_findings(limit=100) if f.rule_id == "dga-like")
    await analyses.save_analyses(
        [
            Analysis(
                finding_id=dga.id,
                summary="A random-looking name, reused from an earlier finding.",
                likely_cause="Possibly malware.",
                recommended_action="Check the laptop.",
                priority=Severity.MEDIUM,
                group_key="dga",
                confidence=0.4,
                source="cache",
                model="qwen3:8b",
            )
        ],
        now=PERIOD_END,
    )
    builder = DigestBuilder(store.engine, profiles=PROFILES, tz=TZ)
    title, body = render_digest(await builder.build(PERIOD_END))
    await NotificationStore(store.engine).record_digest(
        period_start=PERIOD_START,
        period_end=PERIOD_END,
        now=PERIOD_END,
        message=OutgoingMessage(title=title, body=body, priority=Severity.MEDIUM),
        data={},
    )
