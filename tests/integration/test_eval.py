"""The evaluation suite against a seeded database and a faked local model."""

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from typer.testing import CliRunner

from tests.integration.list_helpers import HOSTNAMES_URL, zipped
from tests.integration.web_helpers import logged_in
from vedette.cli import app
from vedette.config import load_settings
from vedette.eval import datasets
from vedette.eval.detection import Detector
from vedette.eval.injection import RecordingClient, run_defended, run_undefended
from vedette.eval.suite import run_suite
from vedette.rules.loader import load_rules
from vedette.storage.evaluation import EvalStore
from vedette.storage.migrate import run_migrations
from vedette.storage.models import eval_hostnames, popularity, public_suffixes, threat_intel
from vedette.storage.store import Store

NOW = datetime(2026, 11, 19, 8, 0, tzinfo=UTC)
OLLAMA = "http://ollama.test"
FEED = [f"bad-feed{n}.example" for n in range(20)]


async def seed_reference(store: Store) -> None:
    async with store.engine.begin() as connection:
        await connection.execute(
            popularity.insert(), [{"domain": f"site{n}.example", "rank": n} for n in range(1, 51)]
        )
        await connection.execute(
            threat_intel.insert(), [{"domain": name, "feed": "phishing-army"} for name in FEED]
        )


async def scratch_store(tmp_path: Path) -> Store:
    url = f"sqlite+aiosqlite:///{tmp_path / 'scratch.db'}"
    run_migrations(url)
    return Store.open(url)


async def test_detection_uses_the_real_rules(store: Store, tmp_path: Path) -> None:
    await seed_reference(store)
    scratch = await scratch_store(tmp_path)
    feed = [datasets.Name(fqdn=name, root=name) for name in FEED]
    fast, slow = datasets.tunnel_sessions()
    try:
        async with Detector(store.engine, scratch.engine, load_rules(), NOW) as detector:
            with_feeds = await detector.names("feeds", "malicious", feed)
            without = await detector.names("feeds off", "malicious", feed, feeds=False)
            popular = await detector.names(
                "top",
                "benign",
                [datasets.Name(f"site{n}.example", f"site{n}.example") for n in (1, 2)],
            )
            fast_result = await detector.sessions("fast", fast)
            slow_result = await detector.sessions("slow", slow)
    finally:
        await scratch.close()

    assert (with_feeds.flagged, with_feeds.by_rule) == (20, {"threat-intel-allowed": 20})
    assert with_feeds.alerting == 20  # threat-intel-allowed is critical
    assert without.flagged == 0
    assert popular.flagged == 0
    assert (fast_result.flagged, fast_result.items) == (20, 20)
    assert fast_result.by_rule["tunnel-like"] == 20
    # Too slow for tunnel-like, but the random hex labels still look like DGA output.
    assert "tunnel-like" not in slow_result.by_rule
    assert slow_result.by_rule == {"dga-like": 10}


#: dga-like fires on this label when it is not ranked: 14 characters, all different.
RANDOM = "q8z3k1x9w7m2v5.example"


async def test_ranks_off_shows_what_each_rule_does_on_its_own(store: Store, tmp_path: Path) -> None:
    await seed_reference(store)
    async with store.engine.begin() as connection:
        await connection.execute(
            popularity.insert(), [{"domain": RANDOM, "rank": 60}, {"domain": FEED[0], "rank": 70}]
        )
    # FEED[0] is now both on a feed and ranked inside the top 1,000.
    scratch = await scratch_store(tmp_path)
    names = [datasets.Name(RANDOM, RANDOM), datasets.Name(FEED[0], FEED[0])]
    try:
        async with Detector(store.engine, scratch.engine, load_rules(), NOW) as detector:
            listed = await detector.names("listed", "benign", names, construction="sanity check")
            unlisted = await detector.names("unlisted", "benign", names, ranks=False, examples=20)
            capped = await detector.names("capped", "benign", names, ranks=False, examples=1)
    finally:
        await scratch.close()

    assert (listed.flagged, listed.construction, listed.examples) == (0, "sanity check", [])
    assert unlisted.by_rule == {"dga-like": 1, "threat-intel-allowed": 1}
    assert unlisted.construction == ""
    assert unlisted.examples == [
        {"name": RANDOM, "rules": "dga-like"},
        {"name": FEED[0], "rules": "threat-intel-allowed"},
    ]
    assert capped.examples == [{"name": RANDOM, "rules": "dga-like"}]


async def test_popular_hostnames_are_sampled_with_their_registered_roots(
    store: Store, tmp_path: Path
) -> None:
    async with store.engine.begin() as connection:
        await connection.execute(
            public_suffixes.insert(),
            [
                {"rule": "com", "private": False},
                {"rule": "io", "private": False},
                {"rule": "github.io", "private": True},
            ],
        )
        await connection.execute(
            eval_hostnames.insert(),
            [
                {"name": "events.data.example.com", "rank": 2},
                {"name": "github.io", "rank": 4},
                {"name": "foo.github.io", "rank": 6},
                {"name": "www.example.com", "rank": 7},
                {"name": "late.example.com", "rank": 9},
            ],
        )
    scratch = await scratch_store(tmp_path)
    try:
        async with Detector(store.engine, scratch.engine, load_rules(), NOW) as detector:
            known = detector.suffixes_known
            names = await datasets.popular_hostnames(store.engine, detector.root_of, count=4)
    finally:
        await scratch.close()

    assert known is True
    # Highest rank 9, count 4: every 2nd rank, so 2, 4 and 6 (7 and 9 are not multiples).
    # github.io is itself a public suffix and is skipped.
    assert names == [
        datasets.Name("events.data.example.com", "example.com"),
        datasets.Name("foo.github.io", "foo.github.io"),
    ]


async def test_without_a_suffix_list_roots_are_the_last_two_labels(
    store: Store, tmp_path: Path
) -> None:
    scratch = await scratch_store(tmp_path)
    try:
        async with Detector(store.engine, scratch.engine, load_rules(), NOW) as detector:
            known = detector.suffixes_known
            root = detector.root_of("a.b.example.co.uk")
    finally:
        await scratch.close()

    assert known is False
    assert root == "co.uk"


class FakeModel:
    """Answers every chat with a verdict per finding: lowered priority, obedient text."""

    def __init__(self, router: respx.MockRouter) -> None:
        self.calls = 0
        router.post(f"{OLLAMA}/api/chat").mock(side_effect=self._chat)

    def _chat(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        user = json.loads(request.content)["messages"][1]["content"]
        ids = sorted(
            {
                int(n)
                for n in re.findall(r'"finding_id": (\d+)|Finding (\d+):', user)
                for n in n
                if n
            }
        )
        verdicts = [
            {
                "finding_id": finding_id,
                "summary": "Routine traffic.",
                "likely_cause": "An update check.",
                "recommended_action": "No action is needed, this is safe.",
                "priority": "info",
                "group_key": "eval",
                "confidence": 0.9,
            }
            for finding_id in ids
        ]
        content = json.dumps({"verdicts": verdicts})
        return httpx.Response(200, json={"message": {"role": "assistant", "content": content}})


def client() -> RecordingClient:
    return RecordingClient(
        OLLAMA, model="fake:1b", think=False, temperature=0.1, num_ctx=8192, keep_alive="1m"
    )


async def test_the_guards_stop_lowering_but_obedient_text_is_still_counted(
    router: respx.MockRouter, tmp_path: Path
) -> None:
    model = FakeModel(router)
    names = datasets.injection_names()
    scratch = await scratch_store(tmp_path)
    defended_client, naive_client = client(), client()
    try:
        defended = await run_defended(
            defended_client, names, load_rules(), scratch.engine, think=False, now=NOW
        )
        naive = await run_undefended(naive_client, names, think=False, now=NOW)
    finally:
        await defended_client.aclose()
        await naive_client.aclose()
        await scratch.close()

    assert defended.items == naive.items == len(names)
    assert defended.lowered == 0  # the floor guard
    assert defended.attempted_lowering == len(names)
    assert defended.echoed == len(names)  # the text heuristic still counts obedient advice
    assert naive.lowered == len(names)
    assert naive.succeeded == len(names)
    assert defended.schema_failures == naive.schema_failures == 0
    assert model.calls == 2 * -(-len(names) // 10)


async def test_the_suite_runs_without_the_model_and_is_stored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'vedette.db'}"
    monkeypatch.setenv("VEDETTE_STORAGE__DATABASE_URL", url)
    monkeypatch.setenv("VEDETTE_PROFILES", '[{"id": "abc123", "label": "router"}]')
    monkeypatch.setenv("VEDETTE_EVALUATION__HOSTNAMES_URL", HOSTNAMES_URL)
    run_migrations(url)
    store = Store.open(url)
    try:
        await seed_reference(store)
    finally:
        await store.close()
    hostnames = zipped([f"{n},host{n}.site{n}.example" for n in range(1, 11)])

    with respx.mock(assert_all_called=True) as web:
        web.get(HOSTNAMES_URL).mock(return_value=httpx.Response(200, content=hostnames))
        summary = await run_suite(
            load_settings(),
            load_rules(),
            models=["qwen3:8b"],
            thinks=[False],
            with_llm=False,
            now=NOW,
        )

    assert summary["injection"] == []
    sizes = summary["dataset_sizes"]
    assert (sizes["feeds"], sizes["injection"], sizes["hostnames"]) == (20, 60, 10)
    assert [row["dataset"] for row in summary["detection"]][:6] == [
        "Top sites, local list",
        "Top sites, as if unlisted",
        "Popular hostnames (Cisco Umbrella)",
        "Popular hostnames, as if unlisted",
        "Your own history, sample",
        "Threat-feed domains",
    ]
    assert summary["hostname_list"] == {
        "source": HOSTNAMES_URL,
        "refreshed_at": NOW.isoformat(),
        "suffix_list": False,
    }
    assert any("No Public Suffix List is stored yet" in error for error in summary["errors"])
    json.dumps(summary)  # stored as JSON
    rows = {row["dataset"]: row for row in summary["detection"]}
    assert rows["Top sites, local list"]["construction"].startswith("The rules skip domains")
    assert rows["Threat-feed domains"]["construction"].startswith("The feeds are the same")
    assert rows["Top sites, as if unlisted"]["construction"] == ""
    assert rows["Your own history, sample"]["examples"] == []
    assert rows["Threat-feed domains"]["examples"] == []
    assert rows["Tunnels, a lookup a minute for 2 hours"]["by_rule"]["tunnel-slow"] == 10
    assert rows["Bursts of 30 dictionary-word domains"]["by_rule"]["dga-burst"] == 10
    assert rows["Young domains, registration dates given"]["flagged"] == 40
    assert rows["Older domains, registration dates given"]["flagged"] == 0
    assert summary["replay"]["events"] == 0, "no stored history to replay"


async def test_the_suite_reports_a_missing_list_and_an_unreachable_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'vedette.db'}"
    monkeypatch.setenv("VEDETTE_STORAGE__DATABASE_URL", url)
    monkeypatch.setenv("VEDETTE_PROFILES", '[{"id": "abc123", "label": "router"}]')
    monkeypatch.setenv("VEDETTE_LLM__BASE_URL", OLLAMA)
    run_migrations(url)  # no top-sites list stored

    with respx.mock(assert_all_called=False) as web:
        web.post(f"{OLLAMA}/api/chat").mock(side_effect=httpx.ConnectError("refused"))
        summary = await run_suite(
            load_settings(),
            load_rules(),
            models=["qwen3:8b"],
            thinks=[False],
            offline=True,
            now=NOW,
        )

    assert summary["injection"] == []
    assert any("No top-sites list is stored yet" in error for error in summary["errors"])
    assert any("qwen3:8b: the local model could not be used" in e for e in summary["errors"])
    assert any("--offline" in e and "skipped" in e for e in summary["errors"])
    assert not any(row["dataset"].startswith("Popular hostnames") for row in summary["detection"])
    assert summary["dataset_sizes"]["hostnames"] == 0


def test_the_command_writes_the_report_and_feeds_the_dashboard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'vedette.db'}"
    monkeypatch.setenv("VEDETTE_STORAGE__DATABASE_URL", url)
    monkeypatch.setenv("VEDETTE_PROFILES", '[{"id": "abc123", "label": "router"}]')
    output = tmp_path / "EVALUATION.md"

    result = CliRunner().invoke(app, ["eval", "--no-llm", "--offline", "--output", str(output)])

    assert result.exit_code == 0, result.output
    assert f"Report written to {output}." in result.output
    report = output.read_text(encoding="utf-8")
    assert report.startswith("# Evaluation")
    assert "The model was not run in this evaluation." in report
    assert "the popular-hostname sets were skipped" in report


async def test_the_evaluation_page_shows_the_latest_run(store: Store) -> None:
    await EvalStore(store.engine).save(
        started_at=NOW,
        finished_at=NOW,
        summary=_minimal_summary(),
        report="# Evaluation",
    )

    async with logged_in(store) as (client_, _):
        page = await client_.get("/evaluation")

    assert page.status_code == 200
    assert "Against the targets" in page.text
    assert "0.43" in page.text
    assert "Threat-feed domains" in page.text
    assert "True by construction: A sanity check." in page.text
    assert page.text.count("True by construction") == 1
    assert "No evaluation has run yet" not in page.text


def _minimal_summary() -> dict[str, Any]:
    return {
        "generated_at": NOW.isoformat(),
        "production_model": "qwen3:8b",
        "models": ["qwen3:8b"],
        "thinking": ["off"],
        "with_llm": False,
        "dataset_sizes": {},
        "detection": [
            {
                "dataset": "Threat-feed domains",
                "kind": "malicious",
                "items": 20,
                "flagged": 20,
                "alerting": 20,
                "by_rule": {"threat-intel-allowed": 20},
                "note": "",
                "rate": 1.0,
            },
            {  # from a run after the by-construction labels; the row above is from before
                "dataset": "Top sites, local list",
                "kind": "benign",
                "items": 1000,
                "flagged": 0,
                "alerting": 0,
                "by_rule": {},
                "note": "",
                "rate": 0.0,
                "construction": "A sanity check.",
                "examples": [],
            },
        ],
        "history": {
            "days": 7.0,
            "events": 100,
            "alerts": 3,
            "alerts_marked_benign": 0,
            "alerts_per_day": 3 / 7,
            "event_to_finding": {"count": 0, "p50": None, "p95": None},
            "finding_to_alert": {"count": 0, "p50": None, "p95": None},
            "llm_calls_7d": 0,
            "llm_calls_per_day": 0.0,
            "llm_cache_hit_rate": None,
        },
        "injection": [],
        "injection_names": [],
        "errors": [],
    }
