import asyncio

import pytest
from structlog.testing import capture_logs

from vedette.config import load_settings
from vedette.pipeline.runner import STAGE_NAMES, Pipeline


def test_the_pipeline_has_the_stages_from_the_architecture() -> None:
    assert STAGE_NAMES == (
        "collector",
        "enricher",
        "rule_engine",
        "llm_analyst",
        "notifier",
        "health_monitor",
    )


async def test_pipeline_starts_every_stage_and_stops_cleanly_when_asked() -> None:
    stop = asyncio.Event()
    pipeline = Pipeline(load_settings())

    with capture_logs() as logs:
        task = asyncio.create_task(pipeline.run(stop))
        await asyncio.sleep(0.05)
        assert not task.done()
        stop.set()
        await asyncio.wait_for(task, timeout=2)

    started = [entry["stage"] for entry in logs if entry["event"] == "stage_started"]
    stopped = [entry["stage"] for entry in logs if entry["event"] == "stage_stopped"]
    assert sorted(started) == sorted(STAGE_NAMES)
    assert sorted(stopped) == sorted(STAGE_NAMES)
    assert logs[0]["event"] == "pipeline_started"
    assert logs[-1]["event"] == "pipeline_stopped"


async def test_pipeline_start_log_lists_enabled_profiles_by_label_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stop = asyncio.Event()
    stop.set()
    monkeypatch.setenv(
        "VEDETTE_PROFILES",
        '[{"id": "abc123", "label": "router", "enabled": true},'
        ' {"id": "def456", "label": "pc", "enabled": false}]',
    )

    with capture_logs() as logs:
        await Pipeline(load_settings()).run(stop)

    assert logs[0]["event"] == "pipeline_started"
    assert logs[0]["enabled_profiles"] == ["router"]


async def test_collector_idles_with_a_clear_reason_when_no_api_key_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stop = asyncio.Event()
    stop.set()
    monkeypatch.setenv("VEDETTE_PROFILES", '[{"id": "abc123", "label": "router"}]')

    with capture_logs() as logs:
        await Pipeline(load_settings()).run(stop)

    idle = [entry for entry in logs if entry["event"] == "collector_idle"]
    assert [entry["reason"] for entry in idle] == ["NEXTDNS_API_KEY is not set"]


async def test_collector_idles_with_a_clear_reason_when_no_profile_is_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stop = asyncio.Event()
    stop.set()
    monkeypatch.setenv("NEXTDNS_API_KEY", "not-a-real-key")

    with capture_logs() as logs:
        await Pipeline(load_settings()).run(stop)

    idle = [entry for entry in logs if entry["event"] == "collector_idle"]
    assert [entry["reason"] for entry in idle] == ["no profile is enabled"]
