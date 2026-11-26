import asyncio
import contextlib
import socket
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping, Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

from tests.integration.fake_nextdns import API_KEY, T0, FakeNextDns
from tests.unit.test_reference_parsing import tranco_zip
from vedette.config import load_settings
from vedette.health.state import HealthState
from vedette.pipeline.collector import ProfileCollector
from vedette.pipeline.runner import Pipeline
from vedette.sources.nextdns import NextDnsSource
from vedette.storage.migrate import run_migrations
from vedette.storage.store import Store


class SleepRecorder:
    """Stands in for asyncio.sleep: records requested delays and returns quickly."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)
        await asyncio.sleep(0.001)


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as mock_router:
        # The health monitor asks Ollama which models it has; answer for any host.
        mock_router.get(path="/api/tags").mock(
            return_value=httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]})
        )
        # The Public Suffix List's default address: unavailable, so the enricher
        # uses its fallback unless a test serves a list itself.
        mock_router.get("https://publicsuffix.org/list/public_suffix_list.dat").mock(
            return_value=httpx.Response(404)
        )
        yield mock_router


@pytest.fixture
def server(router: respx.MockRouter) -> FakeNextDns:
    fake = FakeNextDns()
    fake.mount(router)
    return fake


@pytest.fixture
def sleeps() -> SleepRecorder:
    return SleepRecorder()


@pytest.fixture
async def source(server: FakeNextDns, sleeps: SleepRecorder) -> AsyncIterator[NextDnsSource]:
    created = NextDnsSource(API_KEY, page_size=10, sleep=sleeps, rng=lambda: 1.0)
    yield created
    await created.aclose()


@pytest.fixture
def database_url(tmp_path: Path) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'vedette.db'}"
    run_migrations(url)
    return url


@pytest.fixture
async def store(database_url: str) -> AsyncIterator[Store]:
    opened = Store.open(database_url)
    yield opened
    await opened.close()


async def wait_until(condition: Callable[[], Awaitable[bool]], timeout: float = 5.0) -> None:  # noqa: ASYNC109
    """Poll ``condition`` until it is true, failing the test after ``timeout`` seconds."""
    async with asyncio.timeout(timeout):
        while not await condition():  # noqa: ASYNC110 - polling external state
            await asyncio.sleep(0.005)


NOW = T0 + timedelta(hours=1)


def make_collector(
    source: NextDnsSource, store: Store, sleeps: SleepRecorder, *, health: HealthState | None = None
) -> ProfileCollector:
    """A collector for profile ``abc123`` at ``NOW``, sleeping through ``sleeps``."""
    return ProfileCollector(
        "abc123",
        source,
        store,
        backfill_days=7,
        clock=lambda: NOW,
        sleep=sleeps,
        rng=lambda: 1.0,
        health=health,
    )


# --- a whole pipeline run against the fake NextDNS server --------------------------

TOP_SITES_URL = "https://lists.test/top.zip"
FEED_URL = "https://feeds.test/p.txt"
STARTED = {"rule_engine_warmed_up", "collector_backfill_completed"}


def free_port() -> int:
    """A port on the loopback interface that nothing listens on."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def pipeline_env(
    monkeypatch: pytest.MonkeyPatch,
    router: respx.MockRouter,
    database_url: str,
    *,
    findings: bool = False,
    extra: Mapping[str, str] | None = None,
) -> int:
    """Settings for a pipeline run against the fake server; returns the /healthz port.

    No registry lookups are made. Without ``findings`` the top-sites list is
    unavailable and no feed is set. With it, the run reads the fake server's whole
    history, ``site1.example`` is ranked and ``site3.example`` is on a feed, and
    the rules need no learning period, so findings come at once.
    """
    port = free_port()
    env = {
        "NEXTDNS_API_KEY": API_KEY,
        "VEDETTE_STORAGE__DATABASE_URL": database_url,
        "VEDETTE_PROFILES": '[{"id": "abc123", "label": "router"}]',
        "VEDETTE_ENRICH__POPULARITY__URL": TOP_SITES_URL,
        "VEDETTE_ENRICH__RDAP__ENABLED": "false",
        "VEDETTE_ENRICH__THREAT_INTEL__FEEDS": "[]",
        "VEDETTE_HEALTH__HEALTHZ_PORT": str(port),
    }
    if findings:
        env |= {
            "VEDETTE_INGEST__PAGE_SIZE": "10",
            "VEDETTE_INGEST__BACKFILL_DAYS": "36500",
            "VEDETTE_ENRICH__THREAT_INTEL__FEEDS": f'[{{"name": "phish", "url": "{FEED_URL}"}}]',
            "VEDETTE_RULES__LEARNING_DAYS": "0",
        }
        router.get(TOP_SITES_URL).mock(
            return_value=httpx.Response(200, content=tranco_zip("1,site1.example\r\n"))
        )
        router.get(FEED_URL).mock(return_value=httpx.Response(200, text="site3.example\n"))
    else:
        router.get(TOP_SITES_URL).respond(404)
    for name, value in {**env, **(extra or {})}.items():
        monkeypatch.setenv(name, value)
    return port


@contextlib.asynccontextmanager
async def running_pipeline(stop_timeout: float = 10.0) -> AsyncIterator[asyncio.Task[None]]:
    """Run the pipeline from the environment's settings, and stop it on the way out."""
    stop = asyncio.Event()
    task = asyncio.create_task(Pipeline(load_settings()).run(stop))
    try:
        yield task
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=stop_timeout)


async def started(logs: Sequence[Mapping[str, Any]]) -> None:
    """Wait until start-up has finished, so stopping does not interrupt it."""

    async def done() -> bool:
        return {str(entry["event"]) for entry in logs} >= STARTED

    await wait_until(done, timeout=10)


async def read_when_migrated[T](
    database_url: str, read: Callable[[Store], Awaitable[T]]
) -> T | None:
    """``read`` on the pipeline's database, or ``None`` until the pipeline has made its tables."""
    database = Path(make_url(database_url).database or "")
    if not await asyncio.to_thread(database.exists):
        return None
    reader = Store.open(database_url)
    try:
        return await read(reader)
    except OperationalError:
        return None
    finally:
        await reader.close()
