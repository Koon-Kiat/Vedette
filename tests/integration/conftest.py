import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path

import httpx
import pytest
import respx

from tests.integration.fake_nextdns import API_KEY, FakeNextDns
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
