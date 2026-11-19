"""Shared helpers for dashboard tests: an app over a test database, and logging in."""

import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from sentinel.config import ProfileConfig
from sentinel.rules.loader import load_rules
from sentinel.storage.store import Store
from sentinel.web.app import DashboardContext, create_app
from tests.digest_fixture import PROFILES, TZ

TOKEN = "test-dashboard-token-0123456789abcdef"  # noqa: S105 - fake value for tests
BASE = "http://127.0.0.1"
NOW = datetime(2026, 3, 15, 0, 30, tzinfo=UTC)  # 08:30 in Singapore, just after the fixture


class Clock:
    def __init__(self, now: datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


def make_client(
    store: Store,
    *,
    clock: Callable[[], datetime] | None = None,
    profiles: list[ProfileConfig] | None = None,
    **live: Any,
) -> httpx.AsyncClient:
    context = DashboardContext(
        engine=store.engine,
        profiles=profiles or PROFILES,
        tz=TZ,
        token=TOKEN,
        specs=load_rules(),
        session_lifetime=timedelta(hours=12),
        allowed_hosts=["127.0.0.1", "localhost"],
        clock=clock or Clock(),
        **live,
    )
    app = create_app(context)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE)


def hidden(html: str, name: str) -> str:
    match = re.search(rf'name="{name}" value="([^"]*)"', html)
    assert match, f"no hidden field {name!r}"
    return match.group(1)


async def login(client: httpx.AsyncClient, token: str = TOKEN) -> httpx.Response:
    page = await client.get("/login")
    nonce = hidden(page.text, "login_nonce")
    return await client.post("/login", data={"token": token, "login_nonce": nonce})


async def logged_in_csrf(client: httpx.AsyncClient) -> str:
    response = await login(client)
    assert response.status_code == 303, response.text
    home = await client.get("/")
    return hidden(home.text, "csrf_token")


@asynccontextmanager
async def logged_in(store: Store, **kw: object) -> AsyncIterator[tuple[httpx.AsyncClient, str]]:
    """A client with a live session, and that session's CSRF token."""
    async with make_client(store, **kw) as client:  # type: ignore[arg-type]
        yield client, await logged_in_csrf(client)
