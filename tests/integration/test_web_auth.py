"""Dashboard access control and browser-side protections."""

import pytest

from sentinel.storage.store import Store
from tests.digest_fixture import build_fixture
from tests.integration.web_helpers import TOKEN, Clock, hidden, logged_in_csrf, login, make_client

WRONG = "not-the-token"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "object-src 'none'"
)


@pytest.fixture
async def filled(store: Store) -> Store:
    await build_fixture(store)
    return store


async def test_pages_need_a_session(filled: Store) -> None:
    async with make_client(filled) as client:
        page = await client.get("/")
        partial = await client.get("/findings", headers={"HX-Request": "true"})

    assert (page.status_code, page.headers["location"]) == (303, "/login")
    assert (partial.status_code, partial.headers["HX-Redirect"]) == (401, "/login")


async def test_the_login_page_sets_a_one_time_nonce(filled: Store) -> None:
    async with make_client(filled) as client:
        page = await client.get("/login")

    assert page.status_code == 200
    assert hidden(page.text, "login_nonce")
    cookie = page.headers["set-cookie"]
    assert "sentinel_login=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie or "SameSite=Strict" in cookie


async def test_a_wrong_token_is_refused(filled: Store) -> None:
    async with make_client(filled) as client:
        response = await login(client, token=WRONG)
        after = await client.get("/")

    assert response.status_code == 401
    assert "sentinel_session" not in response.headers.get("set-cookie", "")
    assert "not right" in response.text
    assert after.status_code == 303


async def test_login_without_the_nonce_is_refused(filled: Store) -> None:
    async with make_client(filled) as client:
        response = await client.post("/login", data={"token": TOKEN})

    assert response.status_code == 400


async def test_the_right_token_starts_a_session_with_a_safe_cookie(filled: Store) -> None:
    async with make_client(filled) as client:
        response = await login(client)
        home = await client.get("/")

    assert (response.status_code, response.headers["location"]) == (303, "/")
    cookies = response.headers.get_list("set-cookie")
    session = next(c for c in cookies if c.startswith("sentinel_session="))
    assert "HttpOnly" in session
    assert "samesite=strict" in session.lower()
    assert "Path=/" in session
    assert TOKEN not in session
    assert home.status_code == 200


async def test_repeated_failures_are_slowed_down(filled: Store) -> None:
    clock = Clock()
    async with make_client(filled, clock=clock) as client:
        for _ in range(5):
            assert (await login(client, token=WRONG)).status_code == 401
        blocked = await login(client)
        clock.advance(seconds=61)
        allowed = await login(client)

    assert blocked.status_code == 429
    assert allowed.status_code == 303


async def test_sessions_expire(filled: Store) -> None:
    clock = Clock()
    async with make_client(filled, clock=clock) as client:
        await login(client)
        assert (await client.get("/")).status_code == 200
        clock.advance(hours=12, seconds=1)
        expired = await client.get("/")

    assert (expired.status_code, expired.headers["location"]) == (303, "/login")


async def test_logging_out_needs_the_csrf_token_and_ends_the_session(filled: Store) -> None:
    async with make_client(filled) as client:
        csrf = await logged_in_csrf(client)
        refused = await client.post("/logout", data={})
        done = await client.post("/logout", data={"csrf_token": csrf})
        after = await client.get("/")

    assert refused.status_code == 403
    assert (done.status_code, done.headers["location"]) == (303, "/login")
    assert after.status_code == 303


@pytest.mark.parametrize("token", [None, "wrong-token"])
async def test_actions_need_the_csrf_token(filled: Store, token: str | None) -> None:
    async with make_client(filled) as client:
        await logged_in_csrf(client)
        data = {} if token is None else {"csrf_token": token}
        response = await client.post("/findings/1/acknowledge", data=data)

    assert response.status_code == 403


async def test_the_csrf_token_may_come_as_a_header(filled: Store) -> None:
    async with make_client(filled) as client:
        csrf = await logged_in_csrf(client)
        response = await client.post(
            "/findings/1/acknowledge", headers={"X-CSRF-Token": csrf, "HX-Request": "true"}
        )

    assert response.status_code == 200


@pytest.mark.parametrize("path", ["/login", "/", "/static/style.css", "/no-such-page"])
async def test_every_response_carries_the_security_headers(filled: Store, path: str) -> None:
    async with make_client(filled) as client:
        if path != "/login":
            await login(client)
        response = await client.get(path)

    assert response.headers["content-security-policy"] == CSP
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    # Static files are revalidated on every load, so an upgrade never meets stale CSS.
    expected = "no-cache" if path.startswith("/static/") else "no-store"
    assert response.headers["cache-control"] == expected


async def test_an_unexpected_host_name_is_refused(filled: Store) -> None:
    async with make_client(filled) as client:
        response = await client.get("/login", headers={"Host": "evil.example"})

    assert response.status_code == 400


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_framework_api_pages_are_switched_off(filled: Store, path: str) -> None:
    async with make_client(filled) as client:
        await login(client)
        response = await client.get(path)

    assert response.status_code == 404
