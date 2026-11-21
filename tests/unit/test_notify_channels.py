"""Delivery channels: ntfy, Discord webhook and e-mail, with every network call faked."""

import json
import smtplib
import ssl
from collections.abc import AsyncIterator, Iterator
from email.message import EmailMessage
from typing import Any, ClassVar

import httpx
import pytest
import respx

from vedette.notify.channels import (
    DISCORD_MAX_CHUNKS,
    NTFY_MAX_BYTES,
    DeliveryError,
    DiscordChannel,
    EmailChannel,
    NtfyChannel,
    OutgoingMessage,
    escape_discord,
)
from vedette.rules.model import Severity

TOPIC = "vedette-topic-not-real"
TOKEN = "tk_not_a_real_token"  # noqa: S105 - fake value for these tests
WEBHOOK = "https://discord.com/api/webhooks/123456789/not-a-real-webhook-token"
PASSWORD = "not-a-real-password"  # noqa: S105 - fake value for these tests


def message(body: str = "Body line one.\nBody line two.", **kw: Any) -> OutgoingMessage:
    values: dict[str, Any] = {
        "title": "Vedette test",
        "body": body,
        "priority": Severity.HIGH,
        "tags": ("warning",),
    }
    values.update(kw)
    return OutgoingMessage(**values)


@pytest.fixture
def web() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


# --- ntfy ------------------------------------------------------------------------------


@pytest.fixture
async def ntfy(web: respx.MockRouter) -> AsyncIterator[NtfyChannel]:
    channel = NtfyChannel("https://ntfy.example", TOPIC, token=TOKEN)
    yield channel
    await channel.aclose()


async def test_ntfy_publishes_json_to_the_root_url(
    ntfy: NtfyChannel, web: respx.MockRouter
) -> None:
    route = web.post("https://ntfy.example/").mock(return_value=httpx.Response(200, json={}))

    await ntfy.send(message())

    request = route.calls.last.request
    body = json.loads(request.content)
    assert body == {
        "topic": TOPIC,
        "title": "Vedette test",
        "message": "Body line one.\nBody line two.",
        "priority": 4,
        "tags": ["warning"],
    }
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert "Markdown" not in request.headers
    assert "X-Markdown" not in request.headers


@pytest.mark.parametrize(
    ("severity", "priority"),
    [
        (Severity.INFO, 1),
        (Severity.LOW, 2),
        (Severity.MEDIUM, 3),
        (Severity.HIGH, 4),
        (Severity.CRITICAL, 5),
    ],
)
async def test_ntfy_priority_follows_severity(
    ntfy: NtfyChannel, web: respx.MockRouter, severity: Severity, priority: int
) -> None:
    route = web.post("https://ntfy.example/").mock(return_value=httpx.Response(200, json={}))

    await ntfy.send(message(priority=severity))

    assert json.loads(route.calls.last.request.content)["priority"] == priority


async def test_ntfy_without_a_token_sends_no_authorization(web: respx.MockRouter) -> None:
    route = web.post("https://ntfy.example/").mock(return_value=httpx.Response(200, json={}))
    channel = NtfyChannel("https://ntfy.example", TOPIC)
    try:
        await channel.send(message())
    finally:
        await channel.aclose()

    assert "Authorization" not in route.calls.last.request.headers


async def test_ntfy_long_messages_are_cut_below_the_attachment_limit(
    ntfy: NtfyChannel, web: respx.MockRouter
) -> None:
    route = web.post("https://ntfy.example/").mock(return_value=httpx.Response(200, json={}))

    await ntfy.send(message(body="é" * 5000))

    sent = json.loads(route.calls.last.request.content)["message"]
    assert len(sent.encode("utf-8")) <= NTFY_MAX_BYTES
    assert sent.endswith("(cut short; run 'vedette findings' for the rest)")


@pytest.mark.parametrize(
    ("response", "retryable", "retry_after"),
    [
        (httpx.Response(429, headers={"Retry-After": "12"}), True, 12.0),
        (httpx.Response(503), True, None),
        (httpx.Response(401), False, None),
        (httpx.Response(403), False, None),
        (httpx.Response(400, json={"error": "bad"}), False, None),
    ],
)
async def test_ntfy_failures_say_whether_to_retry(
    ntfy: NtfyChannel,
    web: respx.MockRouter,
    response: httpx.Response,
    retryable: bool,
    retry_after: float | None,
) -> None:
    web.post("https://ntfy.example/").mock(return_value=response)

    with pytest.raises(DeliveryError) as excinfo:
        await ntfy.send(message())

    assert excinfo.value.retryable is retryable
    assert excinfo.value.retry_after == retry_after
    assert TOPIC not in str(excinfo.value)
    assert TOKEN not in str(excinfo.value)


async def test_ntfy_network_errors_are_retryable(ntfy: NtfyChannel, web: respx.MockRouter) -> None:
    web.post("https://ntfy.example/").mock(side_effect=httpx.ConnectError("down"))

    with pytest.raises(DeliveryError) as excinfo:
        await ntfy.send(message())

    assert excinfo.value.retryable is True


# --- Discord ---------------------------------------------------------------------------


class SleepRecorder:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


@pytest.fixture
def sleeps() -> SleepRecorder:
    return SleepRecorder()


@pytest.fixture
async def discord(web: respx.MockRouter, sleeps: SleepRecorder) -> AsyncIterator[DiscordChannel]:
    channel = DiscordChannel(WEBHOOK, sleep=sleeps)
    yield channel
    await channel.aclose()


def discord_route(web: respx.MockRouter) -> respx.Route:
    return web.post(WEBHOOK, params={"wait": "true"})


async def test_discord_posts_without_mentions_or_link_previews(
    discord: DiscordChannel, web: respx.MockRouter
) -> None:
    route = discord_route(web).mock(return_value=httpx.Response(200, json={"id": "1"}))

    await discord.send(message())

    body = json.loads(route.calls.last.request.content)
    assert body["allowed_mentions"] == {"parse": []}
    assert body["flags"] == 4
    assert body["content"].startswith("**Vedette test**\n")
    assert "Body line one\\." in body["content"] or "Body line one." in body["content"]


async def test_discord_escapes_markdown_in_message_text(
    discord: DiscordChannel, web: respx.MockRouter
) -> None:
    route = discord_route(web).mock(return_value=httpx.Response(200, json={"id": "1"}))

    await discord.send(message(body="**bold** [click](hxxp://x) @everyone `code` > quote"))

    content = json.loads(route.calls.last.request.content)["content"]
    body = content.split("\n", 1)[1]
    assert "**bold**" not in body
    assert "[click](" not in body
    assert "\\@everyone" in body
    assert "\\`code\\`" in body


def test_escape_discord_escapes_every_formatting_character() -> None:
    assert escape_discord("a*b_c~d`e|f>g#h-i[j]k(l)m<n@o:p\\q") == (
        "a\\*b\\_c\\~d\\`e\\|f\\>g\\#h\\-i\\[j\\]k\\(l\\)m\\<n\\@o\\:p\\\\q"
    )


async def test_discord_splits_long_messages_into_ordered_chunks(
    discord: DiscordChannel, web: respx.MockRouter
) -> None:
    route = discord_route(web).mock(return_value=httpx.Response(200, json={"id": "1"}))
    lines = [f"line {n:04d} " + "x" * 80 for n in range(60)]

    await discord.send(message(body="\n".join(lines)))

    contents = [json.loads(call.request.content)["content"] for call in route.calls]
    assert len(contents) > 1
    assert all(len(content) <= 2000 for content in contents)
    joined = "\n".join(contents)
    positions = [joined.index(f"line {n:04d}") for n in range(60)]
    assert positions == sorted(positions)


async def test_discord_never_sends_more_than_the_chunk_limit(
    discord: DiscordChannel, web: respx.MockRouter
) -> None:
    route = discord_route(web).mock(return_value=httpx.Response(200, json={"id": "1"}))

    await discord.send(message(body="\n".join("y" * 1500 for _ in range(40))))

    assert route.call_count == DISCORD_MAX_CHUNKS
    last = json.loads(route.calls.last.request.content)["content"]
    assert "cut short" in last


async def test_discord_short_rate_limits_are_waited_out(
    discord: DiscordChannel, web: respx.MockRouter, sleeps: SleepRecorder
) -> None:
    discord_route(web).mock(
        side_effect=[
            httpx.Response(429, json={"message": "slow down", "retry_after": 0.5, "global": False}),
            httpx.Response(200, json={"id": "1"}),
        ]
    )

    await discord.send(message())

    assert sleeps.delays == [0.5]


async def test_discord_long_rate_limits_are_handed_back(
    discord: DiscordChannel, web: respx.MockRouter
) -> None:
    discord_route(web).mock(
        return_value=httpx.Response(429, json={"retry_after": 120.0, "global": False})
    )

    with pytest.raises(DeliveryError) as excinfo:
        await discord.send(message())

    assert excinfo.value.retryable is True
    assert excinfo.value.retry_after == 120.0


@pytest.mark.parametrize(
    ("response", "retryable"),
    [
        (httpx.Response(404, json={"message": "Unknown Webhook"}), False),
        (httpx.Response(401), False),
        (httpx.Response(400, json={"message": "bad"}), False),
        (httpx.Response(502), True),
    ],
)
async def test_discord_failures_say_whether_to_retry(
    discord: DiscordChannel, web: respx.MockRouter, response: httpx.Response, retryable: bool
) -> None:
    discord_route(web).mock(return_value=response)

    with pytest.raises(DeliveryError) as excinfo:
        await discord.send(message())

    assert excinfo.value.retryable is retryable
    assert "not-a-real-webhook-token" not in str(excinfo.value)


# --- e-mail ----------------------------------------------------------------------------


class FakeSMTP:
    """Stands in for smtplib.SMTP / SMTP_SSL and records what was done."""

    instances: ClassVar[list[FakeSMTP]] = []
    fail_with: ClassVar[BaseException | None] = None

    def __init__(self, host: str, port: int, **kw: Any) -> None:
        self.host, self.port, self.kw = host, port, kw
        self.calls: list[tuple[str, Any]] = []
        self.sent: list[EmailMessage] = []
        FakeSMTP.instances.append(self)

    def ehlo(self) -> None:
        self.calls.append(("ehlo", None))

    def starttls(self, *, context: ssl.SSLContext) -> None:
        self.calls.append(("starttls", context))

    def login(self, user: str, password: str) -> None:
        self.calls.append(("login", (user, password)))

    def send_message(self, msg: EmailMessage) -> None:
        if FakeSMTP.fail_with is not None:
            raise FakeSMTP.fail_with
        self.sent.append(msg)

    def quit(self) -> None:
        self.calls.append(("quit", None))

    def close(self) -> None:
        self.calls.append(("close", None))


@pytest.fixture(autouse=True)
def reset_fake_smtp() -> None:
    FakeSMTP.instances = []
    FakeSMTP.fail_with = None


def email_channel(security: str = "starttls", username: str = "me@example.org") -> EmailChannel:
    return EmailChannel(
        host="smtp.example.org",
        port=587 if security == "starttls" else 465,
        security=security,
        username=username,
        password=PASSWORD,
        sender="vedette@example.org",
        recipients=["me@example.org", "you@example.org"],
        smtp_class=FakeSMTP,
        smtp_ssl_class=FakeSMTP,
    )


def verified(context: object) -> bool:
    return (
        isinstance(context, ssl.SSLContext)
        and context.verify_mode == ssl.CERT_REQUIRED
        and context.check_hostname
    )


async def test_email_uses_starttls_with_certificate_checks_then_logs_in() -> None:
    await email_channel().send(message())

    (smtp,) = FakeSMTP.instances
    assert (smtp.host, smtp.port) == ("smtp.example.org", 587)
    names = [name for name, _ in smtp.calls]
    assert names.index("starttls") < names.index("login")
    assert verified(dict(smtp.calls)["starttls"])
    assert dict(smtp.calls)["login"] == ("me@example.org", PASSWORD)
    (sent,) = smtp.sent
    assert sent["Subject"] == "[Vedette] Vedette test"
    assert sent["From"] == "vedette@example.org"
    assert sent["To"] == "me@example.org, you@example.org"
    assert sent.get_content().strip() == "Body line one.\nBody line two."
    assert sent.get_content_type() == "text/plain"


async def test_email_over_implicit_tls_verifies_the_certificate() -> None:
    await email_channel(security="ssl").send(message())

    (smtp,) = FakeSMTP.instances
    assert verified(smtp.kw["context"])
    assert "starttls" not in [name for name, _ in smtp.calls]


async def test_email_without_a_username_does_not_log_in() -> None:
    await email_channel(username="").send(message())

    assert "login" not in [name for name, _ in FakeSMTP.instances[0].calls]


async def test_email_subject_cannot_inject_headers() -> None:
    await email_channel().send(message(title="hi\r\nBcc: evil@example.org"))

    (sent,) = FakeSMTP.instances[0].sent
    assert "\n" not in sent["Subject"]
    assert "\r" not in sent["Subject"]
    assert sent["Bcc"] is None


@pytest.mark.parametrize(
    ("error", "retryable"),
    [
        (smtplib.SMTPAuthenticationError(535, b"bad credentials"), False),
        (smtplib.SMTPRecipientsRefused({"me@example.org": (550, b"no")}), False),
        (smtplib.SMTPSenderRefused(550, b"no", "vedette@example.org"), False),
        (ssl.SSLCertVerificationError("certificate verify failed"), False),
        (smtplib.SMTPServerDisconnected("gone"), True),
        (ConnectionRefusedError("refused"), True),
    ],
)
async def test_email_failures_say_whether_to_retry(error: BaseException, retryable: bool) -> None:
    FakeSMTP.fail_with = error

    with pytest.raises(DeliveryError) as excinfo:
        await email_channel().send(message())

    assert excinfo.value.retryable is retryable
    assert PASSWORD not in str(excinfo.value)
