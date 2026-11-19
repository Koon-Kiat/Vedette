"""Delivery channels: ntfy, a Discord webhook, or e-mail.

Each channel sends one :class:`OutgoingMessage` and raises
:class:`DeliveryError` saying whether a retry could help. Error messages never
contain the channel's secrets (topic, token, webhook URL, password).

Message text is plain and already defanged by the renderer. Channels add only
what their medium needs: ntfy gets plain text (Markdown stays off), Discord
gets every formatting character escaped with mentions and link previews
disabled, and e-mail is ``text/plain``.
"""

import asyncio
import smtplib
import ssl
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

import httpx

from sentinel.notify.defang import clean_text
from sentinel.retry import parse_retry_after
from sentinel.rules.model import Severity

NTFY_MAX_BYTES = 4000  # ntfy turns messages over 4,096 bytes into attachments
DISCORD_CHUNK = 1900  # Discord allows 2,000 characters per message
DISCORD_MAX_CHUNKS = 10
DISCORD_MAX_INLINE_WAIT = 30.0
DISCORD_SUPPRESS_EMBEDS = 1 << 2
CUT_NOTE = "… (cut short; run 'sentinel findings' for the rest)"

_NTFY_PRIORITY = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
_DISCORD_SPECIAL = frozenset("\\*_~`|>#-[]()<@:")
_TIMEOUT = httpx.Timeout(30.0)


@dataclass(frozen=True, slots=True)
class OutgoingMessage:
    """A notification ready to send: plain text, already made safe."""

    title: str
    body: str
    priority: Severity
    tags: tuple[str, ...] = ()


class DeliveryError(Exception):
    """A message could not be delivered."""

    def __init__(self, message: str, *, retryable: bool, retry_after: float | None = None) -> None:
        """Record why delivery failed and whether trying again may help."""
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


class Channel(ABC):
    """Somewhere notifications can be sent."""

    name: str

    @abstractmethod
    async def send(self, message: OutgoingMessage) -> None:
        """Deliver one message.

        Raises:
            DeliveryError: The message was not delivered.
        """

    @abstractmethod
    async def aclose(self) -> None:
        """Release any open connections."""


def _http_error(name: str, response: httpx.Response) -> DeliveryError:
    status = response.status_code
    if status == 429 or status >= 500:
        return DeliveryError(
            f"{name} answered HTTP {status}",
            retryable=True,
            retry_after=parse_retry_after(response.headers.get("Retry-After")),
        )
    if status in (401, 403):
        return DeliveryError(f"{name} rejected the credentials (HTTP {status})", retryable=False)
    return DeliveryError(f"{name} refused the message (HTTP {status})", retryable=False)


def _cut_bytes(text: str, limit: int) -> str:
    """Shorten ``text`` to at most ``limit`` UTF-8 bytes, ending with a note if cut."""
    if len(text.encode("utf-8")) <= limit:
        return text
    room = limit - len(("\n" + CUT_NOTE).encode("utf-8"))
    head = text.encode("utf-8")[:room].decode("utf-8", errors="ignore").rstrip()
    return f"{head}\n{CUT_NOTE}"


class NtfyChannel(Channel):
    """Publishes to an ntfy topic (ntfy.sh or self-hosted) as JSON."""

    name = "ntfy"

    def __init__(
        self,
        url: str,
        topic: str,
        *,
        token: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Create the channel.

        Args:
            url: The ntfy server's root URL.
            topic: Topic to publish to. On a public server it acts as a password.
            token: Optional access token.
            client: HTTP client to use; one is created if not given.
        """
        self._url = url.rstrip("/") + "/"
        self._topic = topic
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._client = client or httpx.AsyncClient(timeout=_TIMEOUT)
        self._headers = headers

    async def aclose(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def send(self, message: OutgoingMessage) -> None:
        """Publish ``message`` as plain text (Markdown stays off)."""
        payload: dict[str, Any] = {
            "topic": self._topic,
            "title": message.title[:250],
            "message": _cut_bytes(message.body, NTFY_MAX_BYTES),
            "priority": _NTFY_PRIORITY[message.priority],
            "tags": list(message.tags),
        }
        try:
            response = await self._client.post(self._url, json=payload, headers=self._headers)
        except httpx.HTTPError as exc:
            raise DeliveryError(
                f"ntfy request failed: {type(exc).__name__}", retryable=True
            ) from None
        if response.status_code != 200:
            raise _http_error("ntfy", response)


def escape_discord(text: str) -> str:
    """Backslash-escape every character Discord treats as formatting."""
    return "".join("\\" + ch if ch in _DISCORD_SPECIAL else ch for ch in text)


def _split(text: str, limit: int) -> list[str]:
    """Split text into chunks of at most ``limit`` characters, on line breaks if possible."""
    chunks: list[str] = []
    current = ""
    for line in text.split("\n"):
        while len(line) > limit:
            if current:
                chunks.append(current)
                current = ""
            chunks.append(line[:limit])
            line = line[limit:]
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > limit:
            chunks.append(current)
            current = line
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


class DiscordChannel(Channel):
    """Posts to a Discord channel through a webhook."""

    name = "discord"

    def __init__(
        self,
        webhook_url: str,
        *,
        client: httpx.AsyncClient | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Create the channel.

        Args:
            webhook_url: The webhook URL. It contains a secret token.
            client: HTTP client to use; one is created if not given.
            sleep: Awaitable used to wait out short rate limits.
        """
        self._url = webhook_url
        self._client = client or httpx.AsyncClient(timeout=_TIMEOUT)
        self._sleep = sleep

    async def aclose(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def send(self, message: OutgoingMessage) -> None:
        """Post ``message`` in as many parts as needed (at most ten)."""
        text = f"**{escape_discord(message.title[:250])}**\n{escape_discord(message.body)}"
        chunks = _split(text, DISCORD_CHUNK)
        if len(chunks) > DISCORD_MAX_CHUNKS:
            chunks = chunks[:DISCORD_MAX_CHUNKS]
            chunks[-1] = f"{chunks[-1]}\n{CUT_NOTE}"
        for chunk in chunks:
            await self._post(chunk)

    async def _post(self, content: str) -> None:
        payload = {
            "content": content,
            "allowed_mentions": {"parse": []},
            "flags": DISCORD_SUPPRESS_EMBEDS,
        }
        for _ in range(3):
            try:
                response = await self._client.post(self._url, params={"wait": "true"}, json=payload)
            except httpx.HTTPError as exc:
                raise DeliveryError(
                    f"Discord request failed: {type(exc).__name__}", retryable=True
                ) from None
            if response.status_code in (200, 204):
                return
            if response.status_code == 404:
                raise DeliveryError(
                    "the Discord webhook no longer exists (HTTP 404)", retryable=False
                )
            if response.status_code != 429:
                raise _http_error("Discord", response)
            wait = self._retry_after(response)
            if wait is None or wait > DISCORD_MAX_INLINE_WAIT:
                raise DeliveryError(
                    "Discord rate limit (HTTP 429)", retryable=True, retry_after=wait
                )
            await self._sleep(wait)
        raise DeliveryError("Discord rate limit (HTTP 429)", retryable=True)

    @staticmethod
    def _retry_after(response: httpx.Response) -> float | None:
        try:
            value = response.json().get("retry_after")
        except ValueError, AttributeError:
            value = None
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            return float(value)
        return parse_retry_after(response.headers.get("Retry-After"))


class EmailChannel(Channel):
    """Sends plain-text e-mail over SMTP with TLS and certificate checks."""

    name = "email"

    def __init__(
        self,
        *,
        host: str,
        port: int,
        security: str,
        username: str,
        password: str | None,
        sender: str,
        recipients: Sequence[str],
        timeout: float = 30.0,
        smtp_class: Callable[..., Any] = smtplib.SMTP,
        smtp_ssl_class: Callable[..., Any] = smtplib.SMTP_SSL,
    ) -> None:
        """Create the channel.

        Args:
            host: SMTP server.
            port: SMTP port (587 for STARTTLS, 465 for implicit TLS).
            security: ``starttls`` or ``ssl``. There is no unencrypted option.
            username: Login name; empty means no login.
            password: Login password.
            sender: The From address.
            recipients: The To addresses.
            timeout: Seconds to wait for the server.
            smtp_class: SMTP client class (replaced in tests).
            smtp_ssl_class: SMTP-over-TLS client class (replaced in tests).
        """
        self._host = host
        self._port = port
        self._security = security
        self._username = username
        self._password = password or ""
        self._sender = sender
        self._recipients = tuple(recipients)
        self._timeout = timeout
        self._smtp_class = smtp_class
        self._smtp_ssl_class = smtp_ssl_class

    async def aclose(self) -> None:
        """Nothing to release: each message uses its own SMTP connection."""
        return

    def _build(self, message: OutgoingMessage) -> EmailMessage:
        email = EmailMessage()
        email["Subject"] = f"[NextDNS Sentinel] {clean_text(message.title, limit=180)}"
        email["From"] = self._sender
        email["To"] = ", ".join(self._recipients)
        email["Date"] = formatdate(localtime=False)
        email["Message-ID"] = make_msgid(domain=self._sender.rpartition("@")[2] or None)
        email.set_content(message.body)
        return email

    def _send_sync(self, email: EmailMessage) -> None:
        context = ssl.create_default_context()
        if self._security == "ssl":
            smtp = self._smtp_ssl_class(
                self._host, self._port, context=context, timeout=self._timeout
            )
        else:
            smtp = self._smtp_class(self._host, self._port, timeout=self._timeout)
        try:
            if self._security == "starttls":
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
            if self._username:
                smtp.login(self._username, self._password)
            smtp.send_message(email)
        finally:
            try:
                smtp.quit()
            except smtplib.SMTPException, OSError:
                smtp.close()

    async def send(self, message: OutgoingMessage) -> None:
        """Send ``message`` to every recipient."""
        email = self._build(message)
        try:
            await asyncio.to_thread(self._send_sync, email)
        except smtplib.SMTPAuthenticationError as exc:
            raise DeliveryError(
                f"the mail server rejected the login (SMTP {exc.smtp_code})", retryable=False
            ) from None
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as exc:
            raise DeliveryError(
                f"the mail server refused an address ({type(exc).__name__})", retryable=False
            ) from None
        except ssl.SSLCertVerificationError:
            raise DeliveryError(
                "the mail server's TLS certificate could not be verified", retryable=False
            ) from None
        except smtplib.SMTPResponseException as exc:
            raise DeliveryError(
                f"the mail server answered SMTP {exc.smtp_code}", retryable=exc.smtp_code < 500
            ) from None
        except (smtplib.SMTPException, OSError) as exc:
            raise DeliveryError(
                f"e-mail delivery failed: {type(exc).__name__}", retryable=True
            ) from None
