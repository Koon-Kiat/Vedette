"""The internal DNS event model and the interface every log source implements.

Every later stage works only with :class:`DnsEvent`, so another source (AdGuard
Home, Pi-hole) can be added by implementing :class:`LogSource` alone.
"""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import AwareDatetime, BaseModel, ConfigDict, field_validator


class Reason(BaseModel):
    """Why the resolver blocked or allowed a query (for example a blocklist)."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str


class DnsEvent(BaseModel):
    """One DNS query, normalised. Every string in it is untrusted input."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    profile_id: str
    ts: AwareDatetime
    fqdn: str
    root: str | None = None
    status: str
    reasons: tuple[Reason, ...] = ()
    device_id: str | None = None
    device_name: str | None = None
    client_ip: str | None = None
    protocol: str | None = None
    encrypted: bool | None = None
    tracker: str | None = None
    source: str

    @field_validator("ts")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class LogPage:
    """One page of historical events.

    ``stream_cursor``, when present, is the position from which the live
    stream continues this history without gaps.
    """

    events: tuple[DnsEvent, ...]
    stream_cursor: str | None = None


@dataclass(frozen=True, slots=True)
class StreamedEvent:
    """A live event plus the cursor to resume from after it."""

    event: DnsEvent
    cursor: str | None


class SourceError(Exception):
    """The log source returned an error that retrying will not fix by itself."""


class SourceAuthError(SourceError):
    """The log source rejected our credentials."""


class SourceUnavailable(SourceError):
    """The log source is temporarily unreachable or overloaded; retry later."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        """Record the failure and, if the server gave one, how long to wait."""
        super().__init__(message)
        self.retry_after = retry_after


class StreamCursorRejected(SourceError):
    """The live stream refused the stored cursor; history must be re-read."""


class LogSource(ABC):
    """A provider of DNS query logs for a profile."""

    @abstractmethod
    def backfill(self, profile_id: str, since: datetime) -> AsyncIterator[LogPage]:
        """Yield pages covering every event from ``since`` until now.

        Exactly one page (the first) carries a ``stream_cursor``. Pages may
        overlap; callers must store events idempotently.
        """

    @abstractmethod
    def stream(self, profile_id: str, cursor: str) -> AsyncIterator[StreamedEvent]:
        """Yield live events that follow ``cursor`` until the connection ends.

        Raises:
            StreamCursorRejected: The source no longer accepts ``cursor``.
            SourceUnavailable: The connection failed or dropped.
        """
