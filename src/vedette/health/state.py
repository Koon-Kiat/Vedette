"""What running components report about themselves, for the health monitor."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class _SourceStatus:
    failing_since: datetime | None = None
    reason: str = ""
    last_ok: datetime | None = None


class HealthState:
    """In-memory reports from the collectors about reaching NextDNS."""

    def __init__(self) -> None:
        """Start with nothing reported."""
        self._sources: dict[str, _SourceStatus] = {}
        self._caught_up: set[str] = set()

    def caught_up(self, profile_id: str) -> None:
        """Record that the profile's collector has read everything up to about now.

        After a start-up the stored events end when Vedette stopped, so until
        this is reported their age says nothing about the profile itself.
        """
        self._caught_up.add(profile_id)

    def is_caught_up(self, profile_id: str) -> bool:
        """Whether the profile's collector has caught up since this start."""
        return profile_id in self._caught_up

    def source_ok(self, profile_id: str, *, now: datetime) -> None:
        """Record that the profile's source answered normally."""
        status = self._sources.setdefault(profile_id, _SourceStatus())
        status.failing_since = None
        status.reason = ""
        status.last_ok = now

    def source_failed(self, profile_id: str, reason: str, *, now: datetime) -> None:
        """Record a failed attempt; the failure run starts at the first one."""
        status = self._sources.setdefault(profile_id, _SourceStatus())
        if status.failing_since is None:
            status.failing_since = now
        status.reason = reason

    def failing_since(self, profile_id: str) -> tuple[datetime, str] | None:
        """When the current run of failures began and the latest reason, if failing."""
        status = self._sources.get(profile_id)
        if status is None or status.failing_since is None:
            return None
        return status.failing_since, status.reason
