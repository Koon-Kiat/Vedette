"""Dashboard sessions and login throttling.

Sessions live in memory: a restart means logging in again. The session cookie
holds only a random id; the login token itself is never stored in a cookie.
"""

import secrets
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

SESSION_COOKIE = "sentinel_session"
LOGIN_COOKIE = "sentinel_login"
MAX_FAILURES = 5
FAILURE_WINDOW = timedelta(seconds=60)


@dataclass(frozen=True, slots=True)
class Session:
    """A logged-in browser."""

    id: str
    csrf: str
    expires_at: datetime


class SessionStore:
    """Creates, finds and ends sessions."""

    def __init__(self, lifetime: timedelta, clock: Callable[[], datetime]) -> None:
        """Sessions last ``lifetime`` from login."""
        self._lifetime = lifetime
        self._clock = clock
        self._sessions: dict[str, Session] = {}

    @property
    def lifetime(self) -> timedelta:
        """How long a session lasts."""
        return self._lifetime

    def create(self) -> Session:
        """Start a session with fresh random identifiers."""
        now = self._clock()
        self._sessions = {k: s for k, s in self._sessions.items() if s.expires_at > now}
        session = Session(
            id=secrets.token_urlsafe(32),
            csrf=secrets.token_urlsafe(32),
            expires_at=now + self._lifetime,
        )
        self._sessions[session.id] = session
        return session

    def get(self, session_id: str | None) -> Session | None:
        """The live session with this id, if any."""
        if not session_id:
            return None
        session = self._sessions.get(session_id)
        if session is None:
            return None
        if session.expires_at <= self._clock():
            del self._sessions[session_id]
            return None
        return session

    def end(self, session_id: str) -> None:
        """Forget a session."""
        self._sessions.pop(session_id, None)


class LoginLimiter:
    """Refuses logins for a minute after five failures within a minute."""

    def __init__(self, clock: Callable[[], datetime]) -> None:
        """Count failures against ``clock``."""
        self._clock = clock
        self._failures: deque[datetime] = deque()

    def _trim(self) -> None:
        cutoff = self._clock() - FAILURE_WINDOW
        while self._failures and self._failures[0] <= cutoff:
            self._failures.popleft()

    def blocked(self) -> bool:
        """Whether logins are currently refused."""
        self._trim()
        return len(self._failures) >= MAX_FAILURES

    def failed(self) -> None:
        """Record a failed login."""
        self._failures.append(self._clock())
