"""Latest health check results, kept so the digest, CLI and dashboard can show them."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinel.storage.models import health_checks


@dataclass(frozen=True, slots=True)
class HealthCheck:
    """The outcome of one check. ``detail`` is our own wording, never log data.

    A ``pending`` check cannot be judged yet; it is shown as OK and neither
    raises nor resolves an alert.
    """

    key: str
    label: str
    ok: bool
    detail: str
    pending: bool = False


@dataclass(frozen=True, slots=True)
class HealthRow:
    """A stored check result. ``since`` is when it last changed between OK and not."""

    key: str
    label: str
    ok: bool
    detail: str
    since: datetime
    updated_at: datetime


class HealthStore:
    """Replaces and reads the set of current health check results."""

    def __init__(self, engine: AsyncEngine) -> None:
        """Use the given database engine (shared with the event store)."""
        self._engine = engine

    async def save(self, checks: Sequence[HealthCheck], *, now: datetime) -> None:
        """Store the latest results, keeping ``since`` for checks whose state held."""
        async with self._engine.begin() as connection:
            previous = {
                row.check_key: row
                for row in (await connection.execute(select(health_checks))).all()
            }
            keys = [check.key for check in checks]
            await connection.execute(
                delete(health_checks).where(health_checks.c.check_key.not_in(keys))
            )
            for position, check in enumerate(checks):
                old = previous.get(check.key)
                since = old.since if old is not None and old.ok == check.ok else now
                values = {
                    "position": position,
                    "label": check.label[:128],
                    "ok": check.ok,
                    "detail": check.detail[:300],
                    "since": since,
                    "updated_at": now,
                }
                statement = sqlite_insert(health_checks).values(check_key=check.key, **values)
                await connection.execute(
                    statement.on_conflict_do_update(index_elements=["check_key"], set_=values)
                )

    async def read(self) -> list[HealthRow]:
        """The latest results, in the order the monitor produced them."""
        async with self._engine.connect() as connection:
            rows = (
                await connection.execute(select(health_checks).order_by(health_checks.c.position))
            ).all()
        return [
            HealthRow(
                key=row.check_key,
                label=row.label,
                ok=row.ok,
                detail=row.detail,
                since=row.since,
                updated_at=row.updated_at,
            )
            for row in rows
        ]
