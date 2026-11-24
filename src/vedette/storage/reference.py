"""Storage for enrichment reference data: popularity, threat feeds, domain ages, first-seen.

Kept in the same database as the events so that a restart finds every cache
intact and nothing has to be downloaded or looked up again.
"""

from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import batched
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from vedette.storage.models import (
    domain_age,
    eval_hostnames,
    first_seen,
    popularity,
    public_suffixes,
    reference_state,
    threat_intel,
)

_IN_CHUNK = 500
_INSERT_CHUNK = 5000


@dataclass(frozen=True, slots=True)
class DomainAgeRecord:
    """A cached RDAP answer for a root.

    ``status`` is ``found`` (``registered_at`` set) or a reason it is unknown.
    """

    root: str
    status: str
    registered_at: datetime | None
    fetched_at: datetime


@dataclass(frozen=True, slots=True)
class FirstSeenRow:
    """The first event in which a value was seen for a profile (and subject)."""

    profile_id: str
    kind: str
    subject: str
    value: str
    first_ts: datetime
    first_event_id: str


class ReferenceStore:
    """Reads and writes the enrichment reference tables."""

    def __init__(self, engine: AsyncEngine) -> None:
        """Use the given database engine (shared with the event store)."""
        self._engine = engine

    # --- refresh bookkeeping ------------------------------------------------------

    async def refreshed_at(self, name: str) -> datetime | None:
        """When the named data set was last refreshed successfully."""
        async with self._engine.connect() as connection:
            row = (
                await connection.execute(
                    select(reference_state.c.refreshed_at).where(reference_state.c.name == name)
                )
            ).one_or_none()
        return None if row is None else row.refreshed_at

    async def _mark_refreshed(
        self, connection: AsyncConnection, name: str, when: datetime, entries: int
    ) -> None:
        statement = sqlite_insert(reference_state).values(
            name=name, refreshed_at=when, entries=entries
        )
        await connection.execute(
            statement.on_conflict_do_update(
                index_elements=["name"],
                set_={"refreshed_at": when, "entries": entries},
            )
        )

    # --- popularity -----------------------------------------------------------------

    async def replace_popularity(self, rows: Iterable[tuple[str, int]], when: datetime) -> int:
        """Replace the whole top-sites list in one transaction; return its size."""
        total = 0
        async with self._engine.begin() as connection:
            await connection.execute(delete(popularity))
            for chunk in batched(rows, _INSERT_CHUNK, strict=False):
                await connection.execute(
                    popularity.insert(),
                    [{"domain": domain, "rank": rank} for domain, rank in chunk],
                )
                total += len(chunk)
            if total == 0:
                await connection.rollback()
                return 0
            await self._mark_refreshed(connection, "popularity", when, total)
        return total

    async def popularity_count(self) -> int:
        """Number of domains in the stored top-sites list."""
        async with self._engine.connect() as connection:
            result = await connection.execute(select(func.count()).select_from(popularity))
            return int(result.scalar_one())

    async def ranks(self, domains: Collection[str]) -> dict[str, int]:
        """Ranks of the given domains that are on the list."""
        found: dict[str, int] = {}
        async with self._engine.connect() as connection:
            for chunk in batched(domains, _IN_CHUNK, strict=False):
                rows = await connection.execute(
                    select(popularity.c.domain, popularity.c.rank).where(
                        popularity.c.domain.in_(chunk)
                    )
                )
                found.update((row.domain, row.rank) for row in rows)
        return found

    # --- popular hostnames, for the evaluation ------------------------------------------

    async def replace_eval_hostnames(self, rows: Iterable[tuple[str, int]], when: datetime) -> int:
        """Replace the evaluation's hostname list in one transaction; return its size.

        An empty list changes nothing and returns 0, so the stored copy survives.
        """
        total = 0
        async with self._engine.begin() as connection:
            await connection.execute(delete(eval_hostnames))
            for chunk in batched(rows, _INSERT_CHUNK, strict=False):
                await connection.execute(
                    eval_hostnames.insert(),
                    [{"name": name, "rank": rank} for name, rank in chunk],
                )
                total += len(chunk)
            if total == 0:
                await connection.rollback()
                return 0
            await self._mark_refreshed(connection, "eval_hostnames", when, total)
        return total

    # --- public suffix list -----------------------------------------------------------

    async def replace_public_suffixes(
        self, rules: Iterable[tuple[str, bool]], when: datetime
    ) -> int:
        """Replace the whole Public Suffix List in one transaction; return its size."""
        total = 0
        async with self._engine.begin() as connection:
            await connection.execute(delete(public_suffixes))
            statement = sqlite_insert(public_suffixes).on_conflict_do_nothing()
            for chunk in batched(rules, _INSERT_CHUNK, strict=False):
                await connection.execute(
                    statement, [{"rule": rule, "private": private} for rule, private in chunk]
                )
                total += len(chunk)
            if total == 0:
                await connection.rollback()
                return 0
            await self._mark_refreshed(connection, "public_suffix", when, total)
        return total

    async def public_suffix_rules(self) -> list[tuple[str, bool]]:
        """Every stored Public Suffix List rule and whether it is a private one."""
        async with self._engine.connect() as connection:
            rows = (await connection.execute(select(public_suffixes))).all()
        return [(row.rule, row.private) for row in rows]

    # --- threat intelligence ----------------------------------------------------------

    async def replace_feed(self, feed: str, domains: Iterable[str], when: datetime) -> int:
        """Replace one feed's entries in one transaction; return how many it has."""
        total = 0
        async with self._engine.begin() as connection:
            await connection.execute(delete(threat_intel).where(threat_intel.c.feed == feed))
            statement = sqlite_insert(threat_intel).on_conflict_do_nothing()
            for chunk in batched(domains, _INSERT_CHUNK, strict=False):
                await connection.execute(
                    statement, [{"domain": domain, "feed": feed} for domain in chunk]
                )
                total += len(chunk)
            if total == 0:
                await connection.rollback()
                return 0
            await self._mark_refreshed(connection, f"feed:{feed}", when, total)
        return total

    async def threat_matches(self, domains: Collection[str]) -> dict[str, list[str]]:
        """Feeds listing each of the given domains (exact matches only)."""
        found: dict[str, list[str]] = {}
        async with self._engine.connect() as connection:
            for chunk in batched(domains, _IN_CHUNK, strict=False):
                rows = await connection.execute(
                    select(threat_intel.c.domain, threat_intel.c.feed).where(
                        threat_intel.c.domain.in_(chunk)
                    )
                )
                for row in rows:
                    found.setdefault(row.domain, []).append(row.feed)
        return found

    # --- domain age -------------------------------------------------------------------

    async def domain_ages(self, roots: Collection[str]) -> dict[str, DomainAgeRecord]:
        """Cached RDAP answers for the given roots."""
        found: dict[str, DomainAgeRecord] = {}
        async with self._engine.connect() as connection:
            for chunk in batched(roots, _IN_CHUNK, strict=False):
                rows = await connection.execute(
                    select(domain_age).where(domain_age.c.root.in_(chunk))
                )
                for row in rows:
                    found[row.root] = DomainAgeRecord(
                        root=row.root,
                        status=row.status,
                        registered_at=row.registered_at,
                        fetched_at=row.fetched_at,
                    )
        return found

    async def save_domain_ages(self, records: Sequence[DomainAgeRecord]) -> None:
        """Insert or replace cached RDAP answers."""
        if not records:
            return
        rows: list[dict[str, Any]] = [
            {
                "root": record.root,
                "status": record.status,
                "registered_at": record.registered_at,
                "fetched_at": record.fetched_at,
            }
            for record in records
        ]
        statement = sqlite_insert(domain_age)
        async with self._engine.begin() as connection:
            await connection.execute(
                statement.on_conflict_do_update(
                    index_elements=["root"],
                    set_={
                        "status": statement.excluded.status,
                        "registered_at": statement.excluded.registered_at,
                        "fetched_at": statement.excluded.fetched_at,
                    },
                ),
                rows,
            )

    # --- first seen -------------------------------------------------------------------

    async def load_first_seen(self) -> list[FirstSeenRow]:
        """Every first-seen record."""
        async with self._engine.connect() as connection:
            rows = (await connection.execute(select(first_seen))).all()
        return [
            FirstSeenRow(
                profile_id=row.profile_id,
                kind=row.kind,
                subject=row.subject,
                value=row.value,
                first_ts=row.first_ts,
                first_event_id=row.first_event_id,
            )
            for row in rows
        ]

    async def save_first_seen(self, rows: Sequence[FirstSeenRow]) -> None:
        """Record new first sightings; existing records are left untouched."""
        if not rows:
            return
        statement = sqlite_insert(first_seen).on_conflict_do_nothing()
        async with self._engine.begin() as connection:
            for chunk in batched(rows, _INSERT_CHUNK, strict=False):
                await connection.execute(
                    statement,
                    [
                        {
                            "profile_id": row.profile_id,
                            "kind": row.kind,
                            "subject": row.subject,
                            "value": row.value,
                            "first_ts": row.first_ts,
                            "first_event_id": row.first_event_id,
                        }
                        for row in chunk
                    ],
                )
