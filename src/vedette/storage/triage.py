"""Triage actions on findings, the stored allowlist, and the audit log.

Every change is made in one transaction together with its audit entry. Marking
a domain finding benign allowlists its root for that profile, so the rules stop
flagging it; reopening the finding removes that entry again.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from vedette.rules.allowlist import AllowlistEntry
from vedette.storage.models import allowlist, audit_log, findings
from vedette.storage.store import StoredFinding, finding_from_row

# Rules whose target is a domain root; marking these benign allowlists the root.
DOMAIN_RULES = frozenset(
    {"young-domain", "threat-intel-allowed", "dga-like", "tunnel-like", "tunnel-slow"}
)
STATUSES = ("open", "acknowledged", "benign")
# Audit actions that change a finding's status; other entries only add history.
_DECISIONS = frozenset({"acknowledge", "mark_benign", "reopen"})


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One recorded change. ``detail`` may contain a raw domain name."""

    at: datetime
    actor: str
    action: str
    finding_id: int | None
    detail: str


@dataclass(frozen=True, slots=True)
class StoredAllowlistEntry:
    """An allowlist entry made from a triage decision. ``root`` is a raw domain name."""

    id: int
    root: str
    profile_id: str | None
    device_id: str | None
    finding_id: int | None
    created_at: datetime
    created_by: str


class TriageStore:
    """Changes finding status and keeps the allowlist and audit log."""

    def __init__(self, engine: AsyncEngine) -> None:
        """Use the given database engine (shared with the event store)."""
        self._engine = engine

    @staticmethod
    async def _load(connection: AsyncConnection, finding_id: int) -> StoredFinding | None:
        row = (
            await connection.execute(select(findings).where(findings.c.id == finding_id))
        ).one_or_none()
        return None if row is None else finding_from_row(row)

    @staticmethod
    async def _set_status(
        connection: AsyncConnection, finding_id: int, status: str, now: datetime
    ) -> None:
        await connection.execute(
            update(findings)
            .where(findings.c.id == finding_id)
            .values(status=status, updated_at=now)
        )

    @staticmethod
    async def _audit(
        connection: AsyncConnection,
        *,
        actor: str,
        action: str,
        finding_id: int,
        detail: str,
        now: datetime,
    ) -> None:
        await connection.execute(
            audit_log.insert().values(
                at=now, actor=actor, action=action, finding_id=finding_id, detail=detail[:300]
            )
        )

    async def acknowledge(
        self, finding_id: int, *, actor: str, now: datetime
    ) -> StoredFinding | None:
        """Mark a finding as seen. Returns the updated finding, or ``None`` if unknown."""
        async with self._engine.begin() as connection:
            if await self._load(connection, finding_id) is None:
                return None
            await self._set_status(connection, finding_id, "acknowledged", now)
            await self._audit(
                connection,
                actor=actor,
                action="acknowledge",
                finding_id=finding_id,
                detail="status set to acknowledged",
                now=now,
            )
            return await self._load(connection, finding_id)

    async def mark_benign(
        self, finding_id: int, *, actor: str, now: datetime
    ) -> StoredFinding | None:
        """Mark a finding benign; for a domain finding, allowlist its root for the profile."""
        async with self._engine.begin() as connection:
            finding = await self._load(connection, finding_id)
            if finding is None:
                return None
            await self._set_status(connection, finding_id, "benign", now)
            detail = "status set to benign"
            if finding.rule_id in DOMAIN_RULES:
                await connection.execute(
                    delete(allowlist).where(allowlist.c.finding_id == finding_id)
                )
                await connection.execute(
                    allowlist.insert().values(
                        root=finding.target.lower(),
                        profile_id=finding.profile_id,
                        device_id=None,
                        finding_id=finding_id,
                        created_at=now,
                        created_by=actor,
                    )
                )
                detail = f"status set to benign; {finding.target} allowlisted for this profile"
            await self._audit(
                connection,
                actor=actor,
                action="mark_benign",
                finding_id=finding_id,
                detail=detail,
                now=now,
            )
            return await self._load(connection, finding_id)

    async def reopen(self, finding_id: int, *, actor: str, now: datetime) -> StoredFinding | None:
        """Set a finding back to open and remove any allowlist entry it created."""
        async with self._engine.begin() as connection:
            if await self._load(connection, finding_id) is None:
                return None
            removed = await connection.execute(
                delete(allowlist).where(allowlist.c.finding_id == finding_id)
            )
            await self._set_status(connection, finding_id, "open", now)
            detail = "status set to open" + (
                "; allowlist entry removed" if removed.rowcount else ""
            )
            await self._audit(
                connection,
                actor=actor,
                action="reopen",
                finding_id=finding_id,
                detail=detail,
                now=now,
            )
            return await self._load(connection, finding_id)

    async def stored_allowlist(self) -> list[StoredAllowlistEntry]:
        """Every stored allowlist entry with where it came from, newest first."""
        statement = select(allowlist).order_by(allowlist.c.id.desc())
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        return [
            StoredAllowlistEntry(
                id=row.id,
                root=row.root,
                profile_id=row.profile_id,
                device_id=row.device_id,
                finding_id=row.finding_id,
                created_at=row.created_at,
                created_by=row.created_by,
            )
            for row in rows
        ]

    async def remove_allowlist_entry(
        self, entry_id: int, *, actor: str, now: datetime
    ) -> StoredAllowlistEntry | None:
        """Take back one stored entry, so the rules flag its root again.

        The finding that made it stays benign; its history records the removal.
        Returns the entry, or ``None`` if there is no such entry.
        """
        async with self._engine.begin() as connection:
            row = (
                await connection.execute(select(allowlist).where(allowlist.c.id == entry_id))
            ).one_or_none()
            if row is None:
                return None
            await connection.execute(delete(allowlist).where(allowlist.c.id == entry_id))
            if row.finding_id is not None:
                await self._audit(
                    connection,
                    actor=actor,
                    action="allowlist_removed",
                    finding_id=row.finding_id,
                    detail=f"{row.root} removed from the allowlist; the rules flag it again",
                    now=now,
                )
        return StoredAllowlistEntry(
            id=row.id,
            root=row.root,
            profile_id=row.profile_id,
            device_id=row.device_id,
            finding_id=row.finding_id,
            created_at=row.created_at,
            created_by=row.created_by,
        )

    async def allowlist_entries(self) -> list[AllowlistEntry]:
        """Every stored allowlist entry."""
        async with self._engine.connect() as connection:
            rows = (await connection.execute(select(allowlist).order_by(allowlist.c.id))).all()
        return [
            AllowlistEntry(root=row.root, profile=row.profile_id, device=row.device_id)
            for row in rows
        ]

    async def latest_for(self, finding_ids: Sequence[int]) -> dict[int, AuditEntry]:
        """The most recent decision (acknowledge, mark benign, reopen) of each finding."""
        latest: dict[int, AuditEntry] = {}
        for entry in await self.audit_for(finding_ids):
            if entry.finding_id is not None and entry.action in _DECISIONS:
                latest[entry.finding_id] = entry
        return latest

    async def audit_for(self, finding_ids: Sequence[int]) -> list[AuditEntry]:
        """Audit entries for the given findings, oldest first."""
        async with self._engine.connect() as connection:
            rows = (
                await connection.execute(
                    select(audit_log)
                    .where(audit_log.c.finding_id.in_(list(finding_ids)))
                    .order_by(audit_log.c.id)
                )
            ).all()
        return [
            AuditEntry(
                at=row.at,
                actor=row.actor,
                action=row.action,
                finding_id=row.finding_id,
                detail=row.detail,
            )
            for row in rows
        ]
