"""First-seen tracking per profile and per device.

Answers "is this the first event ever with this device / client IP / root /
category?". Each first sighting is tied to the id of the event that caused it,
so enriching the same event again (after a crash, say) gives the same answer
instead of silently losing the finding.
"""

from dataclasses import dataclass

from sentinel.sources.base import DnsEvent
from sentinel.storage.reference import FirstSeenRow, ReferenceStore

_PROFILE_WIDE = ""

type _Key = tuple[str, str, str, str]


@dataclass(frozen=True, slots=True)
class FirstSeenFlags:
    """What is new about one event."""

    new_device: bool
    new_client_ip: bool
    new_root_for_profile: bool
    new_root_for_device: bool
    new_categories: tuple[str, ...]


class FirstSeenTracker:
    """In-memory view of the first-seen table, written back with :meth:`flush`."""

    def __init__(self, reference: ReferenceStore, known: dict[_Key, str]) -> None:
        """Use :meth:`load` instead."""
        self._reference = reference
        self._known = known
        self._pending: list[FirstSeenRow] = []

    @classmethod
    async def load(cls, reference: ReferenceStore) -> FirstSeenTracker:
        """Build a tracker from everything recorded so far."""
        rows = await reference.load_first_seen()
        known = {
            (row.profile_id, row.kind, row.subject, row.value): row.first_event_id for row in rows
        }
        return cls(reference, known)

    def _first(self, event: DnsEvent, kind: str, subject: str, value: str) -> bool:
        key = (event.profile_id, kind, subject, value[:256])
        first_event = self._known.get(key)
        if first_event is None:
            self._known[key] = event.event_id
            self._pending.append(
                FirstSeenRow(event.profile_id, kind, subject, key[3], event.ts, event.event_id)
            )
            return True
        return first_event == event.event_id

    def observe(self, event: DnsEvent) -> FirstSeenFlags:
        """Record an event and report what it is the first sighting of.

        Without a device id, categories are tracked for the profile as a whole
        and the device flags are ``False``.
        """
        device = event.device_id
        subject = device if device is not None else _PROFILE_WIDE
        root = event.root or event.fqdn
        return FirstSeenFlags(
            new_device=device is not None and self._first(event, "device", _PROFILE_WIDE, device),
            new_client_ip=event.client_ip is not None
            and self._first(event, "client_ip", _PROFILE_WIDE, event.client_ip),
            new_root_for_profile=self._first(event, "root", _PROFILE_WIDE, root),
            new_root_for_device=device is not None and self._first(event, "root", device, root),
            new_categories=tuple(
                reason.id
                for reason in event.reasons
                if self._first(event, "category", subject, reason.id)
            ),
        )

    async def flush(self) -> None:
        """Write first sightings recorded since the last flush to the database."""
        pending, self._pending = self._pending, []
        await self._reference.save_first_seen(pending)
