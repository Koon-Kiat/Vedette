"""Known-good roots that domain rules must not flag."""

from collections.abc import Mapping, Sequence

from vedette.shared.models import AllowlistEntry


class Allowlist:
    """Answers whether a query is covered by an allowlist entry."""

    def __init__(
        self, entries: Sequence[AllowlistEntry], *, labels: Mapping[str, str] | None = None
    ) -> None:
        """Create an allowlist.

        Args:
            entries: The allowlisted roots.
            labels: Profile id to label, so entries may name either.
        """
        self._entries = tuple(entries)
        self._labels = dict(labels or {})

    def replace(self, entries: Sequence[AllowlistEntry]) -> None:
        """Swap in a new set of entries (configured plus stored ones)."""
        self._entries = tuple(entries)

    def allows(self, profile_id: str, device_id: str | None, fqdn: str, root: str | None) -> bool:
        """Return ``True`` if an entry covers this name for this profile and device."""
        for entry in self._entries:
            if entry.profile is not None and entry.profile not in (
                profile_id,
                self._labels.get(profile_id),
            ):
                continue
            if entry.device is not None and entry.device != device_id:
                continue
            if fqdn == entry.root or root == entry.root or fqdn.endswith("." + entry.root):
                return True
        return False
