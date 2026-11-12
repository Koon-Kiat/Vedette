"""Known-good roots that domain rules must not flag."""

from collections.abc import Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AllowlistEntry(BaseModel):
    """One allowlisted root, optionally limited to a profile or a device.

    Attributes:
        root: Domain to allow; its subdomains are allowed too.
        profile: Profile id or label the entry applies to; all profiles if unset.
        device: Device id the entry applies to; all devices if unset.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    root: str = Field(min_length=1)
    profile: str | None = None
    device: str | None = None

    @field_validator("root")
    @classmethod
    def _normalise(cls, value: str) -> str:
        return value.strip().lower().strip(".")


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
