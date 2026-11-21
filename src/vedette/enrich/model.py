"""The enriched event handed from the enricher to the rule engine."""

from pydantic import BaseModel, ConfigDict

from vedette.enrich.lexical import LexicalFeatures
from vedette.sources.base import DnsEvent


class EnrichedEvent(BaseModel):
    """A DNS event plus the local context the rules need.

    Attributes:
        event: The original event.
        lexical: Lexical features of the queried name.
        popularity_rank: Rank of the root in the top-sites list, ``None`` if absent.
        platform_rank: Best rank among the root's parent domains. Set when the
            name is a customer hostname on a popular platform (a cloud or CDN
            provider), which NextDNS reports as a root of its own.
        platform: Whether the root is a customer name on a hosting platform, from
            the Public Suffix List; ``None`` when no list is loaded, in which case
            a ranked parent (``platform_rank``) stands in. Read ``is_platform``.
        popularity_known: ``False`` when no top-sites list is loaded, in which
            case a missing rank says nothing and "unpopular" rules stay quiet.
        domain_age_days: Days since the root was registered; ``None`` = unknown.
        threat_feeds: Names of threat-intel feeds listing the name or a parent.
        threat_match: The listed domain that matched.
        new_device: First event ever from this device id on the profile.
        new_client_ip: First event ever from this client IP on the profile.
        new_root_for_profile: First query for this root on the profile.
        new_root_for_device: First query for this root from this device.
        new_categories: Reason ids this device (or profile) never produced before.
    """

    model_config = ConfigDict(frozen=True)

    event: DnsEvent
    lexical: LexicalFeatures
    popularity_rank: int | None = None
    platform_rank: int | None = None
    platform: bool | None = None
    popularity_known: bool = False
    domain_age_days: int | None = None
    threat_feeds: tuple[str, ...] = ()
    threat_match: str | None = None
    new_device: bool = False
    new_client_ip: bool = False
    new_root_for_profile: bool = False
    new_root_for_device: bool = False
    new_categories: tuple[str, ...] = ()

    @property
    def is_platform(self) -> bool:
        """Whether the root is a platform customer name, not a registered domain."""
        return self.platform if self.platform is not None else self.platform_rank is not None
