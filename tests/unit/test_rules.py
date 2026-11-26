"""Every detection rule: fire and no-fire cases, with and without device attribution.

``device`` is ``"D1"`` when NextDNS reports the device and ``None`` when it does
not (a router profile); in the second mode rules key on the profile.
"""

from datetime import timedelta
from typing import Any

import pytest

from tests.unit.rule_helpers import HOME_IP, PROFILE, engine, enriched, event, fired
from vedette.rules.loader import load_rules
from vedette.shared.models import AllowlistEntry, Finding, Severity

MODES = [pytest.param("D1", id="device-attributed"), pytest.param(None, id="profile-only")]
RANDOM_LABEL = "xkq7vbn2mtrp9zlw"


def check_mode(finding: Finding, device: str | None) -> None:
    assert finding.profile_id == PROFILE
    assert finding.subject == device
    assert finding.device_mode is (device is not None)


# --- new-device ---------------------------------------------------------------


def test_new_device_fires_for_an_unseen_device_id() -> None:
    findings = engine().evaluate(enriched(event(device="D9"), new_device=True))

    (finding,) = fired(findings, "new-device")
    assert finding.severity is Severity.MEDIUM
    assert finding.target == "D9"
    assert finding.evidence["device_name"] == "Device D9"
    check_mode(finding, "D9")


def test_new_device_fires_for_an_unseen_client_ip_when_devices_are_not_reported() -> None:
    findings = engine().evaluate(
        enriched(event(device=None, client_ip="203.0.113.9"), new_client_ip=True)
    )

    (finding,) = fired(findings, "new-device")
    assert finding.target == "203.0.113.9"
    assert finding.evidence["attribution"] == "unavailable"
    check_mode(finding, None)


@pytest.mark.parametrize("device", MODES)
def test_new_device_does_not_fire_for_known_devices_and_addresses(device: str | None) -> None:
    assert fired(engine().evaluate(enriched(event(device=device))), "new-device") == []


def test_new_device_ignores_a_new_address_when_the_device_itself_is_known() -> None:
    findings = engine().evaluate(enriched(event(device="D1"), new_client_ip=True))

    assert fired(findings, "new-device") == []


@pytest.mark.parametrize("device", MODES)
def test_new_device_is_quiet_while_the_profile_is_still_being_learned(device: str | None) -> None:
    rules = engine(learning=timedelta(days=3))
    rules.evaluate(enriched(event(device=device)))  # first event starts the learning period
    during = enriched(
        event(device=device, at=timedelta(days=1)), new_device=True, new_client_ip=True
    )
    after = enriched(
        event(device=device, at=timedelta(days=4)), new_device=True, new_client_ip=True
    )

    assert fired(rules.evaluate(during), "new-device") == []
    assert len(fired(rules.evaluate(after), "new-device")) == 1


# --- young-domain -------------------------------------------------------------


def young(device: str | None, **overrides: Any) -> Any:
    values: dict[str, Any] = {"popularity_rank": None, "domain_age_days": 5}
    values.update(overrides)
    status = values.pop("status", "default")
    return enriched(
        event(
            fqdn="login.fresh-site.example", root="fresh-site.example", device=device, status=status
        ),
        **values,
    )


@pytest.mark.parametrize("device", MODES)
def test_young_domain_fires_for_an_allowed_recently_registered_unpopular_root(
    device: str | None,
) -> None:
    (finding,) = fired(engine().evaluate(young(device)), "young-domain")

    assert finding.severity is Severity.HIGH
    assert finding.target == "fresh-site.example"
    assert finding.evidence["domain_age_days"] == 5
    check_mode(finding, device)


@pytest.mark.parametrize("device", MODES)
@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"domain_age_days": 30}, id="thirty-days-old"),
        pytest.param({"domain_age_days": None}, id="age-unknown"),
        pytest.param({"status": "blocked"}, id="blocked"),
        pytest.param({"popularity_rank": 5000}, id="popular"),
        pytest.param({"popularity_known": False}, id="popularity-list-unavailable"),
    ],
)
def test_young_domain_does_not_fire(device: str | None, overrides: dict[str, Any]) -> None:
    assert fired(engine().evaluate(young(device, **overrides)), "young-domain") == []


@pytest.mark.parametrize("device", MODES)
def test_young_domain_respects_the_allowlist(device: str | None) -> None:
    rules = engine(allow=(AllowlistEntry(root="fresh-site.example"),))

    assert fired(rules.evaluate(young(device)), "young-domain") == []


# --- threat-intel-allowed -----------------------------------------------------


def listed(device: str | None, **overrides: Any) -> Any:
    values: dict[str, Any] = {
        "popularity_rank": None,
        "threat_feeds": ("phishing_army",),
        "threat_match": "bad.example",
    }
    values.update(overrides)
    status = values.pop("status", "default")
    return enriched(
        event(fqdn="pay.bad.example", root="bad.example", device=device, status=status), **values
    )


@pytest.mark.parametrize("device", MODES)
def test_threat_intel_fires_when_an_allowed_domain_is_on_a_feed(device: str | None) -> None:
    (finding,) = fired(engine().evaluate(listed(device)), "threat-intel-allowed")

    assert finding.severity is Severity.CRITICAL
    assert finding.target == "bad.example"
    assert finding.evidence["threat_feeds"] == ["phishing_army"]
    check_mode(finding, device)


@pytest.mark.parametrize("device", MODES)
@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"threat_feeds": (), "threat_match": None}, id="not-listed"),
        pytest.param({"status": "blocked"}, id="blocked"),
        pytest.param({"popularity_rank": 50}, id="top-site-so-feed-entry-distrusted"),
    ],
)
def test_threat_intel_does_not_fire(device: str | None, overrides: dict[str, Any]) -> None:
    assert fired(engine().evaluate(listed(device, **overrides)), "threat-intel-allowed") == []


@pytest.mark.parametrize("device", MODES)
def test_threat_intel_respects_the_allowlist(device: str | None) -> None:
    rules = engine(allow=(AllowlistEntry(root="bad.example"),))

    assert fired(rules.evaluate(listed(device)), "threat-intel-allowed") == []


# --- dga-like -----------------------------------------------------------------


def dga(
    device: str | None, label: str = RANDOM_LABEL, *, prefix: str = "", **overrides: Any
) -> Any:
    """A lookup under the root ``<label>.example``, with ``prefix`` in front of it."""
    values: dict[str, Any] = {"popularity_rank": None}
    values.update(overrides)
    status = values.pop("status", "default")
    root = values.pop("root", f"{label}.example")
    return enriched(
        event(fqdn=f"{prefix}{root}", root=root, device=device, status=status), **values
    )


@pytest.mark.parametrize("device", MODES)
def test_dga_like_fires_for_a_random_registered_label_on_an_unpopular_root(
    device: str | None,
) -> None:
    (finding,) = fired(engine().evaluate(dga(device)), "dga-like")

    assert finding.severity is Severity.MEDIUM
    assert finding.target == f"{RANDOM_LABEL}.example"
    assert finding.evidence["label"] == RANDOM_LABEL
    assert finding.evidence["label_length"] == len(RANDOM_LABEL)
    assert finding.evidence["randomness"] >= 20
    assert "entropy" not in finding.evidence
    check_mode(finding, device)


@pytest.mark.parametrize("prefix", ["www.", "mail.", "cdn.static."])
def test_dga_like_judges_the_registered_label_behind_a_prefix(prefix: str) -> None:
    (finding,) = fired(engine().evaluate(dga("D1", prefix=prefix)), "dga-like")

    assert finding.evidence["fqdn"] == f"{prefix}{RANDOM_LABEL}.example"
    assert finding.evidence["label"] == RANDOM_LABEL


def test_dga_like_leaves_a_random_subdomain_of_a_word_domain_to_the_tunnel_rules() -> None:
    item = dga("D1", prefix=f"{RANDOM_LABEL}.", root="harbour-dental.example")

    assert fired(engine().evaluate(item), "dga-like") == []


@pytest.mark.parametrize("device", MODES)
@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        pytest.param("xkq7vbn", {}, id="short-label"),
        pytest.param("aaaaaaaabbbbbbbb", {}, id="repeated-letters"),
        pytest.param("elektroheizung-direkt", {}, id="words"),
        pytest.param("xn--80ak6aa92e", {}, id="punycode"),
        pytest.param(RANDOM_LABEL, {"popularity_rank": 800}, id="popular-root"),
        pytest.param(RANDOM_LABEL, {"popularity_known": False}, id="popularity-list-unavailable"),
        pytest.param(RANDOM_LABEL, {"status": "blocked"}, id="blocked"),
    ],
)
def test_dga_like_does_not_fire(device: str | None, label: str, overrides: dict[str, Any]) -> None:
    assert fired(engine().evaluate(dga(device, label, **overrides)), "dga-like") == []


@pytest.mark.parametrize("device", MODES)
def test_dga_like_respects_the_allowlist(device: str | None) -> None:
    rules = engine(allow=(AllowlistEntry(root=f"{RANDOM_LABEL}.example"),))

    assert fired(rules.evaluate(dga(device)), "dga-like") == []


# --- tunnel-like --------------------------------------------------------------


def tunnel_query(n: int, device: str | None, *, at: timedelta, long: bool = True, **kw: Any) -> Any:
    label = f"{n:04d}{'a1b2c3d4e5' * 3}" if long else f"h{n}"
    return enriched(
        event(fqdn=f"{label}.tun.example", root="tun.example", device=device, at=at, n=n),
        popularity_rank=kw.get("rank"),
    )


def run_tunnel(
    rules: Any, count: int, device: str | None, *, step: timedelta, **kw: Any
) -> list[Finding]:
    findings: list[Finding] = []
    for n in range(count):
        findings += fired(rules.evaluate(tunnel_query(n, device, at=step * n, **kw)), "tunnel-like")
    return findings


@pytest.mark.parametrize("device", MODES)
def test_tunnel_like_fires_once_more_than_n_unique_long_subdomains_appear_in_the_window(
    device: str | None,
) -> None:
    findings = run_tunnel(engine(), 31, device, step=timedelta(seconds=5))

    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].target == "tun.example"
    assert findings[0].evidence["unique_subdomains"] == 31
    check_mode(findings[0], device)


@pytest.mark.parametrize("device", MODES)
def test_tunnel_like_does_not_fire_at_exactly_n(device: str | None) -> None:
    assert run_tunnel(engine(), 30, device, step=timedelta(seconds=5)) == []


@pytest.mark.parametrize("device", MODES)
def test_tunnel_like_does_not_fire_when_spread_beyond_the_window(device: str | None) -> None:
    assert run_tunnel(engine(), 60, device, step=timedelta(seconds=30)) == []


@pytest.mark.parametrize("device", MODES)
def test_tunnel_like_ignores_short_subdomains(device: str | None) -> None:
    assert run_tunnel(engine(), 60, device, step=timedelta(seconds=5), long=False) == []


@pytest.mark.parametrize("device", MODES)
def test_tunnel_like_ignores_repeats_of_the_same_name(device: str | None) -> None:
    rules = engine()
    findings: list[Finding] = []
    for n in range(100):
        findings += fired(
            rules.evaluate(tunnel_query(7, device, at=timedelta(seconds=n))), "tunnel-like"
        )

    assert findings == []


@pytest.mark.parametrize("device", MODES)
def test_tunnel_like_ignores_very_popular_roots(device: str | None) -> None:
    assert run_tunnel(engine(), 60, device, step=timedelta(seconds=5), rank=50) == []


@pytest.mark.parametrize("device", MODES)
def test_tunnel_like_respects_the_allowlist(device: str | None) -> None:
    rules = engine(allow=(AllowlistEntry(root="tun.example"),))

    assert run_tunnel(rules, 60, device, step=timedelta(seconds=5)) == []


def spread_over_devices(reported: bool) -> list[Finding]:
    """40 unique long names, split evenly over two devices."""
    rules = engine()
    findings: list[Finding] = []
    for n in range(40):
        device = f"D{n % 2}" if reported else None
        findings += fired(
            rules.evaluate(tunnel_query(n, device, at=timedelta(seconds=n))), "tunnel-like"
        )
    return findings


def test_tunnel_like_counts_each_reported_device_separately() -> None:
    assert spread_over_devices(reported=True) == []


def test_tunnel_like_counts_the_whole_profile_when_devices_are_not_reported() -> None:
    assert len(spread_over_devices(reported=False)) == 1


# --- volume-spike -------------------------------------------------------------


def feed_hours(rules: Any, device: str | None, hours: int, per_hour: int) -> None:
    """Warm the baseline with ``hours`` past hours of ``per_hour`` queries each."""
    for hour in range(hours):
        for n in range(per_hour):
            at = timedelta(hours=hour - hours, seconds=n)
            rules.observe(event(device=device, at=at, n=n))


def burst(rules: Any, device: str | None, count: int) -> list[Finding]:
    findings: list[Finding] = []
    for n in range(count):
        item = enriched(event(device=device, at=timedelta(seconds=n), n=n))
        findings += fired(rules.evaluate(item), "volume-spike")
    return findings


@pytest.mark.parametrize("device", MODES)
def test_volume_spike_fires_when_an_hour_reaches_the_factor_times_the_baseline(
    device: str | None,
) -> None:
    rules = engine()
    feed_hours(rules, device, hours=30, per_hour=50)

    findings = burst(rules, device, 250)

    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert findings[0].evidence["queries_this_hour"] == 250
    assert findings[0].evidence["baseline_per_hour"] == 50.0
    check_mode(findings[0], device)


@pytest.mark.parametrize("device", MODES)
def test_volume_spike_does_not_fire_just_below_the_factor(device: str | None) -> None:
    rules = engine()
    feed_hours(rules, device, hours=30, per_hour=50)

    assert burst(rules, device, 249) == []


@pytest.mark.parametrize("device", MODES)
def test_volume_spike_needs_enough_baseline_hours(device: str | None) -> None:
    rules = engine()
    feed_hours(rules, device, hours=10, per_hour=50)

    assert burst(rules, device, 400) == []


@pytest.mark.parametrize("device", MODES)
def test_volume_spike_ignores_small_absolute_volumes(device: str | None) -> None:
    rules = engine()
    feed_hours(rules, device, hours=30, per_hour=2)

    assert burst(rules, device, 150) == []


def test_volume_spike_baseline_is_per_device_when_devices_are_reported() -> None:
    rules = engine()
    feed_hours(rules, "D1", hours=30, per_hour=50)

    assert burst(rules, "D2", 400) == [], "D2 has no baseline of its own yet"


# --- blocked-burst ------------------------------------------------------------


def blocked_run(
    rules: Any, device: str | None, count: int, *, step: timedelta, status: str = "blocked"
) -> list[Finding]:
    findings: list[Finding] = []
    for n in range(count):
        item = enriched(
            event(
                fqdn=f"ad{n}.ads.example",
                root="ads.example",
                device=device,
                status=status,
                at=step * n,
                n=n,
            )
        )
        findings += fired(rules.evaluate(item), "blocked-burst")
    return findings


def test_blocked_burst_fires_for_a_device_at_the_device_threshold() -> None:
    findings = blocked_run(engine(), "D1", 50, step=timedelta(seconds=2))

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].evidence["blocked_in_window"] == 50
    check_mode(findings[0], "D1")


def test_blocked_burst_does_not_fire_for_a_device_below_the_threshold() -> None:
    assert blocked_run(engine(), "D1", 49, step=timedelta(seconds=2)) == []


def test_blocked_burst_uses_the_higher_profile_threshold_without_device_data() -> None:
    assert blocked_run(engine(), None, 199, step=timedelta(seconds=1)) == []

    findings = blocked_run(engine(), None, 200, step=timedelta(seconds=1))

    assert len(findings) == 1
    assert findings[0].evidence["blocked_in_window"] == 200
    check_mode(findings[0], None)


@pytest.mark.parametrize("device", MODES)
def test_blocked_burst_does_not_fire_when_spread_beyond_the_window(device: str | None) -> None:
    assert blocked_run(engine(), device, 400, step=timedelta(seconds=30)) == []


@pytest.mark.parametrize("device", MODES)
def test_blocked_burst_ignores_queries_that_were_not_blocked(device: str | None) -> None:
    assert blocked_run(engine(), device, 400, step=timedelta(seconds=1), status="default") == []


# --- new-destination-category ---------------------------------------------------


@pytest.mark.parametrize("device", MODES)
def test_new_category_fires_once_per_category_first_used(device: str | None) -> None:
    item = enriched(
        event(device=device, status="blocked", reasons=(("blocklist:gambling", "Gambling"),)),
        new_categories=("blocklist:gambling", "blocklist:malware"),
    )

    findings = fired(engine().evaluate(item), "new-destination-category")

    assert [finding.target for finding in findings] == ["blocklist:gambling", "blocklist:malware"]
    assert findings[0].severity is Severity.LOW
    assert findings[0].evidence["category_name"] == "Gambling"
    check_mode(findings[0], device)


@pytest.mark.parametrize("device", MODES)
def test_new_category_does_not_fire_for_categories_already_used(device: str | None) -> None:
    item = enriched(event(device=device, reasons=(("blocklist:gambling", "Gambling"),)))

    assert fired(engine().evaluate(item), "new-destination-category") == []


@pytest.mark.parametrize("device", MODES)
def test_new_category_is_quiet_while_the_profile_is_still_being_learned(device: str | None) -> None:
    rules = engine(learning=timedelta(days=3))
    item = enriched(event(device=device), new_categories=("blocklist:gambling",))

    assert fired(rules.evaluate(item), "new-destination-category") == []


# --- behaviour shared by all rules ------------------------------------------------


def test_the_rule_file_defines_exactly_the_ten_rules_with_their_severity_floors() -> None:
    assert {spec.id: spec.severity for spec in load_rules()} == {
        "new-device": Severity.MEDIUM,
        "young-domain": Severity.HIGH,
        "threat-intel-allowed": Severity.CRITICAL,
        "dga-like": Severity.MEDIUM,
        "tunnel-like": Severity.HIGH,
        "tunnel-slow": Severity.MEDIUM,
        "dga-burst": Severity.MEDIUM,
        "volume-spike": Severity.LOW,
        "blocked-burst": Severity.MEDIUM,
        "new-destination-category": Severity.LOW,
    }


def test_every_rule_explains_why_it_matters() -> None:
    for spec in load_rules():
        assert len(spec.description) > 40, spec.id
        assert spec.evidence, spec.id


def test_a_benign_event_produces_no_findings() -> None:
    assert engine().evaluate(enriched()) == []


def test_a_disabled_rule_does_not_fire() -> None:
    assert engine(disabled=("young-domain",)).evaluate(young("D1")) == []


def test_thresholds_come_from_the_rule_parameters() -> None:
    rules = engine(params={"young-domain": {"max_age_days": 3}})

    assert fired(rules.evaluate(young("D1")), "young-domain") == []


def test_evidence_contains_only_the_fields_the_rule_declares() -> None:
    declared = {spec.id: set(spec.evidence) for spec in load_rules()}
    findings = engine().evaluate(young("D1")) + engine().evaluate(listed(None))

    assert findings
    for finding in findings:
        assert set(finding.evidence) <= declared[finding.rule_id]


def test_same_root_on_the_same_day_shares_a_dedupe_key_and_a_new_day_does_not() -> None:
    rules = engine()
    day_one = fired(rules.evaluate(young("D1")), "young-domain")[0]
    again = fired(rules.evaluate(young("D1")), "young-domain")[0]
    later = enriched(
        event(fqdn="x.fresh-site.example", root="fresh-site.example", at=timedelta(days=1)),
        popularity_rank=None,
        domain_age_days=6,
    )
    day_two = fired(rules.evaluate(later), "young-domain")[0]

    assert day_one.dedupe_key == again.dedupe_key
    assert day_one.dedupe_key != day_two.dedupe_key


def test_dedupe_keys_separate_devices_and_profile_only_findings() -> None:
    keys = {
        fired(engine().evaluate(young(device)), "young-domain")[0].dedupe_key
        for device in ("D1", "D2", None)
    }

    assert len(keys) == 3


def test_allowlist_entries_can_be_limited_to_a_profile_or_a_device() -> None:
    other_profile = engine(allow=(AllowlistEntry(root="fresh-site.example", profile="phone"),))
    this_profile = engine(allow=(AllowlistEntry(root="fresh-site.example", profile="router"),))
    other_device = engine(allow=(AllowlistEntry(root="fresh-site.example", device="D2"),))
    this_device = engine(allow=(AllowlistEntry(root="fresh-site.example", device="D1"),))

    assert fired(other_profile.evaluate(young("D1")), "young-domain")
    assert not fired(this_profile.evaluate(young("D1")), "young-domain")
    assert fired(other_device.evaluate(young("D1")), "young-domain")
    assert not fired(this_device.evaluate(young("D1")), "young-domain")


def test_allowlisting_a_root_covers_its_subdomains_but_not_lookalikes() -> None:
    rules = engine(allow=(AllowlistEntry(root="site.example"),))
    lookalike = enriched(
        event(fqdn="login.fresh-site.example", root="fresh-site.example"),
        popularity_rank=None,
        domain_age_days=5,
    )

    assert fired(rules.evaluate(lookalike), "young-domain")


def test_home_ip_constant_is_used_by_default() -> None:
    assert event().client_ip == HOME_IP


# --- names hosted on a platform (a customer name NextDNS reports as its own root) ---------


@pytest.mark.parametrize("device", MODES)
@pytest.mark.parametrize("platform", ["duckdns.org", "github.io", "ddns.net", "pages.dev"])
def test_dga_like_fires_for_a_random_customer_name_on_a_platform(
    device: str | None, platform: str
) -> None:
    root = f"{RANDOM_LABEL}.{platform}"
    item = dga(device, root=root, prefix="www.", platform=True, platform_rank=40)

    (finding,) = fired(engine().evaluate(item), "dga-like")

    assert finding.target == root
    assert finding.evidence["label"] == RANDOM_LABEL


@pytest.mark.parametrize(
    "root",
    [
        "d3c3cq33003psk.cloudfront.net",
        "x7kq2vbn9mtrp4zl.blob.core.windows.net",
        "ec2-k3j9x2m8q1z7.eu-central-1.compute.amazonaws.com",
        "cloudfront.net",
    ],
)
def test_dga_like_skips_platforms_that_name_their_customers_themselves(root: str) -> None:
    item = dga("D1", root=root, platform=True, platform_rank=40)

    assert fired(engine().evaluate(item), "dga-like") == []


def test_with_no_assigned_name_platforms_every_customer_name_is_judged() -> None:
    rules = engine(params={"dga-like": {"assigned_name_platforms": []}})
    item = dga("D1", root="d3c3cq33003psk.cloudfront.net", platform=True)

    assert len(fired(rules.evaluate(item), "dga-like")) == 1


@pytest.mark.parametrize("device", MODES)
def test_young_domain_does_not_fire_for_a_customer_name_on_a_popular_platform(
    device: str | None,
) -> None:
    assert fired(engine().evaluate(young(device, platform_rank=40)), "young-domain") == []


@pytest.mark.parametrize("device", MODES)
def test_tunnel_like_ignores_names_on_a_very_popular_platform(device: str | None) -> None:
    rules = engine()
    findings: list[Finding] = []
    for n in range(60):
        item = tunnel_query(n, device, at=timedelta(seconds=5 * n))
        findings += fired(
            rules.evaluate(item.model_copy(update={"platform_rank": 40})), "tunnel-like"
        )

    assert findings == []


@pytest.mark.parametrize("device", MODES)
def test_threat_intel_still_fires_for_a_listed_name_on_a_popular_platform(
    device: str | None,
) -> None:
    findings = engine().evaluate(listed(device, platform_rank=40))

    assert len(fired(findings, "threat-intel-allowed")) == 1
