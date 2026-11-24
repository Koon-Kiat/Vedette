"""Reading the Public Suffix List and telling platform customer names from domains."""

import pytest

from vedette.enrich.public_suffix import SuffixRules, parse_public_suffix_list

LIST = """\
// This Source Code Form is subject to the terms of the Mozilla Public License.
// ===BEGIN ICANN DOMAINS===
com
org
uk
co.uk
// Wildcards and exceptions
*.ck
!www.ck
// Internationalised names are written in Unicode
公司.cn
cn
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
// GitHub, Inc.
github.io
// A cloud with per-region customer names
*.compute.example-cloud.com
!metadata.compute.example-cloud.com
// ===END PRIVATE DOMAINS===
"""


def test_rules_are_read_with_their_section() -> None:
    rules = dict(parse_public_suffix_list(LIST))

    assert rules["co.uk"] is False
    assert rules["github.io"] is True
    assert rules["*.compute.example-cloud.com"] is True
    assert rules["!www.ck"] is False
    assert "xn--55qx5d.cn" in rules, "Unicode rules are matched in their ASCII form"
    assert not any(rule.startswith("//") for rule in rules)


@pytest.fixture
def suffixes() -> SuffixRules:
    return SuffixRules(parse_public_suffix_list(LIST))


@pytest.mark.parametrize(
    ("name", "platform"),
    [
        ("customer.github.io", "github.io"),
        ("deep.customer.github.io", "github.io"),
        ("app.eu-west.compute.example-cloud.com", "eu-west.compute.example-cloud.com"),
        ("metadata.compute.example-cloud.com", "compute.example-cloud.com"),
        ("CUSTOMER.GitHub.IO", "github.io"),
    ],
)
def test_names_under_a_private_suffix_are_platform_customers(
    suffixes: SuffixRules, name: str, platform: str
) -> None:
    assert suffixes.platform_suffix(name) == platform


@pytest.mark.parametrize(
    "name",
    [
        "github.io",  # the platform itself, not a customer of it
        "example.com",
        "bbc.co.uk",  # registered under a multi-label public suffix
        "www.ck",  # an exception in the ICANN section
        "shop.xn--55qx5d.cn",
        "unknown-tld.zz",
        "",
    ],
)
def test_registered_domains_are_not_platform_customers(suffixes: SuffixRules, name: str) -> None:
    assert suffixes.platform_suffix(name) is None


@pytest.mark.parametrize(
    ("name", "longer"),
    [
        # NextDNS made this a root of its own, so it knows a platform under
        # "cdn-provider.com" that the list does not.
        ("abc.cdn-provider.com", True),
        ("x.y.example.org", True),
        ("example.com", False),
        ("bbc.co.uk", False),
        ("customer.github.io", False),  # exactly the registered name under github.io
        ("shop.zz", False),  # no rule: the last label stands in as the suffix
    ],
)
def test_a_root_longer_than_its_registered_domain_is_recognised(
    suffixes: SuffixRules, name: str, longer: bool
) -> None:
    assert suffixes.longer_than_registered(name) is longer


@pytest.mark.parametrize(
    ("name", "private"),
    [
        # A wildcard makes every region a suffix of its own; NextDNS reports such
        # a name as a root when a customer's name sits under it.
        ("eu-west.compute.example-cloud.com", True),
        ("github.io", True),
        ("customer.github.io", True),
        ("bbc.co.uk", False),
        ("example.com", False),
        ("shop.zz", False),
    ],
)
def test_a_name_set_by_a_private_rule_is_recognised(
    suffixes: SuffixRules, name: str, private: bool
) -> None:
    assert suffixes.under_private_rule(name) is private


def test_an_empty_list_knows_no_platforms() -> None:
    assert SuffixRules([]).platform_suffix("customer.github.io") is None


@pytest.mark.parametrize(
    ("name", "registered"),
    [
        ("events.data.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("foo.github.io", "foo.github.io"),
        ("deep.foo.github.io", "foo.github.io"),
        ("x.y.unlisted", "y.unlisted"),
        ("WWW.Example.COM.", "example.com"),
        ("github.io", None),
        ("co.uk", None),
        ("com", None),
    ],
)
def test_the_registered_domain_follows_the_list(
    suffixes: SuffixRules, name: str, registered: str | None
) -> None:
    assert suffixes.registered(name) == registered


@pytest.mark.parametrize(
    ("name", "registered"),
    [
        ("bar.ck", None),  # *.ck makes every second-level name a public suffix
        ("foo.bar.ck", "foo.bar.ck"),
        ("www.ck", "www.ck"),  # !www.ck: the exception is a registered domain
        ("a.www.ck", "www.ck"),
        ("app.eu-west.compute.example-cloud.com", "app.eu-west.compute.example-cloud.com"),
        ("eu-west.compute.example-cloud.com", None),
        ("metadata.compute.example-cloud.com", "metadata.compute.example-cloud.com"),
        ("x.metadata.compute.example-cloud.com", "metadata.compute.example-cloud.com"),
    ],
)
def test_the_registered_domain_follows_wildcard_and_exception_rules(
    suffixes: SuffixRules, name: str, registered: str | None
) -> None:
    assert suffixes.registered(name) == registered
