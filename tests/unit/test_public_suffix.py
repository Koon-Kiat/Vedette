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


def test_an_empty_list_knows_no_platforms() -> None:
    assert SuffixRules([]).platform_suffix("customer.github.io") is None
