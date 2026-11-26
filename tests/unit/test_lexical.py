import pytest

from vedette.shared.names import lexical_features, registered_label

RANDOM_LABEL = "xkq7vbn2mtrp9zlw"


def test_features_describe_the_registered_label_not_the_leftmost() -> None:
    features = lexical_features("ab12.cdn.example.org", "example.org")

    assert features.label == "example"
    assert features.label_length == 7
    assert features.digit_ratio == 0.0
    assert features.subdomain_depth == 2
    assert features.subdomain_length == len("ab12.cdn")


@pytest.mark.parametrize("prefix", ["", "www.", "mail.", "a.b.c."])
def test_a_prefix_in_front_of_a_random_domain_does_not_hide_it(prefix: str) -> None:
    root = f"{RANDOM_LABEL}.com"

    features = lexical_features(prefix + root, root)

    assert features.label == RANDOM_LABEL
    assert features.randomness == lexical_features(root, root).randomness
    assert features.randomness > 20


def test_a_random_subdomain_under_a_word_domain_is_not_the_label_judged() -> None:
    features = lexical_features(f"{RANDOM_LABEL}.example.org", "example.org")

    assert features.label == "example"
    assert features.randomness < 0
    assert features.subdomain_length == len(RANDOM_LABEL)


def test_a_customer_name_on_a_platform_is_judged_on_the_customer_label() -> None:
    features = lexical_features(f"www.{RANDOM_LABEL}.github.io", f"{RANDOM_LABEL}.github.io")

    assert features.label == RANDOM_LABEL
    assert features.subdomain_depth == 1


@pytest.mark.parametrize(
    ("fqdn", "root", "label"),
    [
        ("www.example.org", None, "example"),
        ("example.org", None, "example"),
        ("localhost", None, "localhost"),
        ("a.b.example.org", "other.test", "example"),
        ("shop.example.co.uk", "example.co.uk", "example"),
    ],
)
def test_the_registered_label_falls_back_to_the_second_to_last_label(
    fqdn: str, root: str | None, label: str
) -> None:
    assert registered_label(fqdn, root) == label


def test_a_bare_root_has_no_subdomain() -> None:
    features = lexical_features("example.org", "example.org")

    assert features.label == "example"
    assert features.subdomain_depth == 0
    assert features.subdomain_length == 0


@pytest.mark.parametrize(
    ("fqdn", "depth"),
    [("example.org", 0), ("www.example.org", 1), ("a.b.c.example.org", 3), ("localhost", 0)],
)
def test_depth_falls_back_to_two_label_roots_when_root_is_unknown(fqdn: str, depth: int) -> None:
    assert lexical_features(fqdn, None).subdomain_depth == depth


def test_root_that_is_not_a_suffix_of_the_name_is_ignored() -> None:
    assert lexical_features("a.b.example.org", "other.test").subdomain_depth == 2
