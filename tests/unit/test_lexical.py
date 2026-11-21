import pytest

from vedette.enrich.lexical import lexical_features, shannon_entropy


def test_entropy_of_a_single_repeated_character_is_zero() -> None:
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_of_two_equally_likely_characters_is_one_bit() -> None:
    assert shannon_entropy("abababab") == 1.0


def test_entropy_of_four_equally_likely_characters_is_two_bits() -> None:
    assert shannon_entropy("abcdabcd") == 2.0


def test_entropy_of_an_empty_string_is_zero() -> None:
    assert shannon_entropy("") == 0.0


def test_random_looking_label_has_higher_entropy_than_a_word() -> None:
    assert shannon_entropy("xkq7vbn2mtrp9zlw") > shannon_entropy("accounts")


def test_features_describe_the_leftmost_label() -> None:
    features = lexical_features("ab12.cdn.example.org", "example.org")

    assert features.label == "ab12"
    assert features.label_length == 4
    assert features.digit_ratio == 0.5
    assert features.subdomain_depth == 2
    assert features.subdomain_length == len("ab12.cdn")


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
