"""The label model: how random a registered label looks, and why short ones cannot."""

import math
from collections import Counter
from importlib import resources

import pytest

from vedette.shared import label_model
from vedette.shared.label_model import LabelModel, random_alphabet, read_counts, scorable


def toy() -> LabelModel:
    """A model that has only ever seen the label "abab"."""
    counts: Counter[str] = Counter()
    for _ in range(100):
        padded = "^^abab$"
        counts.update(padded[i - 2 : i + 1] for i in range(2, len(padded)))
    return LabelModel(counts)


def test_a_label_the_model_has_seen_costs_few_bits() -> None:
    model = toy()

    assert model.bits("abab") < 3.0
    assert model.bits("zqzq") > 20.0


def test_randomness_compares_the_model_with_random_characters() -> None:
    model = toy()
    label = "zqxw"

    assert model.randomness(label) == pytest.approx(model.bits(label) - 4 * math.log2(26))


def test_every_probability_is_smoothed_so_no_label_costs_infinitely_much() -> None:
    assert math.isfinite(toy().bits("0-9z" * 10))


@pytest.mark.parametrize(
    ("label", "size"),
    [
        ("3f9a1c0e", 16),
        ("deadbeef", 26),
        ("12345678", 36),
        ("abc123xyz", 36),
        ("abc-xyz", 37),
    ],
)
def test_the_random_explanation_uses_the_smallest_fitting_alphabet(label: str, size: int) -> None:
    assert random_alphabet(label) == size


@pytest.mark.parametrize(
    ("label", "ok"),
    [("example", True), ("", False), ("xn--80ak6aa92e", False), ("under_score", False)],
)
def test_only_plain_labels_are_scored(label: str, ok: bool) -> None:
    assert scorable(label) is ok
    if not ok:
        assert toy().randomness(label) == 0.0


def test_a_trigram_count_must_be_three_characters() -> None:
    with pytest.raises(ValueError, match="not a trigram"):
        LabelModel({"ab": 3})


def test_the_packaged_model_names_the_list_it_was_built_from() -> None:
    data = resources.files("vedette.shared").joinpath("data", label_model.DATA_FILE).read_bytes()

    meta, counts = read_counts(data)

    assert meta["source"] == "Tranco list V354N"
    assert meta["labels"] > 800_000
    assert all(len(key) == 3 for key in counts)


@pytest.mark.parametrize(
    "label",
    ["google", "facebook", "microsoftdownloader", "elektroheizung-direkt", "onlinestopwatch"],
)
def test_real_domain_labels_read_as_words(label: str) -> None:
    assert label_model.packaged().randomness(label) < 0


@pytest.mark.parametrize("label", ["qx7vk2pzm9lt", "xkq7vbn2mtrp9zlw", "3f9a1c0e7b2d4f6a"])
def test_random_labels_score_far_above_the_rule_threshold(label: str) -> None:
    assert label_model.packaged().randomness(label) > 20


def test_a_longer_random_label_gives_more_evidence_than_a_short_one() -> None:
    model = label_model.packaged()

    assert model.randomness("kqzxvt") < 20 < model.randomness("kqzxvtpwmrhjbn")


def test_a_label_repeating_two_letters_is_not_random() -> None:
    assert label_model.packaged().randomness("aaaaaaaabbbbbbbb") < 20
