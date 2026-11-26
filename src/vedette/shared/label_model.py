"""How random a domain label looks, measured against real domain labels.

Raw Shannon entropy cannot judge a short label: a label of n characters holds
at most log2(n) bits per character, so a 12-character random label rarely
reaches a fixed threshold. This score compares two explanations of the label
instead. One is a character model of real registered labels (which letter
tends to follow which two), trained on a popularity list; the other is random
characters drawn evenly from the smallest alphabet the label uses (hex digits,
letters, letters and digits, or all three plus hyphens). The score is how many
bits more likely the random explanation is. Every character adds evidence, so a
longer label can reach a threshold that a short one cannot, which is the
length-awareness entropy lacks.

The trigram counts are packaged with the code and built by
``tools/label_model.py`` from a pinned list, so a score never changes between
runs or machines.
"""

import gzip
import json
import math
import string
from collections import Counter
from collections.abc import Mapping
from functools import cache
from importlib import resources
from typing import Any

#: Characters a registered label may hold; any other is not scored.
ALPHABET = string.ascii_lowercase + string.digits + "-"
START = "^"
END = "$"
#: What may follow a context: any label character, or the end of the label.
_OUTCOMES = len(ALPHABET) + 1
#: Pseudo-counts that blend each order with the one below it.
_BIGRAM_WEIGHT = 0.5 * _OUTCOMES
_TRIGRAM_WEIGHT = 2.0
_DIGITS = frozenset(string.digits)
_HEX = frozenset("0123456789abcdef")
_LETTERS = frozenset(string.ascii_lowercase)
_ALNUM = frozenset(string.ascii_lowercase + string.digits)
_SCORED = frozenset(ALPHABET)
DATA_FILE = "label_trigrams.json.gz"


def random_alphabet(label: str) -> int:
    """Size of the alphabet random characters would be drawn from to give ``label``.

    Hex digits when the label mixes digits with the letters a to f and nothing
    else, as a hash written out does. Otherwise the smallest of letters,
    letters and digits, or all of them with hyphens that holds every
    character. Letters alone never count as hex, or a label repeating one or
    two of a to f would look like random hex.
    """
    chars = set(label)
    if chars <= _HEX and chars & _DIGITS and chars - _DIGITS:
        return len(_HEX)
    for alphabet in (_LETTERS, _ALNUM):
        if chars <= alphabet:
            return len(alphabet)
    return len(ALPHABET)


def scorable(label: str) -> bool:
    """Whether ``label`` can be scored: label characters only, and not punycode.

    An internationalised label (``xn--``) is an encoding of Unicode text, so
    its ASCII form looks random whatever it says.
    """
    return bool(label) and set(label) <= _SCORED and not label.startswith("xn--")


class LabelModel:
    """A character trigram model of registered domain labels."""

    def __init__(self, trigrams: Mapping[str, int]) -> None:
        """Build the model from trigram counts.

        Args:
            trigrams: Counts keyed by three characters: two of context, then
                the character that followed. Labels are padded with two
                ``^`` in front and one ``$`` behind.
        """
        self._tri: dict[str, Counter[str]] = {}
        self._bi: dict[str, Counter[str]] = {}
        self._uni: Counter[str] = Counter()
        for key, count in trigrams.items():
            if len(key) != 3 or count <= 0:
                raise ValueError(f"not a trigram count: {key!r}")
            self._tri.setdefault(key[:2], Counter())[key[2]] += count
            self._bi.setdefault(key[1], Counter())[key[2]] += count
            self._uni[key[2]] += count
        self._tri_total = {context: row.total() for context, row in self._tri.items()}
        self._bi_total = {context: row.total() for context, row in self._bi.items()}
        self._uni_total = self._uni.total()

    def _unigram(self, char: str) -> float:
        return (self._uni[char] + 1) / (self._uni_total + _OUTCOMES)

    def _bigram(self, previous: str, char: str) -> float:
        row = self._bi.get(previous)
        seen, total = (row[char], self._bi_total[previous]) if row else (0, 0)
        return (seen + _BIGRAM_WEIGHT * self._unigram(char)) / (total + _BIGRAM_WEIGHT)

    def _trigram(self, context: str, char: str) -> float:
        row = self._tri.get(context)
        seen, total = (row[char], self._tri_total[context]) if row else (0, 0)
        return (seen + _TRIGRAM_WEIGHT * self._bigram(context[1], char)) / (total + _TRIGRAM_WEIGHT)

    def bits(self, label: str) -> float:
        """Bits the model needs to describe ``label``, its end included."""
        padded = START * 2 + label + END
        return -sum(
            math.log2(self._trigram(padded[i - 2 : i], padded[i])) for i in range(2, len(padded))
        )

    def randomness(self, label: str) -> float:
        """Bits by which random characters explain ``label`` better than the model does.

        Positive means the label looks more like random characters than like a
        registered domain label; ``0.0`` for a label that cannot be scored.
        """
        if not scorable(label):
            return 0.0
        return self.bits(label) - len(label) * math.log2(random_alphabet(label))


def read_counts(data: bytes) -> tuple[dict[str, Any], dict[str, int]]:
    """The metadata and trigram counts from a packaged model file."""
    loaded = json.loads(gzip.decompress(data))
    return dict(loaded["meta"]), {str(key): int(value) for key, value in loaded["trigrams"].items()}


@cache
def packaged() -> LabelModel:
    """The model packaged with the code, loaded once."""
    data = resources.files("vedette.shared").joinpath("data", DATA_FILE).read_bytes()
    return LabelModel(read_counts(data)[1])
