"""Builds the label model that the dga-like rule scores names with.

Counts character trigrams in the registered labels of a pinned Tranco list
(popular registered domains, combined from five providers over 30 days), and
writes them to ``src/vedette/shared/data/label_trigrams.json.gz``. One domain in
ten, picked by a hash of its name, is kept out of the counts. The tool then
prints how often each threshold flags those kept-out labels and random ones,
which is how ``min_randomness`` in ``rules.yaml`` was chosen.

Run it only to retrain; its output is committed:

    docker compose --profile dev run --rm dev python tools/label_model.py

Tranco: Le Pochat et al., "Tranco: A Research-Oriented Top Sites Ranking
Hardened Against Manipulation", NDSS 2019. https://tranco-list.eu/
"""

import argparse
import gzip
import hashlib
import json
import random
import string
import sys
import urllib.request
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path

from vedette.shared.label_model import END, START, LabelModel, scorable

LIST_ID = "V354N"
LIST_URL = "https://tranco-list.eu/download/{list_id}/1000000"
OUTPUT = Path(__file__).resolve().parents[1] / "src/vedette/shared/data/label_trigrams.json.gz"
THRESHOLDS = (10, 12, 14, 16, 18, 20, 22, 24, 26)
MIN_LENGTH = 8
SEED = 20261126


def kept_out(domain: str) -> bool:
    """Whether ``domain`` is one of the one in ten kept out of the counts."""
    return int(hashlib.sha256(domain.encode()).hexdigest(), 16) % 10 == 0


def split(rows: Iterable[str]) -> tuple[list[str], list[str]]:
    """Registered labels from ``rank,domain`` rows: those counted, and those kept out.

    The list holds registered domains, so the first label of each is the one
    left of its public suffix. Labels that cannot be scored are skipped.
    """
    counted: list[str] = []
    held: list[str] = []
    for row in rows:
        domain = row.strip().lower().partition(",")[2]
        label = domain.split(".", 1)[0]
        if scorable(label):
            (held if kept_out(domain) else counted).append(label)
    return counted, held


def trigrams(labels: Iterable[str]) -> Counter[str]:
    """Trigram counts over labels padded with two starts and one end."""
    counts: Counter[str] = Counter()
    for label in labels:
        padded = START * 2 + label + END
        counts.update(padded[i - 2 : i + 1] for i in range(2, len(padded)))
    return counts


def encode(counts: Counter[str], meta: dict[str, object]) -> bytes:
    """The model file: the same counts always give the same bytes."""
    body = json.dumps({"meta": meta, "trigrams": dict(sorted(counts.items()))}, sort_keys=True)
    return gzip.compress(body.encode(), compresslevel=9, mtime=0)


def random_labels(rng: random.Random, alphabet: str, count: int) -> list[str]:
    """Labels of 8 to 20 characters drawn evenly from ``alphabet``."""
    return [
        "".join(rng.choice(alphabet) for _ in range(rng.randint(MIN_LENGTH, 20)))
        for _ in range(count)
    ]


def _share(values: Sequence[float], threshold: float) -> float:
    """The share of ``values`` at or above ``threshold``; 0 for none."""
    return sum(value >= threshold for value in values) / len(values) if values else 0.0


def calibration(model: LabelModel, held: Sequence[str]) -> list[str]:
    """How often each threshold flags kept-out labels and random ones."""
    rng = random.Random(SEED)  # noqa: S311 - reproducible test data, not security
    sets = {
        "random letters": random_labels(rng, string.ascii_lowercase, 3000),
        "random letters and digits": random_labels(
            rng, string.ascii_lowercase + string.digits, 3000
        ),
    }
    benign = [model.randomness(label) for label in held if len(label) >= MIN_LENGTH]
    scored = {name: [model.randomness(label) for label in labels] for name, labels in sets.items()}
    lines = [
        f"Kept-out labels of {MIN_LENGTH}+ characters: {len(benign)}",
        "threshold  kept-out flagged  " + "  ".join(f"{name} flagged" for name in sets),
    ]
    for threshold in THRESHOLDS:
        row = [f"{threshold:9}", f"{_share(benign, threshold):16.2%}"]
        row += [
            f"{_share(values, threshold):{len(name) + 8}.1%}" for name, values in scored.items()
        ]
        lines.append("  ".join(row))
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    """Download the pinned list, count trigrams, write the model and print the calibration."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list-id", default=LIST_ID, help="Tranco list id to train on.")
    parser.add_argument("--source", type=Path, help="A local copy of that list (rank,domain).")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    url = LIST_URL.format(list_id=args.list_id)
    if args.source is not None:
        text = args.source.read_text(encoding="utf-8")
    else:
        with urllib.request.urlopen(url, timeout=300) as response:  # noqa: S310 - fixed https URL
            text = response.read().decode("utf-8")
    counted, held = split(text.splitlines())
    counts = trigrams(counted)
    meta: dict[str, object] = {
        "source": f"Tranco list {args.list_id}",
        "url": url,
        "labels": len(counted),
        "kept_out": len(held),
        "note": "built by tools/label_model.py; one domain in ten (by hash) kept out",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encode(counts, meta))
    sys.stdout.write(f"Wrote {args.output} from {len(counted)} labels ({len(counts)} trigrams).\n")
    sys.stdout.write("\n".join(calibration(LabelModel(counts), held)) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
