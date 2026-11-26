"""tools/label_model.py: building the label model from a ranked list."""

import gzip
import json
from pathlib import Path

import label_model as tool
from vedette.shared.label_model import LabelModel, read_counts

ROWS = [
    "1,google.com",
    "2,facebook.com",
    "3,xn--80ak6aa92e.com",
    "4,under_score.org",
    "5,bbc.co.uk",
    "6,example.net",
]
SCORED = ("google.com", "facebook.com", "bbc.co.uk", "example.net")


def test_labels_are_split_by_a_hash_of_the_domain() -> None:
    counted, held = tool.split(ROWS)

    assert sorted(counted + held) == ["bbc", "example", "facebook", "google"]
    assert sorted(held) == sorted(name.split(".")[0] for name in SCORED if tool.kept_out(name))


def test_trigrams_pad_each_label_with_two_starts_and_an_end() -> None:
    assert tool.trigrams(["ab"]) == {"^^a": 1, "^ab": 1, "ab$": 1}


def test_the_same_counts_always_give_the_same_file() -> None:
    counts = tool.trigrams(["google", "facebook"])
    meta: dict[str, object] = {"source": "test"}

    first = tool.encode(counts, meta)

    assert first == tool.encode(counts, meta)
    assert read_counts(first) == (meta, dict(counts))


def test_calibration_reports_each_threshold() -> None:
    model = LabelModel(tool.trigrams(["examplesite", "anothersite"] * 50))

    lines = tool.calibration(model, ["examplesites", "othersitename"])

    assert lines[0] == "Kept-out labels of 8+ characters: 2"
    assert len(lines) == 2 + len(tool.THRESHOLDS)


def test_main_writes_the_model_from_a_local_copy(tmp_path: Path) -> None:
    source = tmp_path / "list.csv"
    source.write_text("\n".join(ROWS * 20), encoding="utf-8")
    output = tmp_path / "model.json.gz"

    assert tool.main(["--source", str(source), "--output", str(output), "--list-id", "TEST"]) == 0

    loaded = json.loads(gzip.decompress(output.read_bytes()))
    assert loaded["meta"]["source"] == "Tranco list TEST"
    assert loaded["meta"]["labels"] + loaded["meta"]["kept_out"] == 4 * 20
    assert all(len(key) == 3 for key in loaded["trigrams"])
