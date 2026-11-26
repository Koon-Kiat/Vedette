"""Releases added to uv.lock must be at least 14 days old."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import lock_age

NOW = datetime(2026, 11, 26, 12, tzinfo=UTC)


def lock(*packages: tuple[str, str, str | None]) -> str:
    """A uv.lock with each package's sdist uploaded at the given time (None: local)."""
    blocks = []
    for name, version, uploaded in packages:
        block = f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        if uploaded is None:
            block += 'source = { editable = "." }\n'
        else:
            block += f'sdist = {{ url = "https://x/{name}.tar.gz", upload-time = "{uploaded}" }}\n'
            block += f'wheels = [{{ url = "https://x/{name}.whl", upload-time = "{uploaded}" }}]\n'
        blocks.append(block)
    return "version = 1\n\n" + "\n".join(blocks)


def test_an_unchanged_lock_passes() -> None:
    text = lock(("fastapi", "0.162.2", "2026-11-25T00:00:00Z"))
    assert lock_age.too_new(text, text, now=NOW) == []


def test_a_release_added_14_days_after_its_upload_passes() -> None:
    base = lock(("fastapi", "0.162.0", "2026-10-01T00:00:00Z"))
    head = lock(("fastapi", "0.162.2", "2026-11-12T12:00:00Z"))
    assert lock_age.too_new(base, head, now=NOW) == []


def test_a_release_younger_than_14_days_is_refused() -> None:
    base = lock(("fastapi", "0.162.0", "2026-10-01T00:00:00Z"))
    head = lock(("fastapi", "0.163.0", "2026-11-20T09:00:00Z"))
    (problem,) = lock_age.too_new(base, head, now=NOW)
    assert problem.startswith("fastapi 0.163.0 was released on 2026-11-20, 6 days ago")
    assert "at least 14 days old" in problem


def test_a_new_transitive_package_counts_too() -> None:
    base = lock(("fastapi", "0.162.2", "2026-10-01T00:00:00Z"))
    head = lock(
        ("fastapi", "0.162.2", "2026-10-01T00:00:00Z"),
        ("grimp", "3.20", "2026-11-13T00:00:00Z"),
    )
    (problem,) = lock_age.too_new(base, head, now=NOW)
    assert problem.startswith("grimp 3.20 ")


def test_the_earliest_upload_of_a_release_is_its_date() -> None:
    head = lock(("uvicorn", "0.54.0", "2026-11-25T00:00:00Z")).replace(
        'sdist = { url = "https://x/uvicorn.tar.gz", upload-time = "2026-11-25T00:00:00Z" }',
        'sdist = { url = "https://x/uvicorn.tar.gz", upload-time = "2026-10-01T00:00:00Z" }',
    )
    assert lock_age.too_new(lock(), head, now=NOW) == []


def test_a_local_package_has_no_release_date_and_is_skipped() -> None:
    head = lock(("vedette", "0.2.0", None))
    assert lock_age.too_new(lock(), head, now=NOW) == []


@pytest.mark.parametrize(("days_old", "status"), [(30, 0), (1, 1)])
def test_the_entry_point_exits_1_on_a_young_release(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], days_old: int, status: int
) -> None:
    uploaded = (datetime.now(UTC) - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = tmp_path / "base.lock"
    head = tmp_path / "head.lock"
    base.write_text(lock(), encoding="utf-8")
    head.write_text(lock(("jinja2", "3.1.7", uploaded)), encoding="utf-8")
    assert lock_age.main([str(base), str(head)]) == status
    assert ("jinja2 3.1.7" in capsys.readouterr().err) is bool(status)


def test_this_repository_lock_file_parses() -> None:
    text = (Path(lock_age.__file__).parents[1] / "uv.lock").read_text(encoding="utf-8")
    found = lock_age.releases(text)
    assert ("fastapi", "0.162.2") in found
    assert all(released is not None for (name, _), released in found.items() if name != "vedette")
