"""Checks that every release a change adds to uv.lock is at least 14 days old.

The conventions workflow runs it on every pull request, against the base
branch's lock file:

    python tools/lock_age.py BASE_LOCK HEAD_LOCK
"""

import argparse
import sys
import tomllib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

MIN_AGE = timedelta(days=14)


def _released(package: Mapping[str, Any]) -> datetime | None:
    """When a locked release was first uploaded; ``None`` for a local package."""
    files = [package.get("sdist", {}), *package.get("wheels", [])]
    times = [datetime.fromisoformat(file["upload-time"]) for file in files if "upload-time" in file]
    return min(times) if times else None


def releases(lock: str) -> dict[tuple[str, str], datetime | None]:
    """Each package and version in a uv.lock, with when it was released."""
    return {
        (package["name"], package["version"]): _released(package)
        for package in tomllib.loads(lock).get("package", [])
        if "version" in package
    }


def too_new(base: str, head: str, *, now: datetime) -> list[str]:
    """Releases in ``head`` but not in ``base`` uploaded less than 14 days before ``now``."""
    added = releases(head).items() - releases(base).items()
    problems = []
    for (name, version), released in sorted(added, key=lambda item: item[0]):
        if released is None or now - released >= MIN_AGE:
            continue
        age = (now - released).days
        problems.append(
            f"{name} {version} was released on {released:%Y-%m-%d}, {age} days ago; lock a "
            f"release at least {MIN_AGE.days} days old. A security fix may go in sooner, with "
            "this check failing until the release is old enough."
        )
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    """Compare two lock files and print the releases that are too new."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base")
    parser.add_argument("head")
    args = parser.parse_args(argv)
    base = Path(args.base).read_text(encoding="utf-8")
    head = Path(args.head).read_text(encoding="utf-8")
    problems = too_new(base, head, now=datetime.now(UTC))
    sys.stderr.writelines(f"{problem}\n" for problem in problems)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
