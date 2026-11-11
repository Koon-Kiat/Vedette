import logging
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
import structlog

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the developer's real settings and secrets out of every test."""
    for name in list(os.environ):
        if name.startswith("SENTINEL_") or name == "NEXTDNS_API_KEY":
            monkeypatch.delenv(name)


@pytest.fixture(autouse=True)
def reset_logging() -> Iterator[None]:
    """Undo any logging configuration a test installed."""
    yield
    structlog.reset_defaults()
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(logging.WARNING)


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT
