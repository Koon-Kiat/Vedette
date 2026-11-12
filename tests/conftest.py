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


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live",
        action="store_true",
        default=False,
        help="also run tests that need real services (the local Ollama model)",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--live"):
        return
    skip = pytest.mark.skip(reason="needs real services; run with --live")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)
