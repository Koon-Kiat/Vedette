"""Applies database migrations at start-up."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url

from sentinel.storage.retention import restrict_permissions

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def run_migrations(database_url: str) -> None:
    """Bring the database schema up to date. Safe to call on every start.

    Migrations run over a synchronous connection, so the async driver in the
    URL (for example ``sqlite+aiosqlite``) is replaced by the backend's default.
    Afterwards a SQLite file and its directory are made owner-only.
    """
    url = make_url(database_url)
    sync_url = url.set(drivername=url.get_backend_name())
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option(
        "sqlalchemy.url", sync_url.render_as_string(hide_password=False).replace("%", "%%")
    )
    command.upgrade(config, "head")
    restrict_permissions(database_url)
