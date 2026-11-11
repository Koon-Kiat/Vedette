"""Alembic environment: runs migrations over a plain synchronous connection."""

from alembic import context
from sqlalchemy import create_engine

from sentinel.storage.models import metadata


def run_migrations_online() -> None:
    """Connect to the configured database and apply pending migrations."""
    url = context.config.get_main_option("sqlalchemy.url")
    if url is None:
        raise RuntimeError("sqlalchemy.url is not configured")
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            context.configure(connection=connection, target_metadata=metadata, render_as_batch=True)
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


run_migrations_online()
