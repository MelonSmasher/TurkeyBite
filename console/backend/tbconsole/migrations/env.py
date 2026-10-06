"""Alembic environment: migrations run against TBCONSOLE_DATABASE_URL."""

import asyncio

from alembic import context
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from tbconsole import models  # noqa: F401  # pylint: disable=unused-import  # imported to register every table
from tbconsole.config import get_settings
from tbconsole.db import Base

target_metadata = Base.metadata


def run_offline() -> None:
    """Writes the migrations out as SQL, without connecting to the database."""
    context.configure(url=get_settings().database_url, target_metadata=target_metadata,
                      literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


# pg_advisory_xact_lock key: console processes started together with
# --migrate take turns, and each after the first finds nothing left to do
MIGRATION_LOCK = 0x7462_0000


def _run(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        connection.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': MIGRATION_LOCK})
        context.run_migrations()


async def run_online() -> None:
    """Runs the migrations against the database, one console process at a time."""
    engine = create_async_engine(get_settings().database_url)
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    run_offline()
else:
    asyncio.run(run_online())
