"""The console's Postgres: engine, sessions, and the declarative base."""

from collections.abc import AsyncIterator

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import get_settings

# Named constraints, so Alembic can drop and alter them by name later
NAMING = {
    'ix': 'ix_%(column_0_label)s',
    'uq': 'uq_%(table_name)s_%(column_0_name)s',
    'ck': 'ck_%(table_name)s_%(constraint_name)s',
    'fk': 'fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s',
    'pk': 'pk_%(table_name)s',
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


_engine: AsyncEngine | None = None
_sessions: async_sessionmaker[AsyncSession] | None = None


def engine() -> AsyncEngine:
    global _engine, _sessions
    if _engine is None:
        # A database that does not answer is given up on: in ten seconds to
        # connect or to lend a pooled connection, not the minute or more the
        # drivers would wait, and in a minute for any one statement, so a
        # connection to a database that froze cannot hold a request for ever
        _engine = create_async_engine(get_settings().database_url, pool_pre_ping=True,
                                      pool_size=10, max_overflow=10, pool_timeout=10,
                                      connect_args={'timeout': 10, 'command_timeout': 60})
        _sessions = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def sessionmaker() -> async_sessionmaker[AsyncSession]:
    engine()
    assert _sessions is not None
    return _sessions


async def dispose() -> None:
    global _engine, _sessions
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessions = None


async def get_session() -> AsyncIterator[AsyncSession]:
    """A session per request. Routes commit what they change themselves."""
    async with sessionmaker()() as session:
        yield session
