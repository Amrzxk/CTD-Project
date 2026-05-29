"""Database access layer.

Exports the async SQLAlchemy engine, the session factory, and the
`get_session` FastAPI dependency. Importing this module does NOT open
any connections — the engine lazily creates them on first use.

DATABASE_URL must include `+asyncpg` for the async driver, e.g.::

    postgresql+asyncpg://hids:hids@127.0.0.1:5432/hids

The engine is process-local, so multi-worker gunicorn gives each worker
its own pool. Default pool size (5) × workers (4) = 20 connections — well
under Postgres' default ``max_connections=100``.
"""
from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from typing import Final

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

log = logging.getLogger(__name__)

# Default points at the docker-compose service. Override via env in prod.
_DEFAULT_URL: Final[str] = (
    "postgresql+asyncpg://hids:hids@127.0.0.1:5432/hids"
)


def _resolve_database_url() -> str:
    url = os.getenv("DATABASE_URL", _DEFAULT_URL)
    # asyncpg requires the `+asyncpg` driver tag; bare `postgresql://` would
    # silently fall back to psycopg2 (sync) and block the event loop. Reject
    # loudly so misconfiguration shows up at startup, not under load.
    if url.startswith("postgresql://"):
        raise RuntimeError(
            "DATABASE_URL must use the asyncpg driver — "
            "use 'postgresql+asyncpg://...' instead of 'postgresql://...'"
        )
    return url


engine: AsyncEngine = create_async_engine(
    _resolve_database_url(),
    # echo=True would log every SQL statement — useful for debugging but
    # noisy at runtime. Toggle via env if needed.
    echo=os.getenv("DB_ECHO") == "1",
    # `future=True` is the SA 2.x default; spelled out for clarity.
    future=True,
    # pool_pre_ping issues a cheap SELECT 1 before handing out a connection.
    # Survives transient network blips and idle connections killed by RDS
    # / pgbouncer / cloud load balancers without the app seeing them.
    pool_pre_ping=True,
)

SessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine,
    expire_on_commit=False,
    autoflush=False,
)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: yields a per-request AsyncSession.

    Commits on successful return, rolls back on exception. The session is
    always closed. Pattern lifted from the FastAPI + SQLAlchemy 2.x
    cookbook.
    """
    async with SessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()
