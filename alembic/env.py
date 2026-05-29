"""Async-aware Alembic environment.

Reads ``DATABASE_URL`` from the OS environment so the same migrations
run against local docker-compose Postgres, CI, and AWS RDS without
config drift. Uses the asyncpg driver to match the application's
runtime — guarantees migrations exercise the same dialect quirks.

Run with::

    alembic upgrade head

(or via the container's start script, which invokes the same command
on every API container boot — Postgres' DDL locks serialize concurrent
attempts, and Alembic's ``alembic_version`` table prevents double
application).
"""
from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import AsyncEngine, async_engine_from_config

# Ensure the project root is importable so `app.db.base` resolves whether
# alembic is invoked from the repo root or inside the API container.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.db.base import Base  # noqa: E402  (after sys.path fixup)
from app.db import models  # noqa: F401,E402  (registers model metadata)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_url() -> str:
    """Resolve the database URL from env, falling back to the compose default."""
    return os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://hids:hids@127.0.0.1:5432/hids",
    )


def run_migrations_offline() -> None:
    """Generate SQL without connecting. Mostly used for review."""
    context.configure(
        url=_get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        # Render the naming convention from base.metadata.
        render_as_batch=False,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    ini_section = config.get_section(config.config_ini_section) or {}
    ini_section["sqlalchemy.url"] = _get_url()
    # async_engine_from_config matches our `+asyncpg` URL; the plain
    # `engine_from_config` returns a sync engine, which trips the
    # MissingGreenlet error the moment we call `await connect()`.
    connectable: AsyncEngine = async_engine_from_config(
        ini_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
