"""User repository — CRUD + login bookkeeping.

Username is normalised to lowercase at this layer. The DB column is plain
``VARCHAR`` (no ``citext`` extension dep), so case-insensitive lookups
work uniformly across Postgres versions.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import User


def _normalise(username: str) -> str:
    return username.strip().lower()


async def get_by_username(session: AsyncSession, username: str) -> User | None:
    """Lookup by username. Case-insensitive."""
    stmt = select(User).where(User.username == _normalise(username))
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def get_by_id(session: AsyncSession, user_id: int) -> User | None:
    return await session.get(User, user_id)


async def create(
    session: AsyncSession,
    *,
    username: str,
    password_hash: str,
    role: str = "analyst",
) -> User:
    """Insert a new user. Caller is responsible for hashing the password
    (see ``app.auth.security.hash_password``)."""
    user = User(
        username=_normalise(username),
        password_hash=password_hash,
        role=role,
    )
    session.add(user)
    await session.flush()
    return user


async def update_last_login(session: AsyncSession, user_id: int) -> None:
    """Stamp ``last_login_at`` to now. Called from POST /auth/login."""
    user = await session.get(User, user_id)
    if user is not None:
        user.last_login_at = datetime.utcnow()


async def has_any(session: AsyncSession) -> bool:
    """True if the users table has at least one row. Used by the seed
    routine to decide whether to provision the bootstrap admin."""
    stmt = select(func.count(User.id))
    result = await session.execute(stmt)
    return (result.scalar_one() or 0) > 0


async def list_active(session: AsyncSession) -> list[User]:
    stmt = select(User).where(User.is_active.is_(True)).order_by(User.username)
    result = await session.execute(stmt)
    return list(result.scalars())
