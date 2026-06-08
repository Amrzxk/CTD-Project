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
    must_change_password: bool = False,
) -> User:
    """Insert a new user. Caller is responsible for hashing the password
    (see ``app.auth.security.hash_password``).

    ``must_change_password`` arms the forced first-login change for SOC
    accounts minted with an admin-set temporary password.
    """
    user = User(
        username=_normalise(username),
        password_hash=password_hash,
        role=role,
        must_change_password=must_change_password,
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


async def list_all(session: AsyncSession) -> list[User]:
    """Every user, active or not — for the admin management table.

    Unlike ``list_active`` this includes deactivated accounts so an admin
    can re-enable them. Ordered by username for a stable table."""
    stmt = select(User).order_by(User.username)
    result = await session.execute(stmt)
    return list(result.scalars())


async def set_active(
    session: AsyncSession, user_id: int, is_active: bool
) -> User | None:
    """Enable/disable an account. Deactivating also bumps ``token_version``
    so any live session for that user is invalidated on its next request
    (see ``get_current_user``). Returns the row, or None if not found."""
    user = await session.get(User, user_id)
    if user is None:
        return None
    user.is_active = is_active
    if not is_active:
        user.token_version = int(user.token_version) + 1
    return user


async def reset_password(
    session: AsyncSession, user_id: int, password_hash: str
) -> User | None:
    """Admin-set a new temporary password. Re-arms the forced first-login
    change and bumps ``token_version`` to kill the user's existing sessions.
    Returns the row, or None if not found."""
    user = await session.get(User, user_id)
    if user is None:
        return None
    user.password_hash = password_hash
    user.must_change_password = True
    user.token_version = int(user.token_version) + 1
    return user


async def usernames_for(
    session: AsyncSession, ids: set[int]
) -> dict[int, str]:
    """Resolve a set of user ids to usernames in one query. Used to surface
    ack attribution (``ack_by`` / ``ack_history.user_id``) as usernames."""
    clean = {int(i) for i in ids if i is not None}
    if not clean:
        return {}
    stmt = select(User.id, User.username).where(User.id.in_(clean))
    rows = (await session.execute(stmt)).all()
    return {int(uid): uname for uid, uname in rows}
