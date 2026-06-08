"""Append-only audit-trail repository for admin account management.

Every privileged action an admin takes against another account
(create / enable / disable / reset_password) writes one row here, inside
the same transaction that mutates the target ``users`` row — so the audit
trail and live state never drift. Mirrors ``ack_history``.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import UserAdminHistory


async def record(
    session: AsyncSession,
    *,
    actor_id: int | None,
    target_id: int | None,
    target_username: str,
    action: str,
) -> UserAdminHistory:
    """Insert one audit row. ``created_at`` uses NOW() server-side so
    multi-worker timing stays consistent."""
    entry = UserAdminHistory(
        actor_id=actor_id,
        target_id=target_id,
        target_username=target_username,
        action=action,
    )
    session.add(entry)
    return entry


async def list_recent(
    session: AsyncSession, limit: int = 100
) -> list[UserAdminHistory]:
    """Most recent admin actions, newest first. Not surfaced in the UI yet;
    available for a future compliance view."""
    stmt = (
        select(UserAdminHistory)
        .order_by(UserAdminHistory.created_at.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars())
