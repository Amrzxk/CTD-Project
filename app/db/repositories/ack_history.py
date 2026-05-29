"""Append-only audit-trail repository.

Every ack-state change writes a row here. The predictions repo calls
``record()`` inside the same transaction that updates the prediction's
mirror fields (``ack_state`` / ``ack_at`` / ``ack_note`` / ``ack_by``),
so the audit trail and the live state never drift.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AckHistory


async def record(
    session: AsyncSession,
    *,
    prediction_id: str,
    user_id: int | None,
    from_state: str,
    to_state: str,
    note: str | None = None,
) -> AckHistory:
    """Insert one audit row. The ``changed_at`` column uses NOW() server-side
    so multi-worker timing stays consistent."""
    entry = AckHistory(
        prediction_id=prediction_id,
        user_id=user_id,
        from_state=from_state,
        to_state=to_state,
        note=note,
    )
    session.add(entry)
    return entry


async def list_for(session: AsyncSession, prediction_id: str) -> list[AckHistory]:
    """Return all audit rows for a prediction, newest first. Used by the
    drawer's "who touched this" timeline."""
    stmt = (
        select(AckHistory)
        .where(AckHistory.prediction_id == prediction_id)
        .order_by(AckHistory.changed_at.desc())
    )
    result = await session.execute(stmt)
    return list(result.scalars())
