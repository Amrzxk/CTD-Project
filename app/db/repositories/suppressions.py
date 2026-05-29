"""Server-enforced suppression rules.

Replaces the previous in-memory module at ``app/core/suppression.py``.
Same precedence order — ``sid > flow_key > src_ip > src_cidr`` — so an
analyst's mental model carries over. The big wins from moving to
Postgres:

* Rules survive restarts (the whole point).
* ``hits`` counter is atomic via ``UPDATE … SET hits = hits + 1``,
  safe under multi-worker concurrency.
* Expired rules are pruned in one ``DELETE`` instead of per-call list
  rewrites.
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Suppression

_VALID_KINDS = {"sid", "src_ip", "src_cidr", "flow_key"}


def _build_flow_key(p: dict) -> str:
    return (
        f"{p.get('sourceIp')}:{p.get('sourcePort')}-"
        f"{p.get('destinationIp')}:{p.get('destinationPort')}-"
        f"{p.get('protocol')}"
    )


async def _prune_expired(session: AsyncSession) -> None:
    """Delete rules whose ``expires_at`` has passed. Cheap — index on
    ``expires_at`` is not needed at our scale, but if it becomes hot we
    can add one."""
    stmt = delete(Suppression).where(
        Suppression.expires_at.is_not(None),
        Suppression.expires_at <= datetime.utcnow(),
    )
    await session.execute(stmt)


async def list_active(session: AsyncSession) -> list[Suppression]:
    """All non-expired rules, ordered by creation time."""
    await _prune_expired(session)
    stmt = select(Suppression).order_by(Suppression.created_at.desc())
    result = await session.execute(stmt)
    return list(result.scalars())


async def add(
    session: AsyncSession,
    *,
    kind: str,
    value: str,
    expires_at: datetime | None = None,
    note: str | None = None,
    created_by: int | None = None,
) -> Suppression:
    """Register a new rule. CIDR is validated up-front so a bad value
    fails at create time, not at first match attempt."""
    if kind not in _VALID_KINDS:
        raise ValueError(f"Unknown suppression kind: {kind!r}")
    value = value.strip()
    if not value:
        raise ValueError("Suppression value cannot be empty")
    if kind == "src_cidr":
        # Raises ValueError on bad CIDR.
        ipaddress.ip_network(value, strict=False)

    rule = Suppression(
        id=f"supp_{uuid.uuid4()}",
        kind=kind,
        value=value,
        expires_at=expires_at,
        note=note,
        created_by=created_by,
    )
    session.add(rule)
    await session.flush()
    return rule


async def remove(session: AsyncSession, rule_id: str) -> bool:
    rule = await session.get(Suppression, rule_id)
    if rule is None:
        return False
    await session.delete(rule)
    return True


def _matches(rule: Suppression, p: dict) -> bool:
    """Pure predicate — no DB calls. Mirrors the original in-memory
    module's matching logic exactly."""
    if rule.kind == "sid":
        sid = p.get("snort_sid")
        return sid is not None and str(sid) == rule.value
    if rule.kind == "src_ip":
        return str(p.get("sourceIp") or "") == rule.value
    if rule.kind == "src_cidr":
        try:
            net = ipaddress.ip_network(rule.value, strict=False)
            return ipaddress.ip_address(str(p.get("sourceIp") or "")) in net
        except (ValueError, TypeError):
            return False
    if rule.kind == "flow_key":
        return _build_flow_key(p) == rule.value
    return False


async def match(session: AsyncSession, prediction: dict) -> Suppression | None:
    """Find the first rule that matches this prediction (or ``None``).

    Match order: ``sid > flow_key > src_ip > src_cidr``. Bumps the
    matching rule's ``hits`` counter so the UI can show whether a rule
    is actually firing.
    """
    rules = await list_active(session)
    for kind in ("sid", "flow_key", "src_ip", "src_cidr"):
        for rule in rules:
            if rule.kind == kind and _matches(rule, prediction):
                # Atomic increment — safer than read-modify-write under
                # multi-worker concurrency.
                await session.execute(
                    update(Suppression)
                    .where(Suppression.id == rule.id)
                    .values(hits=Suppression.hits + 1)
                )
                return rule
    return None


async def filter_predictions(
    session: AsyncSession, predictions: list[dict]
) -> tuple[list[dict], int]:
    """Apply all active suppressions to a batch in one pass.

    Returns ``(kept, dropped_count)``. ``kept`` preserves input order so
    downstream consumers (DB insert, streaming response) can use it
    directly.
    """
    if not predictions:
        return [], 0
    # Pull rules once for the whole batch — avoid one query per row.
    rules = await list_active(session)
    if not rules:
        return list(predictions), 0

    kept: list[dict] = []
    dropped = 0
    hit_counter: dict[str, int] = {}
    for p in predictions:
        matched: Suppression | None = None
        for kind in ("sid", "flow_key", "src_ip", "src_cidr"):
            for rule in rules:
                if rule.kind == kind and _matches(rule, p):
                    matched = rule
                    break
            if matched is not None:
                break
        if matched is None:
            kept.append(p)
        else:
            dropped += 1
            hit_counter[matched.id] = hit_counter.get(matched.id, 0) + 1

    # Single UPDATE per rule, not per match. Cuts round-trips on large
    # bursts (e.g. a 1789-row campaign that all hits one SID suppression).
    for rule_id, n in hit_counter.items():
        await session.execute(
            update(Suppression)
            .where(Suppression.id == rule_id)
            .values(hits=Suppression.hits + n)
        )
    return kept, dropped


def to_dict(rule: Suppression) -> dict:
    """Serialise to the API response shape. Kept stable so the dashboard
    contract doesn't change as we swap storage."""
    return {
        "id": rule.id,
        "kind": rule.kind,
        "value": rule.value,
        "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
        "note": rule.note,
        "hits": rule.hits,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "created_by": rule.created_by,
    }
