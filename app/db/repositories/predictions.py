"""Predictions repository — the analyst-facing queue.

Replaces the in-memory ``predictions_store`` list with Postgres queries.
All response shapes are preserved exactly so the dashboard contract
doesn't change. Heavy aggregation (analytics_aggregates) runs in SQL
rather than scanning the row set in Python.
"""
from __future__ import annotations

import ipaddress
import json
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import and_, asc, case, delete, desc, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AckHistory, Prediction
from app.db.repositories import ack_history as ack_history_repo

log = logging.getLogger(__name__)

# Range string → seconds. ``"all"`` means no time filter.
_RANGE_SECONDS: dict[str, int | None] = {
    "1h": 3600,
    "24h": 24 * 3600,
    "7d": 7 * 24 * 3600,
    "30d": 30 * 24 * 3600,
    "all": None,
}

_SEV_CASE = case(
    (Prediction.severity == "High", 3),
    (Prediction.severity == "Medium", 2),
    (Prediction.severity == "Low", 1),
    else_=0,
)


# ----------------------------------------------------------------------
# Serialisation
# ----------------------------------------------------------------------

def _iso(dt: datetime | None) -> str | None:
    """Format a datetime as ISO 8601. Returns ``None`` for None inputs so
    JSON responses stay tidy."""
    return dt.isoformat() if dt is not None else None


def to_full_dict(p: Prediction) -> dict[str, Any]:
    """Full payload for ``GET /predictions/{id}`` and incident-report
    export. Mirrors the legacy in-memory dict shape so the dashboard
    can consume it unchanged."""
    return {
        "id": p.id,
        # Legacy key name "timestamp" preserved; payloads use flow time.
        "timestamp": _iso(p.flow_timestamp),
        "firstSeenAt": _iso(p.first_seen_at),
        "sourceIp": p.source_ip,
        "destinationIp": p.destination_ip,
        "sourcePort": p.source_port,
        "destinationPort": p.destination_port,
        "protocol": p.protocol,
        "packetSize": p.packet_size,
        "duration": p.duration,
        "prediction": p.prediction,
        "attack_type": p.attack_type,
        "family": p.family,
        "subtype": p.subtype,
        "confidence": p.confidence,
        "severity": p.severity,
        "stage1_p": p.stage1_p,
        "stage2_p": p.stage2_p,
        "stage3_p": p.stage3_p,
        "stage2_probs": p.stage2_probs,
        "stage3_probs": p.stage3_probs,
        "mlFeatures": p.ml_features,
        "mitre": p.mitre,
        "source": p.source,
        "model_version": p.model_version,
        "snort_msg": p.snort_msg or "",
        "snort_sid": p.snort_sid or 0,
        "snort_classtype": p.snort_classtype or "",
        "snort_priority": p.snort_priority or 0,
        "ack_state": p.ack_state,
        "ack_at": _iso(p.ack_at),
        "ack_note": p.ack_note,
        "ack_by": p.ack_by,
    }


def to_summary_dict(p: Prediction) -> dict[str, Any]:
    """Slim payload for ``GET /predictions`` and the streaming upload's
    ``result_batch`` events. Drops heavy fields (``stage2_probs``,
    ``stage3_probs``, ``mlFeatures``, full ``mitre.techniques``) so list
    responses stay small even on 80k-row uploads."""
    mitre_summary: dict[str, Any] | None = None
    if isinstance(p.mitre, dict):
        mitre_summary = {
            "confidence_band": p.mitre.get("confidence_band"),
            "tactics": p.mitre.get("tactics", []),
        }
        if p.mitre.get("unmapped"):
            mitre_summary["unmapped"] = True
            mitre_summary["attack_type"] = p.mitre.get("attack_type")
            mitre_summary["description"] = p.mitre.get("description")

    return {
        "id": p.id,
        "timestamp": _iso(p.flow_timestamp),
        "sourceIp": p.source_ip,
        "destinationIp": p.destination_ip,
        "sourcePort": p.source_port,
        "destinationPort": p.destination_port,
        "protocol": p.protocol,
        "packetSize": p.packet_size,
        "duration": p.duration,
        "prediction": p.prediction,
        "attack_type": p.attack_type,
        "confidence": p.confidence,
        "severity": p.severity,
        "family": p.family,
        "subtype": p.subtype,
        "stage1_p": p.stage1_p,
        "stage2_p": p.stage2_p,
        "stage3_p": p.stage3_p,
        "source": p.source,
        "model_version": p.model_version,
        "ack_state": p.ack_state,
        "ack_at": _iso(p.ack_at),
        "ack_note": p.ack_note,
        "snort_msg": p.snort_msg or "",
        "snort_sid": p.snort_sid or 0,
        "snort_classtype": p.snort_classtype or "",
        "snort_priority": p.snort_priority or 0,
        "mitre": mitre_summary,
    }


# ----------------------------------------------------------------------
# Insert
# ----------------------------------------------------------------------

def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # Accept both naive and aware ISO strings; the legacy code emits a
        # mix depending on the ingest path. Postgres TIMESTAMPTZ stores
        # UTC; aware strings keep their offset, naive ones are treated as
        # UTC for storage (consistent default — easier to reason about
        # downstream than "server local time").
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _row_from_dict(d: dict) -> Prediction:
    """Translate a ``_format_predictions()`` dict into a Prediction row.

    Field names map 1:1 except ``timestamp → flow_timestamp`` (renamed
    for explicitness) and ``mlFeatures → ml_features`` (camel → snake).
    """
    flow_ts = _parse_iso(d.get("timestamp")) or datetime.now(timezone.utc)
    return Prediction(
        id=d["id"],
        flow_timestamp=flow_ts,
        source_ip=str(d.get("sourceIp") or "N/A"),
        destination_ip=str(d.get("destinationIp") or "N/A"),
        source_port=int(d.get("sourcePort") or 0),
        destination_port=int(d.get("destinationPort") or 0),
        protocol=str(d.get("protocol") or "N/A"),
        packet_size=int(d.get("packetSize") or 0),
        duration=float(d.get("duration") or 0.0),
        prediction=str(d.get("prediction") or "Normal"),
        attack_type=d.get("attack_type"),
        family=d.get("family"),
        subtype=d.get("subtype"),
        confidence=float(d.get("confidence") or 0.0),
        severity=d.get("severity"),
        stage1_p=_to_float(d.get("stage1_p")),
        stage2_p=_to_float(d.get("stage2_p")),
        stage3_p=_to_float(d.get("stage3_p")),
        stage2_probs=d.get("stage2_probs"),
        stage3_probs=d.get("stage3_probs"),
        ml_features=d.get("mlFeatures"),
        mitre=d.get("mitre"),
        source=d.get("source"),
        model_version=d.get("model_version"),
        snort_msg=d.get("snort_msg") or None,
        snort_sid=int(d["snort_sid"]) if d.get("snort_sid") else None,
        snort_classtype=d.get("snort_classtype") or None,
        snort_priority=int(d["snort_priority"]) if d.get("snort_priority") else None,
        ack_state=str(d.get("ack_state") or "new"),
        ack_at=_parse_iso(d.get("ack_at")),
        ack_note=d.get("ack_note"),
    )


def _to_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def live_event_to_insert_dict(event: dict) -> dict:
    """Translate an SSE event dict (snake_case 5-tuple at top level) into
    the canonical upload-shape dict that ``_row_from_dict`` expects
    (camelCase keys). Single source of truth for the live→DB key mapping
    so both shapes stay aligned.

    ``packetSize`` and ``duration`` are not surfaced on the live SSE event
    by design — the per-flow byte/duration totals live in the Redis flow
    hash that the live generator inspects but does not re-emit. Default
    them to 0 here; analysts filter the Alerts queue on family / verdict /
    severity, not on raw byte counts.
    """
    return {
        "id": event.get("id"),
        "timestamp": event.get("timestamp"),
        "sourceIp": event.get("src_ip"),
        "destinationIp": event.get("dst_ip"),
        "sourcePort": event.get("src_port"),
        "destinationPort": event.get("dst_port"),
        "protocol": event.get("protocol"),
        "packetSize": 0,
        "duration": 0.0,
        "prediction": event.get("prediction"),
        "attack_type": event.get("attack_type"),
        "confidence": event.get("confidence"),
        "severity": event.get("severity"),
        "family": event.get("family"),
        "subtype": event.get("subtype") or event.get("attack_type"),
        "stage1_p": event.get("stage1_p"),
        "stage2_p": event.get("stage2_p"),
        "stage2_probs": event.get("stage2_probs"),
        "stage3_p": event.get("stage3_p"),
        "stage3_probs": event.get("stage3_probs"),
        "mlFeatures": None,
        "mitre": event.get("mitre"),
        "source": event.get("source"),
        "model_version": event.get("model_version"),
        "snort_msg": event.get("snort_msg"),
        "snort_sid": event.get("snort_sid"),
        "snort_classtype": event.get("snort_classtype"),
        "snort_priority": event.get("snort_priority"),
        "ack_state": "new",
        "ack_at": None,
        "ack_note": None,
    }


async def insert_from_live_events(
    session: AsyncSession, events: Iterable[dict]
) -> int:
    """Persist a batch of live SSE events. Drops benign events as a
    backstop — the SSE generator's gate is authoritative but a redundant
    check here keeps the DB clean if a caller forgets.

    Delegates to ``insert_many`` so the wire format stays single-sourced.
    """
    payload: list[dict] = []
    for event in events:
        if (event.get("source") or "").lower() == "benign":
            continue
        if not event.get("id"):
            continue
        payload.append(live_event_to_insert_dict(event))
    if not payload:
        return 0
    return await insert_many(session, payload)


_INSERT_CHUNK = 5000


async def insert_many(session: AsyncSession, rows: Iterable[dict]) -> int:
    """Bulk-insert predictions. Returns count.

    Builds + flushes in chunks of ``_INSERT_CHUNK`` so an 80k-flow PCAP
    upload doesn't materialise all ORM objects + their pending-INSERT state
    in memory at once (which spiked the API's RSS on a 2 GB box). Each chunk
    is flushed (not committed) so the whole call stays in one transaction —
    the caller's commit/rollback boundary is unchanged.
    """
    materialised = list(rows)
    if not materialised:
        return 0
    total = 0
    for start in range(0, len(materialised), _INSERT_CHUNK):
        chunk = materialised[start:start + _INSERT_CHUNK]
        models = [_row_from_dict(r) for r in chunk]
        session.add_all(models)
        await session.flush()
        # Detach flushed rows from the identity map so their state can be
        # GC'd instead of accumulating for the lifetime of the session.
        for m in models:
            session.expunge(m)
        total += len(models)
    return total


# ----------------------------------------------------------------------
# Read helpers
# ----------------------------------------------------------------------

async def get(session: AsyncSession, prediction_id: str) -> Prediction | None:
    return await session.get(Prediction, prediction_id)


_SORT_COLUMNS = {
    "time": Prediction.flow_timestamp,
    "severity": _SEV_CASE,
    "risk": _SEV_CASE,
    "family": Prediction.family,
    "source": Prediction.source,
}


def _apply_filters(stmt, *, ack_state: str | None, severity: str | None,
                   source: str | None, q: str | None,
                   src_cidr: str | None, dst_cidr: str | None,
                   port_min: int | None, port_max: int | None):
    """Compose the WHERE clause shared by listing and counting."""
    if ack_state:
        stmt = stmt.where(Prediction.ack_state == ack_state)
    if severity:
        stmt = stmt.where(func.lower(Prediction.severity) == severity.lower())
    if source:
        stmt = stmt.where(Prediction.source == source)
    if q:
        like = f"%{q.lower()}%"
        # The ``snort_sid`` and ports are cast to text for substring match
        # so analysts can paste a SID like "1000003" directly. Postgres
        # ILIKE handles case-insensitivity.
        stmt = stmt.where(or_(
            func.lower(Prediction.source_ip).like(like),
            func.lower(Prediction.destination_ip).like(like),
            func.lower(func.coalesce(Prediction.snort_msg, "")).like(like),
            func.cast(Prediction.snort_sid, text("text")).like(like),
            func.lower(func.coalesce(Prediction.family, "")).like(like),
            func.lower(func.coalesce(Prediction.attack_type, "")).like(like),
            func.lower(Prediction.id).like(like),
            func.cast(Prediction.source_port, text("text")).like(like),
            func.cast(Prediction.destination_port, text("text")).like(like),
        ))
    # CIDR filters use postgres' inet ops (the `<<=` operator) via the
    # textual cast since we store IPs as VARCHAR for ease of migration.
    if src_cidr:
        _validate_cidr(src_cidr)
        stmt = stmt.where(
            text("(:net)::inet >>= (predictions.source_ip)::inet").bindparams(net=src_cidr)
        )
    if dst_cidr:
        _validate_cidr(dst_cidr)
        stmt = stmt.where(
            text("(:net)::inet >>= (predictions.destination_ip)::inet").bindparams(net=dst_cidr)
        )
    if port_min is not None:
        stmt = stmt.where(Prediction.destination_port >= port_min)
    if port_max is not None:
        stmt = stmt.where(Prediction.destination_port <= port_max)
    return stmt


def _validate_cidr(value: str) -> None:
    """Raises ValueError on malformed CIDR — surfaced as HTTP 400 by routes."""
    ipaddress.ip_network(value, strict=False)


async def list_page(
    session: AsyncSession,
    *,
    limit: int = 200,
    offset: int = 0,
    ack_state: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    q: str | None = None,
    src_cidr: str | None = None,
    dst_cidr: str | None = None,
    port_min: int | None = None,
    port_max: int | None = None,
    sort: str = "time",
    dir_: str = "desc",
    group: str | None = None,
) -> dict[str, Any]:
    """Paginated list with optional grouping. Returns the legacy
    ``{total, offset, limit, items, grouped?}`` envelope."""
    safe_limit = max(1, min(int(limit), 1000))
    safe_offset = max(0, int(offset))

    if group == "campaign":
        return await _list_grouped(
            session,
            limit=safe_limit,
            offset=safe_offset,
            ack_state=ack_state,
            severity=severity,
            source=source,
            q=q,
            src_cidr=src_cidr,
            dst_cidr=dst_cidr,
            port_min=port_min,
            port_max=port_max,
        )

    base = _apply_filters(
        select(Prediction),
        ack_state=ack_state, severity=severity, source=source, q=q,
        src_cidr=src_cidr, dst_cidr=dst_cidr,
        port_min=port_min, port_max=port_max,
    )

    count_stmt = _apply_filters(
        select(func.count(Prediction.id)),
        ack_state=ack_state, severity=severity, source=source, q=q,
        src_cidr=src_cidr, dst_cidr=dst_cidr,
        port_min=port_min, port_max=port_max,
    )
    total = (await session.execute(count_stmt)).scalar_one() or 0

    sort_col = _SORT_COLUMNS.get(sort, Prediction.flow_timestamp)
    order = desc(sort_col) if dir_ != "asc" else asc(sort_col)
    page_stmt = base.order_by(order, desc(Prediction.flow_timestamp)).offset(safe_offset).limit(safe_limit)
    rows = list((await session.execute(page_stmt)).scalars())
    return {
        "total": int(total),
        "offset": safe_offset,
        "limit": safe_limit,
        "items": [to_summary_dict(r) for r in rows],
    }


async def _list_grouped(
    session: AsyncSession,
    *,
    limit: int,
    offset: int,
    ack_state: str | None,
    severity: str | None,
    source: str | None,
    q: str | None,
    src_cidr: str | None,
    dst_cidr: str | None,
    port_min: int | None,
    port_max: int | None,
) -> dict[str, Any]:
    """Server-side fold of rows sharing (source_ip, destination_ip, family).

    Returns one row per group with the representative row's summary
    fields plus ``count``, ``firstSeen``, ``lastSeen``, and ``sampleIds``
    (capped at 50 — enough for the drawer's "view related" pane; bulk
    ack of larger groups uses ``POST /predictions/ack/by-match``).
    """
    # Step 1: aggregate group sizes and bounds.
    group_stmt = _apply_filters(
        select(
            Prediction.source_ip,
            Prediction.destination_ip,
            Prediction.family,
            func.count(Prediction.id).label("cnt"),
            func.min(Prediction.flow_timestamp).label("first_seen"),
            func.max(Prediction.flow_timestamp).label("last_seen"),
        ).group_by(
            Prediction.source_ip, Prediction.destination_ip, Prediction.family
        ),
        ack_state=ack_state, severity=severity, source=source, q=q,
        src_cidr=src_cidr, dst_cidr=dst_cidr,
        port_min=port_min, port_max=port_max,
    )
    group_stmt = group_stmt.order_by(desc("cnt")).offset(offset).limit(limit)
    groups = list((await session.execute(group_stmt)).all())

    # Total = distinct group count under the same filters.
    total_stmt = _apply_filters(
        select(
            func.count(
                func.distinct(
                    func.concat(
                        Prediction.source_ip, "|",
                        Prediction.destination_ip, "|",
                        func.coalesce(Prediction.family, ""),
                    )
                )
            )
        ),
        ack_state=ack_state, severity=severity, source=source, q=q,
        src_cidr=src_cidr, dst_cidr=dst_cidr,
        port_min=port_min, port_max=port_max,
    )
    total = (await session.execute(total_stmt)).scalar_one() or 0

    items: list[dict[str, Any]] = []
    for src_ip, dst_ip, family, cnt, first_seen, last_seen in groups:
        # Step 2 per group: fetch the representative row (newest in the
        # group) plus up to 50 child ids for the drawer.
        rep_stmt = (
            select(Prediction)
            .where(
                Prediction.source_ip == src_ip,
                Prediction.destination_ip == dst_ip,
                Prediction.family.is_(family) if family is None else Prediction.family == family,
            )
            .order_by(desc(Prediction.flow_timestamp))
            .limit(1)
        )
        rep = (await session.execute(rep_stmt)).scalar_one_or_none()
        if rep is None:
            continue
        ids_stmt = (
            select(Prediction.id)
            .where(
                Prediction.source_ip == src_ip,
                Prediction.destination_ip == dst_ip,
                Prediction.family.is_(family) if family is None else Prediction.family == family,
            )
            .order_by(desc(Prediction.flow_timestamp))
            .limit(50)
        )
        sample_ids = list((await session.execute(ids_stmt)).scalars())

        summary = to_summary_dict(rep)
        summary["count"] = int(cnt)
        summary["firstSeen"] = _iso(first_seen)
        summary["lastSeen"] = _iso(last_seen)
        summary["sampleIds"] = sample_ids
        items.append(summary)

    return {
        "total": int(total),
        "offset": offset,
        "limit": limit,
        "grouped": True,
        "items": items,
    }


async def counts_by_ack_state(session: AsyncSession) -> dict[str, int]:
    stmt = select(Prediction.ack_state, func.count(Prediction.id)).group_by(Prediction.ack_state)
    rows = (await session.execute(stmt)).all()
    out = {"new": 0, "reviewed": 0, "escalated": 0, "dismissed": 0}
    total = 0
    for state, cnt in rows:
        if state in out:
            out[state] = int(cnt)
        total += int(cnt)
    return {"total": total, **out}


# ----------------------------------------------------------------------
# Ack operations
# ----------------------------------------------------------------------

async def ack(
    session: AsyncSession,
    *,
    prediction_id: str,
    state: str,
    note: str | None,
    user_id: int | None,
) -> Prediction | None:
    row = await session.get(Prediction, prediction_id)
    if row is None:
        return None
    prev = row.ack_state
    row.ack_state = state
    row.ack_at = datetime.now(timezone.utc)
    row.ack_note = note
    row.ack_by = user_id
    await ack_history_repo.record(
        session,
        prediction_id=prediction_id,
        user_id=user_id,
        from_state=prev,
        to_state=state,
        note=note,
    )
    return row


async def bulk_ack(
    session: AsyncSession,
    *,
    ids: list[str],
    state: str,
    note: str | None,
    user_id: int | None,
) -> dict[str, Any]:
    if not ids:
        return {"updated": 0, "missing": []}
    rows = list(
        (await session.execute(
            select(Prediction).where(Prediction.id.in_(ids))
        )).scalars()
    )
    found_ids = {r.id for r in rows}
    missing = [i for i in ids if i not in found_ids]
    now = datetime.now(timezone.utc)
    for row in rows:
        prev = row.ack_state
        row.ack_state = state
        row.ack_at = now
        row.ack_note = note
        row.ack_by = user_id
        session.add(AckHistory(
            prediction_id=row.id,
            user_id=user_id,
            from_state=prev,
            to_state=state,
            note=note,
        ))
    return {"updated": len(rows), "missing": missing}


async def ack_by_match(
    session: AsyncSession,
    *,
    source_ip: str | None,
    destination_ip: str | None,
    family: str | None,
    state: str,
    note: str | None,
    user_id: int | None,
) -> dict[str, Any]:
    if not any((source_ip, destination_ip, family)):
        raise ValueError(
            "ack_by_match requires at least one of sourceIp / destinationIp / family"
        )
    stmt = select(Prediction)
    if source_ip:
        stmt = stmt.where(Prediction.source_ip == source_ip)
    if destination_ip:
        stmt = stmt.where(Prediction.destination_ip == destination_ip)
    if family:
        stmt = stmt.where(Prediction.family == family)
    rows = list((await session.execute(stmt)).scalars())
    now = datetime.now(timezone.utc)
    for row in rows:
        prev = row.ack_state
        row.ack_state = state
        row.ack_at = now
        row.ack_note = note
        row.ack_by = user_id
        session.add(AckHistory(
            prediction_id=row.id,
            user_id=user_id,
            from_state=prev,
            to_state=state,
            note=note,
        ))
    return {"updated": len(rows)}


async def clear_all(session: AsyncSession) -> int:
    """Wipe the predictions table. Cascades through ack_history via
    ``ON DELETE CASCADE`` on the FK."""
    n = (await session.execute(select(func.count(Prediction.id)))).scalar_one() or 0
    await session.execute(delete(Prediction))
    return int(n)


# ----------------------------------------------------------------------
# Retention
# ----------------------------------------------------------------------

async def delete_older_than(session: AsyncSession, days: int) -> int:
    """Retention worker entry. Deletes predictions whose flow_timestamp
    is older than ``days`` ago."""
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = delete(Prediction).where(Prediction.flow_timestamp < cutoff)
    result = await session.execute(stmt)
    # rowcount may return -1 on some drivers; coerce to non-negative.
    return max(0, result.rowcount or 0)


async def enforce_hard_cap(session: AsyncSession, cap: int) -> int:
    """If the row count exceeds ``cap``, delete the oldest rows over the
    limit. Belt-and-braces guard for runaway uploads."""
    if cap <= 0:
        return 0
    total = (await session.execute(select(func.count(Prediction.id)))).scalar_one() or 0
    overflow = int(total) - cap
    if overflow <= 0:
        return 0
    # Identify the overflow IDs by oldest first_seen_at, then delete.
    victim_stmt = (
        select(Prediction.id)
        .order_by(asc(Prediction.first_seen_at))
        .limit(overflow)
    )
    ids = list((await session.execute(victim_stmt)).scalars())
    if not ids:
        return 0
    await session.execute(delete(Prediction).where(Prediction.id.in_(ids)))
    return len(ids)


async def total_rows(session: AsyncSession) -> int:
    return int((await session.execute(select(func.count(Prediction.id)))).scalar_one() or 0)


async def timestamp_range(session: AsyncSession) -> tuple[datetime | None, datetime | None]:
    """Oldest + newest ``flow_timestamp``. Used by /_debug/store."""
    stmt = select(func.min(Prediction.flow_timestamp), func.max(Prediction.flow_timestamp))
    row = (await session.execute(stmt)).one()
    return row[0], row[1]


# ----------------------------------------------------------------------
# Analytics
# ----------------------------------------------------------------------

# Family / verdict palettes — kept here (not the dashboard) so the API
# response is fully self-describing.
_VERDICT_COLORS = {
    "confirmed": "#ff3366",
    "signature_only": "#ffaa00",
    "ml_only": "#00ccff",
    "benign": "#00ff88",
}
_FAMILY_COLORS = {
    "DoS": "#ff3366", "DDoS": "#ff6633", "Probe": "#00ccff",
    "BruteForce": "#ffaa00", "WebAttack": "#cc66ff",
    "BotnetInfiltration": "#ff66cc", "Benign": "#00ff88",
}
_LEAF_PALETTE = [
    "#ff3366", "#00ccff", "#ffaa00", "#00ff88", "#cc66ff", "#ff6633",
    "#33ccff", "#33ffaa", "#ff66cc", "#88ff33", "#ffcc33", "#3366ff",
    "#cc3366", "#33ffcc", "#ff8833", "#aaaaaa",
]
_PORT_SERVICE: dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPC", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-MSA",
    636: "LDAPS", 873: "Rsync", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5060: "SIP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}


def _range_filter(stmt, range_key: str, *, column=Prediction.flow_timestamp):
    seconds = _RANGE_SECONDS.get(range_key)
    if seconds is None:
        return stmt
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return stmt.where(column >= cutoff)


def _prior_window_filter(stmt, range_key: str, *, column=Prediction.flow_timestamp):
    seconds = _RANGE_SECONDS.get(range_key)
    if seconds is None:
        return None
    now = datetime.now(timezone.utc)
    return stmt.where(column >= now - timedelta(seconds=seconds * 2),
                      column < now - timedelta(seconds=seconds))


async def analytics_aggregates(
    session: AsyncSession,
    *,
    range_key: str = "all",
) -> dict[str, Any]:
    """Build the full ``/analytics`` response shape with SQL aggregates.

    Implementation is intentionally a sequence of focused queries (rather
    than one mega-CTE) so each section is easy to reason about and to
    swap when the schema evolves.
    """
    if range_key not in _RANGE_SECONDS:
        range_key = "all"

    # -- 1. headline counts (normal / malicious / suspicious + severity) --
    base = _range_filter(select(Prediction.prediction, Prediction.severity), range_key)
    pred_rows = (await session.execute(
        _range_filter(
            select(Prediction.prediction, func.count(Prediction.id))
                .group_by(Prediction.prediction),
            range_key,
        )
    )).all()
    normal_count = 0
    malicious_count = 0
    suspicious_count = 0
    for pred, cnt in pred_rows:
        cnt = int(cnt)
        if pred == "Normal":
            normal_count = cnt
        elif pred == "Suspicious":
            suspicious_count = cnt
            malicious_count += cnt
        else:
            malicious_count += cnt

    sev_rows = (await session.execute(
        _range_filter(
            select(func.lower(Prediction.severity), func.count(Prediction.id))
                .where(Prediction.prediction != "Normal")
                .group_by(func.lower(Prediction.severity)),
            range_key,
        )
    )).all()
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for sev, cnt in sev_rows:
        if sev in severity_counts:
            severity_counts[sev] = int(cnt)

    # -- 2. verdict breakdown --
    verdict_rows = (await session.execute(
        _range_filter(
            select(Prediction.source, func.count(Prediction.id))
                .group_by(Prediction.source),
            range_key,
        )
    )).all()
    verdict_counter: dict[str, int] = {}
    for src, cnt in verdict_rows:
        verdict_counter[src or "benign"] = int(cnt)
    verdict_breakdown = [
        {"source": s, "count": verdict_counter.get(s, 0), "color": _VERDICT_COLORS[s]}
        for s in ("confirmed", "signature_only", "ml_only", "benign")
        if verdict_counter.get(s, 0) > 0
    ]

    # -- 3. family breakdown (non-Normal only) --
    fam_rows = (await session.execute(
        _range_filter(
            select(Prediction.family, func.count(Prediction.id))
                .where(Prediction.family.is_not(None))
                .where(Prediction.prediction != "Normal")
                .group_by(Prediction.family)
                .order_by(desc(func.count(Prediction.id))),
            range_key,
        )
    )).all()
    family_breakdown = [
        {"family": fam, "count": int(cnt),
         "color": _FAMILY_COLORS.get(fam, "#aaaaaa")}
        for fam, cnt in fam_rows
    ]

    # -- 4. leaf breakdown (attack_type) --
    leaf_rows = (await session.execute(
        _range_filter(
            select(Prediction.attack_type, Prediction.family, func.count(Prediction.id))
                .where(Prediction.attack_type.is_not(None))
                .where(Prediction.prediction != "Normal")
                .group_by(Prediction.attack_type, Prediction.family)
                .order_by(desc(func.count(Prediction.id))),
            range_key,
        )
    )).all()
    leaf_breakdown = [
        {"leaf": leaf, "family": fam or "Unknown",
         "count": int(cnt), "color": _LEAF_PALETTE[i % len(_LEAF_PALETTE)]}
        for i, (leaf, fam, cnt) in enumerate(leaf_rows)
    ]

    attack_categories = [
        {"name": l["leaf"], "value": l["count"], "color": l["color"]}
        for l in leaf_breakdown
    ]

    # -- 5. severity-by-family pivot --
    sev_fam_rows = (await session.execute(
        _range_filter(
            select(
                Prediction.family,
                func.lower(Prediction.severity),
                func.count(Prediction.id),
            )
                .where(Prediction.family.is_not(None))
                .where(Prediction.prediction != "Normal")
                .group_by(Prediction.family, func.lower(Prediction.severity)),
            range_key,
        )
    )).all()
    sev_fam_map: dict[str, dict[str, int]] = {}
    for fam, sev, cnt in sev_fam_rows:
        if fam is None:
            continue
        bucket = sev_fam_map.setdefault(fam, {"high": 0, "medium": 0, "low": 0})
        if sev in bucket:
            bucket[sev] = int(cnt)
    severity_by_family = sorted(
        [
            {"family": fam, **counts,
             "total": counts["high"] + counts["medium"] + counts["low"],
             "color": _FAMILY_COLORS.get(fam, "#aaaaaa")}
            for fam, counts in sev_fam_map.items()
        ],
        key=lambda e: -e["total"],
    )

    # -- 6. attacker → victim pairs + top IPs + top dst + top ports --
    pair_rows = (await session.execute(
        _range_filter(
            select(
                Prediction.source_ip,
                Prediction.destination_ip,
                Prediction.family,
                func.count(Prediction.id),
            )
                .where(Prediction.prediction != "Normal")
                .where(Prediction.source_ip.is_not(None))
                .where(Prediction.destination_ip.is_not(None))
                .group_by(
                    Prediction.source_ip, Prediction.destination_ip, Prediction.family
                ),
            range_key,
        )
    )).all()
    # Reduce in Python — bidirectional canonicalization is awkward in SQL
    # but cheap here (typically < 5k rows).
    pair_total: Counter = Counter()           # (src,dst) -> total flows
    pair_fam: dict[tuple[str, str], Counter] = {}
    src_total: Counter = Counter()
    dst_total: Counter = Counter()
    for src_ip, dst_ip, family, cnt in pair_rows:
        n = int(cnt)
        pair_total[(src_ip, dst_ip)] += n
        pair_fam.setdefault((src_ip, dst_ip), Counter())[family or "Unknown"] += n
        src_total[src_ip] += n
        dst_total[dst_ip] += n

    canonical_attacker: Counter = Counter()
    canonical_victim: Counter = Counter()
    processed: set[tuple[str, str]] = set()
    for (a, b), cnt_ab in pair_total.items():
        unordered = tuple(sorted((a, b)))
        if unordered in processed:
            continue
        processed.add(unordered)
        cnt_ba = pair_total.get((b, a), 0)
        total = cnt_ab + cnt_ba
        if cnt_ab >= cnt_ba:
            canonical_attacker[a] += total
            canonical_victim[b] += total
        else:
            canonical_attacker[b] += total
            canonical_victim[a] += total
    top_malicious_ips = [{"ip": ip, "count": cnt}
                         for ip, cnt in canonical_attacker.most_common(5)]
    top_destinations = [{"ip": ip, "count": cnt}
                        for ip, cnt in canonical_victim.most_common(5)]

    attacker_victim_pairs = []
    for (src_ip, dst_ip), cnt in pair_total.most_common(10):
        top_fam = "Unknown"
        fam_counter = pair_fam.get((src_ip, dst_ip))
        if fam_counter:
            top_fam = fam_counter.most_common(1)[0][0]
        attacker_victim_pairs.append({
            "src": src_ip,
            "dst": dst_ip,
            "count": int(cnt),
            "topFamily": top_fam,
            "color": _FAMILY_COLORS.get(top_fam, "#aaaaaa"),
        })

    # Top targeted dst ports.
    port_rows = (await session.execute(
        _range_filter(
            select(Prediction.destination_port, func.count(Prediction.id))
                .where(Prediction.prediction != "Normal")
                .where(Prediction.destination_port > 0)
                .group_by(Prediction.destination_port)
                .order_by(desc(func.count(Prediction.id)))
                .limit(10),
            range_key,
        )
    )).all()
    top_targeted_ports = [
        {"port": int(port), "count": int(cnt),
         "label": _PORT_SERVICE.get(int(port), "")}
        for port, cnt in port_rows
    ]

    # -- 7. protocol distribution --
    proto_rows = (await session.execute(
        _range_filter(
            select(func.upper(Prediction.protocol), func.count(Prediction.id))
                .group_by(func.upper(Prediction.protocol)),
            range_key,
        )
    )).all()
    proto_colors = {"TCP": "#00ff88", "UDP": "#00ccff", "ICMP": "#ff3366"}
    base_colors = ["#ffaa00", "#cc66ff", "#ff6633", "#33ccff"]
    protocol_distribution = []
    for i, (name, cnt) in enumerate(proto_rows):
        protocol_distribution.append({
            "name": name,
            "count": int(cnt),
            "color": proto_colors.get(name, base_colors[i % len(base_colors)]),
        })

    # -- 8. hourly timeline (with per-family rollup) --
    hour_rows = (await session.execute(
        _range_filter(
            select(
                func.date_trunc("hour", Prediction.flow_timestamp).label("hour"),
                Prediction.prediction,
                Prediction.family,
                func.count(Prediction.id),
            )
                .group_by("hour", Prediction.prediction, Prediction.family)
                .order_by("hour"),
            range_key,
        )
    )).all()
    hourly_buckets: dict[str, dict[str, int]] = {}
    hourly_family: dict[str, dict[str, int]] = {}
    for hour_dt, pred, family, cnt in hour_rows:
        if hour_dt is None:
            continue
        hour_key = hour_dt.isoformat()
        bucket = hourly_buckets.setdefault(hour_key, {"normal": 0, "malicious": 0, "suspicious": 0})
        if pred == "Normal":
            bucket["normal"] += int(cnt)
        elif pred == "Suspicious":
            bucket["suspicious"] += int(cnt)
            if family:
                hourly_family.setdefault(hour_key, {})[family] = hourly_family.setdefault(hour_key, {}).get(family, 0) + int(cnt)
        else:
            bucket["malicious"] += int(cnt)
            if family:
                hourly_family.setdefault(hour_key, {})[family] = hourly_family.setdefault(hour_key, {}).get(family, 0) + int(cnt)
    hourly_timeline = [
        {
            "hour": h,
            "normal": v["normal"],
            "malicious": v["malicious"],
            "suspicious": v["suspicious"],
            "families": hourly_family.get(h, {}),
        }
        for h, v in sorted(hourly_buckets.items())
    ]

    # Legacy step-binned timeline — kept for back-compat with the older
    # AnalyticsPage timelineData consumer. Approximated from the hour
    # buckets to avoid a second pass over the data.
    timeline_data = []
    for i, h in enumerate(hourly_timeline):
        timeline_data.append({
            "step": i + 1,
            "normal": h["normal"],
            "suspicious": h["malicious"] + h["suspicious"],
        })

    # -- 9. MITRE tactic + technique counts --
    # Tactic counts. Same set-returning-function pattern as techniques —
    # text() with explicit casts is cleaner than SA's expression builder
    # for the jsonb_array_elements + GROUP BY combination.
    tactic_query = text("""
        SELECT tactic, COUNT(*) AS cnt
        FROM (
            SELECT elem->>'name' AS tactic
            FROM predictions, jsonb_array_elements(mitre->'tactics') AS elem
            WHERE mitre IS NOT NULL
              AND prediction != 'Normal'
              AND (CAST(:cutoff AS timestamptz) IS NULL
                   OR flow_timestamp >= CAST(:cutoff AS timestamptz))
        ) AS tactics
        WHERE tactic IS NOT NULL
        GROUP BY tactic
    """)
    tactic_cutoff = None
    if _RANGE_SECONDS.get(range_key) is not None:
        tactic_cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=_RANGE_SECONDS[range_key]  # type: ignore[arg-type]
        )
    tactic_rows = (await session.execute(tactic_query, {"cutoff": tactic_cutoff})).all()
    mitre_tactic_counts = []
    tactic_color: dict[str, str] = {}
    for i, (tname, cnt) in enumerate(sorted(tactic_rows, key=lambda r: -int(r[1]))):
        if not tname:
            continue
        color = _LEAF_PALETTE[i % len(_LEAF_PALETTE)]
        tactic_color[tname] = color
        mitre_tactic_counts.append({"tactic": tname, "count": int(cnt), "color": color})

    # Technique counts — keyed by id, carrying name + url + parent tactic.
    # The subquery hoists the JSONB-extracted columns into named ones we
    # can GROUP BY; Postgres won't resolve column aliases inside a
    # GROUP BY at the same level the expressions are defined.
    # Explicit ::timestamptz cast — asyncpg can't infer the type of a
    # bound NULL parameter, which surfaces as "could not determine data
    # type of parameter $1" the moment we pass cutoff=None for range=all.
    tech_query = text("""
        SELECT id, name, url, tactic, COUNT(*) AS cnt
        FROM (
            SELECT
                elem->>'id'                          AS id,
                elem->>'name'                        AS name,
                elem->>'url'                         AS url,
                (mitre->'tactics'->0->>'name')       AS tactic
            FROM predictions, jsonb_array_elements(mitre->'techniques') AS elem
            WHERE mitre IS NOT NULL
              AND prediction != 'Normal'
              AND (CAST(:cutoff AS timestamptz) IS NULL
                   OR flow_timestamp >= CAST(:cutoff AS timestamptz))
        ) AS techniques
        WHERE id IS NOT NULL
        GROUP BY id, name, url, tactic
        ORDER BY cnt DESC
    """)
    cutoff = None
    if _RANGE_SECONDS.get(range_key) is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=_RANGE_SECONDS[range_key])  # type: ignore[arg-type]
    tech_rows = (await session.execute(tech_query, {"cutoff": cutoff})).all()
    mitre_technique_counts = [
        {
            "id": row[0],
            "name": row[1],
            "url": row[2],
            "tactic": row[3] or "",
            "count": int(row[4]),
            "color": tactic_color.get(row[3] or "", "#cc66ff"),
        }
        for row in tech_rows if row[0]
    ]

    # -- 10. operational KPIs (MTTA, backlog, oldest unacked, closed) --
    kpi_row = (await session.execute(
        _range_filter(
            select(
                func.avg(
                    case(
                        (and_(Prediction.ack_state != "new", Prediction.ack_at.is_not(None)),
                         func.extract("epoch", Prediction.ack_at - Prediction.flow_timestamp)),
                        else_=None,
                    )
                ),
                func.count(case((Prediction.ack_state == "new", 1), else_=None)),
                func.count(case(
                    (and_(Prediction.ack_state != "new", Prediction.ack_at.is_not(None)), 1),
                    else_=None,
                )),
                func.max(case(
                    (Prediction.ack_state == "new",
                     func.extract("epoch", func.now() - Prediction.flow_timestamp)),
                    else_=None,
                )),
            ),
            range_key,
        )
    )).one()
    mtta_seconds, backlog, acked_in_window, oldest_age = kpi_row
    operational_kpis = {
        "mttaSeconds": float(mtta_seconds) if mtta_seconds is not None else None,
        "backlog": int(backlog or 0),
        "oldestUnackedAgeSeconds": float(oldest_age) if oldest_age is not None else 0,
        "ackedInWindow": int(acked_in_window or 0),
    }

    # -- 11. prior window (trend deltas) --
    prior_block: dict[str, Any] | None = None
    if range_key != "all":
        prior_q = _prior_window_filter(
            select(Prediction.prediction, Prediction.severity, Prediction.source),
            range_key,
        )
        if prior_q is not None:
            prior_rows = (await session.execute(prior_q)).all()
            p_normal = p_malicious = p_high = p_med = p_low = 0
            p_verdicts = {"confirmed": 0, "signature_only": 0, "ml_only": 0, "benign": 0}
            for pred, sev, src in prior_rows:
                if pred == "Normal":
                    p_normal += 1
                else:
                    p_malicious += 1
                    sv = (sev or "").lower()
                    if sv == "high":
                        p_high += 1
                    elif sv == "medium":
                        p_med += 1
                    elif sv == "low":
                        p_low += 1
                key = src or "benign"
                if key in p_verdicts:
                    p_verdicts[key] += 1
            prior_block = {
                "normalCount": p_normal,
                "maliciousCount": p_malicious,
                "severityCounts": {"high": p_high, "medium": p_med, "low": p_low},
                "verdictBreakdown": [
                    {"source": s, "count": p_verdicts[s]} for s in p_verdicts
                ],
            }

    total_filtered = normal_count + malicious_count
    total_store = await total_rows(session)

    return {
        "normalCount": normal_count,
        "maliciousCount": malicious_count,
        "suspiciousCount": suspicious_count,
        "timelineData": timeline_data,
        "topMaliciousIPs": top_malicious_ips,
        "severityCounts": severity_counts,
        "attackCategories": attack_categories,
        "protocolDistribution": protocol_distribution,
        # Feature importance was always a stub (averages of mlFeatures);
        # preserved with zeros so the dashboard's chart doesn't break.
        "featureImportance": [
            {"feature": f, "importance": 0.0}
            for f in (
                "sbytes", "dbytes", "dur", "spkts", "dpkts",
                "sload", "dload", "ct_srv_dst", "sttl", "dttl",
            )
        ],
        "verdictBreakdown": verdict_breakdown,
        "familyBreakdown": family_breakdown,
        "leafBreakdown": leaf_breakdown,
        "timeRangeApplied": range_key,
        "totalFlows": total_filtered,
        "storeTotal": total_store,
        "serverTime": datetime.now(timezone.utc).isoformat(),
        "topDestinations": top_destinations,
        "topTargetedPorts": top_targeted_ports,
        "attackerVictimPairs": attacker_victim_pairs,
        "severityByFamily": severity_by_family,
        "hourlyTimeline": hourly_timeline,
        "mitreTacticCounts": mitre_tactic_counts,
        "mitreTechniqueCounts": mitre_technique_counts,
        "operationalKpis": operational_kpis,
        "prior": prior_block,
    }
