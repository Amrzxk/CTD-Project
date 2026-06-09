"""
Per-session background persister — writes live events to the Alerts queue
regardless of whether any SSE client is subscribed.

Why a dedicated task: the SSE generator (``app/api/live.py:_sse_generator``)
only runs while a browser is actively connected to ``/live/stream``. Tying
persistence to it meant a session with the page closed (or stopped from a
different worker) silently dropped its rows. Analysts expect
"session running = events in /alerts" — this module makes that true.

Lifecycle:
* Spawned by ``LiveSessionRegistry.start()`` when ``persist_to_alerts=True``.
* Subscribes to the same Redis pub/sub channels the SSE consumes.
* Mirrors the SSE generator's snort↔flow correlation buffer + warm-up gate
  so the persisted events match what the dashboard sees.
* Cancelled by the registry's ``_stop_locked()`` on session stop. The
  ``finally`` block drains the partial buffer so no rows are lost on a
  clean stop.

The persister and the SSE generator both see the same Redis stream and
both build events. Persisted writes live exclusively in this task — the
SSE generator no longer touches the DB. This guarantees one row per
(flow, snort) regardless of subscriber count.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any

import redis.asyncio as aioredis

from app.db import SessionLocal
from app.db.repositories import (
    predictions as predictions_repo,
    suppressions as suppressions_repo,
)

if TYPE_CHECKING:
    from .live_session import LiveSession


log = logging.getLogger(__name__)


# Flush thresholds — duplicated of the SSE generator constants so the
# persister has independent tuning. Same defaults; override per-env.
import os as _os

FLOW_CHANNEL = "flow_completed"
SNORT_CHANNEL = "snort_alerts"
SNORT_HASH_PREFIX = "snort:"
LIVE_SESSION_EVENTS_CHANNEL = "live_session_events"

PERSIST_BATCH_SIZE = int(_os.getenv("LIVE_PERSIST_BATCH_SIZE", "200"))
PERSIST_FLUSH_INTERVAL_S = float(_os.getenv("LIVE_PERSIST_FLUSH_INTERVAL_S", "0.25"))
# Flow side: short wait for a same-instant Snort alert. Snort side: long hold
# so a Snort hit waits for its flow to export (NFStream idle/active timeout)
# and ML can run on it → `confirmed`. Mirrors app/api/live.py so the persister
# and SSE produce identical verdicts. See _Pending in app/api/live.py.
CORRELATION_WINDOW_S = float(_os.getenv("CORRELATION_WINDOW_S", "2.5"))
SNORT_JOIN_WAIT_S = float(_os.getenv("SNORT_JOIN_WAIT_S", "20"))

# Diagnostic toggle (default off). When set, benign events are written to the
# per-session NDJSON/CSV log — but NOT inserted into the predictions DB and NOT
# emitted to the dashboard SSE. Used to capture the production NFStream benign
# score distribution for Stage-1 threshold (tau1) recalibration; benign is
# high-volume so this is off in normal operation.
LOG_BENIGN = _os.getenv("LOG_BENIGN", "0") == "1"


async def run_persister(
    session: "LiveSession",
    redis_pool: aioredis.Redis,
    model_manager: Any,
    data_standardizer: Any,
    mitre_mapper: Any,
    model_version: str,
) -> None:
    """Subscribe + persist loop. Returns on stop_event or on session_ended.

    All event-building logic is delegated to helpers in
    ``app.api.live`` so the SSE and the persister produce identical event
    dicts. The only divergence is the sink: SSE yields a text frame, this
    task buffers and bulk-inserts.
    """
    # Local imports to dodge the api ↔ core ↔ persister circular when
    # this module is imported at registry start time.
    from app.api.live import (
        _Pending,
        _apply_mode_filter,
        _build_event,
        _lookup_snort,
        _run_ml,
    )

    session_id = session.id
    detection_mode = session.detection_mode
    session_source = session.source
    stop_event = session.stop_event
    # Per-session logger is owned by the registry; we pull a handle here
    # so the persister can write to the CSV/NDJSON when no SSE client is
    # connected. Without this, a headless session produces a downloadable
    # file with only the CSV header (the SSE generator is the only other
    # writer and it never ran). Calls into SessionLogger are guarded — it
    # has its own try/except internally and is a no-op after close().
    session_logger = session.logger

    pcap_attached_local = (
        session.pcap_attached if session_source == "pcap" else True
    )

    pubsub = redis_pool.pubsub()
    await pubsub.subscribe(FLOW_CHANNEL, SNORT_CHANNEL, LIVE_SESSION_EVENTS_CHANNEL)

    pending = _Pending(flow_ttl=CORRELATION_WINDOW_S, snort_ttl=SNORT_JOIN_WAIT_S)
    persist_buffer: list[dict] = []
    last_persist_flush = time.monotonic()
    last_reap = time.monotonic()

    # Per-verdict diagnostics. Proves the hybrid join is balanced and that
    # ml_only actually reaches the DB (the bug this module previously had:
    # flow-only events were parked for the reap, their Redis hash expired
    # before it fired, and they were silently dropped as benign).
    stats = {
        "flows_seen": 0, "snort_seen": 0,
        "confirmed": 0, "signature_only": 0, "ml_only": 0,
        "benign_dropped": 0,
    }

    async def _flush() -> None:
        nonlocal last_persist_flush
        if not persist_buffer:
            last_persist_flush = time.monotonic()
            return
        batch = persist_buffer[:]
        persist_buffer.clear()
        try:
            async with SessionLocal() as db:
                try:
                    kept, dropped = await suppressions_repo.filter_predictions(db, batch)
                    if kept:
                        await predictions_repo.insert_many(db, kept)
                    await db.commit()
                    if kept or dropped:
                        log.info(
                            "live_persister[%s]: flushed kept=%d dropped=%d | "
                            "totals confirmed=%d signature_only=%d ml_only=%d "
                            "benign_dropped=%d (flows=%d snort=%d)",
                            session_id, len(kept), dropped,
                            stats["confirmed"], stats["signature_only"],
                            stats["ml_only"], stats["benign_dropped"],
                            stats["flows_seen"], stats["snort_seen"],
                        )
                except Exception:
                    await db.rollback()
                    raise
        except Exception:
            log.exception(
                "live_persister[%s]: flush failed (batch of %d dropped)",
                session_id, len(batch),
            )
        last_persist_flush = time.monotonic()

    async def _process_pair(flow_key: str, snort: dict | None) -> None:
        if not flow_key:
            return
        ml_pred, flow_data = await _run_ml(
            redis_pool, flow_key, model_manager, data_standardizer
        )
        # `snort`-only mode skips ML cost entirely.
        if detection_mode == "snort":
            ml_pred = None
        is_benign = snort is None and (
            ml_pred is None or ml_pred.get("prediction") != "Malicious"
        )
        if is_benign and not LOG_BENIGN:
            stats["benign_dropped"] += 1
            return  # benign — neither logged nor persisted (default)
        # With LOG_BENIGN set we fall through so benign reaches the NDJSON/CSV
        # log below; the `source == "benign"` skip further down still keeps it
        # out of the Alerts queue (and the dashboard SSE never sees it).
        if flow_data is None and snort is None:
            return

        event = _build_event(
            flow_key=flow_key,
            flow_data=flow_data,
            snort=snort,
            ml_pred=ml_pred,
            model_version=model_version,
        )
        if mitre_mapper:
            event = mitre_mapper.enrich_prediction(event)
        else:
            event["mitre"] = None

        filtered = _apply_mode_filter(event, detection_mode)
        if filtered is None:
            return

        # Write the per-session log artefacts before the benign skip — when
        # LOG_BENIGN is set we want benign events in the CSV/NDJSON (forensic /
        # tau1 calibration) even though they never belong in the Alerts queue.
        if session_logger is not None:
            try:
                session_logger.log(filtered)
            except Exception:
                log.debug("session_logger.log failed in persister", exc_info=True)

        if (filtered.get("source") or "").lower() == "benign":
            stats["benign_dropped"] += 1
            return
        src = (filtered.get("source") or "").lower()
        if src in stats:
            stats[src] += 1
        persist_buffer.append(
            predictions_repo.live_event_to_insert_dict(filtered)
        )
        if len(persist_buffer) >= PERSIST_BATCH_SIZE:
            await _flush()

    log.info(
        "live_persister[%s]: started (source=%s mode=%s)",
        session_id, session_source, detection_mode,
    )
    try:
        # We poll the pubsub with a short timeout so the time-based flush
        # check can run even when no Redis traffic is arriving. The SSE
        # generator can rely on `pubsub.listen()` because it has the
        # disconnect signal to fall back on; we need an explicit timer.
        while not stop_event.is_set():
            try:
                raw_msg = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=0.25,
                )
            except Exception:
                log.exception("live_persister[%s]: pubsub.get_message failed", session_id)
                break
            now = time.monotonic()

            # Periodic flush — runs on every poll wakeup whether or not
            # a message arrived. Bounds tail latency.
            if (
                persist_buffer
                and now - last_persist_flush >= PERSIST_FLUSH_INTERVAL_S
            ):
                await _flush()

            # Reap expired pending entries so stale flow-only or
            # snort-only events get emitted/persisted instead of sitting
            # forever in the joiner.
            if now - last_reap > CORRELATION_WINDOW_S:
                for evicted_key, entry in pending.reap(now):
                    await _process_pair(evicted_key, entry.get("snort"))
                last_reap = now

            if raw_msg is None:
                continue
            channel = raw_msg.get("channel")
            data = raw_msg.get("data")

            try:
                if channel == LIVE_SESSION_EVENTS_CHANNEL:
                    try:
                        import json as _json
                        payload = _json.loads(data)
                    except (ValueError, TypeError):
                        continue
                    event_name = payload.get("event")
                    if (
                        event_name == "stopped"
                        and payload.get("session_id") == session_id
                    ):
                        log.info(
                            "live_persister[%s]: session_ended; draining",
                            session_id,
                        )
                        return
                    if (
                        event_name == "pcap_attached"
                        and payload.get("session_id") == session_id
                    ):
                        pcap_attached_local = True
                    continue

                if channel == FLOW_CHANNEL:
                    if not pcap_attached_local:
                        # Warm-up gate: drop flow_completed for pcap sessions
                        # before their pcap is attached (mirrors SSE).
                        continue
                    flow_key = str(data).strip()
                    if not flow_key:
                        continue
                    stats["flows_seen"] += 1
                    snort_buf = pending.add_flow(flow_key, now)
                    if snort_buf is not None:
                        await _process_pair(flow_key, snort_buf)
                    else:
                        # Mirror the SSE generator (app/api/live.py): a flow with
                        # no buffered Snort alert is processed IMMEDIATELY while
                        # its Redis hash is still fresh — the snort-hash lookup
                        # joins a confirmed verdict if Snort already fired, else
                        # ML runs and emits ml_only. Previously this branch did
                        # nothing for the no-snort case and left the flow to the
                        # reap timer; under the Docker CORRELATION_WINDOW_S the
                        # reap fired long after FLOW_TTL_SECONDS, the hash had
                        # expired, ML returned nothing, and every ml_only event
                        # was silently dropped as benign.
                        snort_hash = await _lookup_snort(redis_pool, flow_key)
                        pending.pop(flow_key)
                        await _process_pair(flow_key, snort_hash)

                elif channel == SNORT_CHANNEL:
                    try:
                        import json as _json
                        snort = _json.loads(data)
                    except (ValueError, TypeError):
                        continue
                    if snort.get("ping"):
                        continue
                    flow_key = snort.get("flow_key", "")
                    if not flow_key:
                        continue
                    stats["snort_seen"] += 1
                    already_have_flow = pending.add_snort(flow_key, snort, now)
                    if already_have_flow:
                        await _process_pair(flow_key, snort)
            except Exception:
                log.exception(
                    "live_persister[%s]: error handling channel=%s",
                    session_id, channel,
                )
    except asyncio.CancelledError:
        log.info("live_persister[%s]: cancelled", session_id)
    finally:
        # Drain the correlation buffer first: held Snort-only entries (kept
        # for up to SNORT_JOIN_WAIT_S waiting for a flow that never came)
        # would otherwise be lost on stop. Force-evict and emit them as
        # signature_only before the final buffer flush.
        try:
            for evicted_key, entry in pending.drain():
                await _process_pair(evicted_key, entry.get("snort"))
        except Exception:
            log.debug("live_persister[%s]: pending drain failed",
                      session_id, exc_info=True)
        # Drain anything left in the buffer so a clean stop preserves the
        # tail of the session. A best-effort attempt — DB blip here is
        # logged and swallowed since the session is already going down.
        if persist_buffer:
            try:
                await _flush()
            except Exception:
                log.debug("live_persister[%s]: final flush failed",
                          session_id, exc_info=True)
        try:
            await pubsub.unsubscribe(
                FLOW_CHANNEL, SNORT_CHANNEL, LIVE_SESSION_EVENTS_CHANNEL
            )
            await pubsub.close()
        except Exception:
            log.debug("live_persister[%s]: pubsub teardown failed",
                      session_id, exc_info=True)
        log.info(
            "live_persister[%s]: stopped | session totals confirmed=%d "
            "signature_only=%d ml_only=%d benign_dropped=%d "
            "(flows_seen=%d snort_seen=%d)",
            session_id, stats["confirmed"], stats["signature_only"],
            stats["ml_only"], stats["benign_dropped"],
            stats["flows_seen"], stats["snort_seen"],
        )
