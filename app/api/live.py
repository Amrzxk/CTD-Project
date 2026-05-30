"""
Live SSE endpoint and session lifecycle — session-aware hybrid stream.

The dashboard subscribes via ``GET /live/stream?session=<id>`` and the
generator joins two Redis Pub/Sub channels:

* ``flow_completed`` — published by either the global ``flow_meter_worker``
  (interface sessions) or the in-API PCAP replay coroutine (pcap sessions).
* ``snort_alerts``   — published by ``snort_tailer_worker`` (interface) or
  inline by the replay coroutine (pcap, when Snort offline runs).

For every event, the SSE generator runs ML inference on the flow stats
(if available in Redis) and looks up any matching Snort verdict. The
OR-gate policy resolves a hybrid ``source`` field (``confirmed``,
``signature_only``, ``ml_only``, ``benign``).

A short correlation buffer prevents emitting two events for the same flow
when the Snort alert and the flow completion arrive within ~5 s of each
other.

The session layer adds:

* ``POST   /live/session``           — start a new session (auto-stops any old one).
* ``GET    /live/session``           — describe the active session.
* ``DELETE /live/session/{id}``      — stop the active session.
* ``POST   /live/session/{id}/pcap`` — attach an uploaded PCAP and start replay.
* ``GET    /live/session/{id}/log``  — download the CSV or NDJSON log.

Detection-mode filter is applied inside ``_sse_generator``:

* ``ml``     — drop ``signature_only`` events; strip ``snort_*`` payload fields.
* ``snort``  — drop ``ml_only`` events; strip ``stage*_p`` / ``stage*_probs`` fields.
* ``hybrid`` — full payload as before.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, StreamingResponse

from app.auth.dependencies import get_current_user
from app.core.live_session import (
    LIVE_SESSION_EVENTS_CHANNEL,
    LiveSession,
    LiveSessionRegistry,
)
from app.core.pcap_replay import replay_pcap
from app.db.models import User
from app.api.schemas import LiveSessionOut, StartSessionRequest

router = APIRouter(prefix="/live", tags=["live"])
log = logging.getLogger(__name__)

FLOW_CHANNEL = "flow_completed"
SNORT_CHANNEL = "snort_alerts"
SNORT_HASH_PREFIX = "snort:"

# Correlation window: how long the joiner waits for the *other* side
# (Snort if ML arrived first, or vice versa) before emitting.
CORRELATION_WINDOW_S = float(os.getenv("CORRELATION_WINDOW_S", "2.5"))

# When True the joiner also emits "benign" events. Off by default to keep
# the dashboard signal-to-noise high.
EMIT_BENIGN = os.getenv("LIVE_EMIT_BENIGN", "0") == "1"

# Hard cap on uploaded PCAP size — defends against an analyst dropping a
# 20 GB capture into the API container. Override via env in test rigs.
LIVE_PCAP_REPLAY_MAX_BYTES = int(
    os.getenv("LIVE_PCAP_REPLAY_MAX_BYTES", str(2 * 1024 * 1024 * 1024))  # 2 GiB
)

# ---------------------------------------------------------------------------
# Flow-key parsing (mirrors flow_key() in app.core.key_utils)
# ---------------------------------------------------------------------------

def _parse_flow_key(key: str) -> dict[str, str | int]:
    """Reverse of ``flow_key()`` — extract 5-tuple parts from the key."""
    try:
        left, right, proto = key.rsplit("-", 2)
        src_ip, src_port = left.rsplit(":", 1)
        dst_ip, dst_port = right.rsplit(":", 1)
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": proto,
        }
    except (ValueError, AttributeError):
        return {"src_ip": "N/A", "dst_ip": "N/A", "src_port": 0,
                "dst_port": 0, "protocol": "TCP"}


# ---------------------------------------------------------------------------
# Pending-event correlation buffer
# ---------------------------------------------------------------------------

class _Pending:
    """In-memory buffer keyed by flow_key with TTL eviction.

    Holds at most one entry per flow_key while we wait for the matching
    side (flow ↔ snort). TTL eviction prevents unbounded growth.
    """

    __slots__ = ("_data", "_ttl")

    def __init__(self, ttl_seconds: float) -> None:
        self._data: dict[str, dict] = {}
        self._ttl = ttl_seconds

    def add_flow(self, key: str, ts: float) -> dict | None:
        entry = self._data.pop(key, None)
        if entry and entry.get("snort"):
            return entry["snort"]
        self._data[key] = {"flow_ts": ts}
        return None

    def add_snort(self, key: str, snort: dict, ts: float) -> bool:
        entry = self._data.pop(key, None)
        if entry and entry.get("flow_ts"):
            return True
        self._data[key] = {"snort_ts": ts, "snort": snort}
        return False

    def reap(self, now: float) -> list[tuple[str, dict]]:
        evicted: list[tuple[str, dict]] = []
        cutoff = now - self._ttl
        for key in list(self._data.keys()):
            entry = self._data[key]
            t = entry.get("flow_ts") or entry.get("snort_ts") or 0
            if t < cutoff:
                evicted.append((key, entry))
                del self._data[key]
        return evicted

    def pop(self, key: str) -> None:
        self._data.pop(key, None)


# ---------------------------------------------------------------------------
# Hybrid event builder
# ---------------------------------------------------------------------------

def _verdict(snort_present: bool, ml_pred: dict | None) -> str:
    ml_malicious = bool(ml_pred and ml_pred.get("prediction") == "Malicious")
    if snort_present and ml_malicious:
        return "confirmed"
    if snort_present and not ml_malicious:
        return "signature_only"
    if not snort_present and ml_malicious:
        return "ml_only"
    return "benign"


def _apply_hybrid_overrides_live(
    prediction_label: str,
    confidence: float,
    severity: str | None,
    attack_type: str | None,
    family: str | None,
    stage2_p: float | None,
    stage3_p: float | None,
    snort: dict | None,
    source: str,
) -> tuple[str, float, str | None, str | None, str | None]:
    """Mirror of `_apply_hybrid_overrides` in routes.py."""
    if source == "confirmed":
        prediction_label = "Malicious"
        if severity == "Low":
            severity = "Medium"
        s2 = float(stage2_p or 0.0)
        s3 = float(stage3_p or 0.0)
        if s2 and s3:
            confidence = round(s2 * s3, 4)
    elif source == "signature_only":
        prediction_label = "Malicious"
        severity = "High"
        msg = (snort or {}).get("snort_msg", "") if snort else ""
        if msg:
            attack_type = msg
        family = "Signature"
        confidence = 1.0
    elif source == "ml_only":
        prediction_label = "Suspicious"
        severity = "Low"
        s2 = float(stage2_p or 0.0)
        s3 = float(stage3_p or 0.0)
        if s2 and s3:
            confidence = round(s2 * s3, 4)
    return prediction_label, confidence, severity, attack_type, family


def _build_event(
    flow_key: str,
    flow_data: dict | None,
    snort: dict | None,
    ml_pred: dict | None,
    model_version: str,
) -> dict:
    parts = _parse_flow_key(flow_key)
    source = _verdict(snort_present=snort is not None, ml_pred=ml_pred)

    prediction_label = (ml_pred or {}).get("prediction", "Snort-Only" if snort else "Normal")
    confidence = float((ml_pred or {}).get("confidence", 0.0))
    severity = (ml_pred or {}).get("severity")
    attack_type = (ml_pred or {}).get("attack_type")
    family = (ml_pred or {}).get("family")
    stage1_p = float((ml_pred or {}).get("stage1_p", 0.0))
    stage2_p = (ml_pred or {}).get("stage2_p")
    stage2_probs = (ml_pred or {}).get("stage2_probs")
    stage3_p = (ml_pred or {}).get("stage3_p")
    stage3_probs = (ml_pred or {}).get("stage3_probs")

    prediction_label, confidence, severity, attack_type, family = (
        _apply_hybrid_overrides_live(
            prediction_label=prediction_label,
            confidence=confidence,
            severity=severity,
            attack_type=attack_type,
            family=family,
            stage2_p=stage2_p,
            stage3_p=stage3_p,
            snort=snort,
            source=source,
        )
    )

    return {
        "id": f"evt_{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "flow_key": flow_key,
        "src_ip": (snort or {}).get("src_ip") or parts["src_ip"],
        "dst_ip": (snort or {}).get("dst_ip") or parts["dst_ip"],
        "src_port": (snort or {}).get("src_port") or parts["src_port"],
        "dst_port": (snort or {}).get("dst_port") or parts["dst_port"],
        "protocol": (snort or {}).get("protocol") or parts["protocol"],
        "prediction": prediction_label,
        "confidence": round(confidence, 4),
        "severity": severity,
        "attack_type": attack_type,
        "family": family,
        "subtype": attack_type,
        "stage1_p": round(stage1_p, 4),
        "stage2_p": stage2_p,
        "stage2_probs": stage2_probs,
        "stage3_p": stage3_p,
        "stage3_probs": stage3_probs,
        "source": source,
        "model_version": model_version,
        "snort_msg": (snort or {}).get("snort_msg", ""),
        "snort_sid": int((snort or {}).get("snort_sid", 0) or 0),
        "snort_classtype": (snort or {}).get("snort_classtype", ""),
        "snort_priority": int((snort or {}).get("snort_priority", 0) or 0),
        "snort_action": (snort or {}).get("snort_action", ""),
        "snort_timestamp": (snort or {}).get("snort_timestamp", ""),
    }


# ---------------------------------------------------------------------------
# Detection-mode payload filter
# ---------------------------------------------------------------------------

_SNORT_FIELDS = (
    "snort_msg", "snort_sid", "snort_classtype",
    "snort_priority", "snort_action", "snort_timestamp",
)
_ML_FIELDS = ("stage1_p", "stage2_p", "stage2_probs", "stage3_p", "stage3_probs")


def _apply_mode_filter(event: dict, mode: str) -> dict | None:
    """Return ``event`` filtered for the session's detection mode, or None to drop.

    * ``hybrid`` — pass through unchanged.
    * ``ml``    — drop ``signature_only`` rows entirely (we explicitly don't
                  want Snort-derived verdicts in the ML-only stream); blank
                  out the snort_* fields on remaining rows so the UI does
                  not render Snort cards. ``confirmed`` is rewritten to
                  ``ml_only`` so the dashboard verdict pill stays honest.
    * ``snort`` — drop ``ml_only`` rows; blank out stage*_p / stage*_probs;
                  rewrite ``confirmed`` to ``signature_only`` for the same
                  reason.
    """
    source = event.get("source")
    if mode == "ml":
        if source == "signature_only":
            return None
        out = dict(event)
        for k in _SNORT_FIELDS:
            out[k] = "" if isinstance(out.get(k), str) else 0
        if source == "confirmed":
            out["source"] = "ml_only"
        return out
    if mode == "snort":
        if source == "ml_only":
            return None
        out = dict(event)
        for k in _ML_FIELDS:
            out[k] = None
        if source == "confirmed":
            out["source"] = "signature_only"
        return out
    # hybrid: identity
    return event


# ---------------------------------------------------------------------------
# ML inference helpers
# ---------------------------------------------------------------------------

async def _run_ml(
    redis_pool: aioredis.Redis,
    flow_key: str,
    model_manager,
    data_standardizer,
) -> tuple[dict | None, dict | None]:
    if not flow_key:
        return None, None
    raw_hash = await redis_pool.hgetall(flow_key)  # type: ignore[arg-type]
    if not raw_hash:
        return None, None
    if model_manager is None or data_standardizer is None:
        return None, raw_hash

    loop = asyncio.get_running_loop()

    def _infer():
        df = data_standardizer.from_redis_flow(raw_hash)
        preds = model_manager.predict(df)
        return preds[0] if preds else None

    try:
        ml_pred = await loop.run_in_executor(None, _infer)
        return ml_pred, raw_hash
    except Exception:
        log.exception("ML inference failed for flow_key=%s", flow_key)
        return None, raw_hash


async def _lookup_snort(redis_pool: aioredis.Redis, flow_key: str) -> dict | None:
    if not flow_key:
        return None
    raw = await redis_pool.hgetall(f"{SNORT_HASH_PREFIX}{flow_key}")  # type: ignore[arg-type]
    if not raw:
        return None
    for k in ("src_port", "dst_port", "snort_sid", "snort_priority"):
        if k in raw:
            try:
                raw[k] = int(raw[k])
            except (TypeError, ValueError):
                pass
    return raw


# ---------------------------------------------------------------------------
# SSE generator
# ---------------------------------------------------------------------------

async def _sse_generator(
    request: Request,
    redis_pool: aioredis.Redis,
    session: LiveSession | None,
):
    """Drive the SSE event stream.

    ``session`` is the in-process active session at subscribe time. When
    None (legacy/no-session connect), the generator runs in ``hybrid`` mode
    with the global ``traffic_logger`` as the only sink — preserving the
    pre-session-aware contract for tools that still hit ``/live/stream``
    without a session id.
    """
    model_manager = request.app.state.model_manager
    data_standardizer = request.app.state.data_standardizer
    legacy_logger = getattr(request.app.state, "traffic_logger", None)
    mitre_mapper = getattr(request.app.state, "mitre_mapper", None)
    model_version = getattr(request.app.state, "model_version", "unknown")

    detection_mode = session.detection_mode if session is not None else "hybrid"
    session_id = session.id if session is not None else None
    # When `persist_to_alerts=True`, the per-session live_persister task
    # owns BOTH the DB writes AND the SessionLogger writes — drop the
    # SSE-side logger handle so we don't double-write every CSV row.
    # Sessions started without persistence still rely on the SSE path
    # for the per-session log artefact.
    persister_owns_log = bool(
        session is not None and session.persist_to_alerts
    )
    session_logger = (
        session.logger if (session is not None and not persister_owns_log) else None
    )
    session_source = session.source if session is not None else None

    # Warm-up gate: pcap-mode sessions silence FLOW_CHANNEL traffic until the
    # PCAP is actually attached. Without this, any flow_meter publishes that
    # arrive between `start_session` and `attach_pcap` leak through as
    # "session B saw events before its PCAP loaded" — see SESSION_HANDOFF
    # #3. Mutable local; flipped by the `pcap_attached` lifecycle event.
    pcap_attached_local = (
        session.pcap_attached
        if (session is not None and session_source == "pcap")
        else True
    )

    pubsub = redis_pool.pubsub()
    await pubsub.subscribe(FLOW_CHANNEL, SNORT_CHANNEL, LIVE_SESSION_EVENTS_CHANNEL)

    pending = _Pending(ttl_seconds=CORRELATION_WINDOW_S)

    async def emit(flow_key: str, snort: dict | None) -> str | None:
        ml_pred, flow_data = await _run_ml(
            redis_pool, flow_key, model_manager, data_standardizer
        )
        # ``snort``-only mode skips ML cost entirely.
        if detection_mode == "snort":
            ml_pred = None

        if (
            snort is None
            and (ml_pred is None or ml_pred.get("prediction") != "Malicious")
            and not EMIT_BENIGN
        ):
            return None
        if flow_data is None and snort is None:
            return None

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
            return None

        # Per-session logger (preferred) + legacy logger (back-compat).
        if session_logger is not None:
            try:
                session_logger.log(filtered)
            except Exception:
                log.debug("session_logger.log failed", exc_info=True)
        if legacy_logger is not None:
            try:
                legacy_logger.log(filtered)
            except Exception:
                log.debug("legacy traffic_logger.log failed", exc_info=True)

        # Persistence to the Alerts queue is owned by the per-session
        # `live_persister` background task (see core/live_persister.py).
        # The SSE generator is intentionally read-only on the DB so the
        # row count doesn't multiply with the number of connected clients.

        return f"data: {json.dumps(filtered, default=str)}\n\n"

    last_reap = time.monotonic()
    try:
        async for raw_msg in pubsub.listen():
            if await request.is_disconnected():
                break

            if raw_msg["type"] != "message":
                continue

            channel = raw_msg["channel"]
            now = time.monotonic()

            # Lifecycle short-circuit — if our session was stopped, close.
            if channel == LIVE_SESSION_EVENTS_CHANNEL:
                try:
                    payload = json.loads(raw_msg["data"])
                except (json.JSONDecodeError, TypeError):
                    continue
                event_name = payload.get("event")
                if event_name == "stopped" and (
                    session_id is None or payload.get("session_id") == session_id
                ):
                    yield (
                        "event: session_ended\n"
                        f"data: {json.dumps({'session_id': session_id, 'reason': payload.get('reason')})}\n\n"
                    )
                    break
                if (
                    event_name == "pcap_attached"
                    and session_id is not None
                    and payload.get("session_id") == session_id
                ):
                    pcap_attached_local = True
                continue

            if now - last_reap > CORRELATION_WINDOW_S:
                for evicted_key, entry in pending.reap(now):
                    payload_text = await emit(
                        flow_key=evicted_key,
                        snort=entry.get("snort"),
                    )
                    if payload_text:
                        yield payload_text
                last_reap = now


            try:
                if channel == FLOW_CHANNEL:
                    # PCAP warm-up gate — drop flow_completed pings that
                    # arrive before the PCAP is attached (likely leftovers
                    # from a previous session or a concurrent interface
                    # publisher).
                    if not pcap_attached_local:
                        continue
                    flow_key = str(raw_msg["data"]).strip()
                    if not flow_key:
                        continue
                    snort_buf = pending.add_flow(flow_key, now)
                    if snort_buf is not None:
                        payload_text = await emit(flow_key=flow_key, snort=snort_buf)
                    else:
                        snort_hash = await _lookup_snort(redis_pool, flow_key)
                        payload_text = await emit(flow_key=flow_key, snort=snort_hash)
                        if payload_text is not None:
                            pending.pop(flow_key)
                    if payload_text:
                        yield payload_text

                elif channel == SNORT_CHANNEL:
                    try:
                        snort = json.loads(raw_msg["data"])
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if snort.get("ping"):
                        continue
                    flow_key = snort.get("flow_key", "")
                    if not flow_key:
                        continue
                    already_have_flow = pending.add_snort(flow_key, snort, now)
                    if already_have_flow:
                        payload_text = await emit(flow_key=flow_key, snort=snort)
                        if payload_text:
                            yield payload_text

            except Exception:
                log.exception("SSE generator: error handling message on %s", channel)

    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe(FLOW_CHANNEL, SNORT_CHANNEL, LIVE_SESSION_EVENTS_CHANNEL)
        await pubsub.close()


# ---------------------------------------------------------------------------
# SSE route
# ---------------------------------------------------------------------------

@router.get("/stream")
async def live_stream(
    request: Request,
    session: str | None = Query(None, description="Live session id"),
    _user: User = Depends(get_current_user),
):
    """SSE endpoint — parallel hybrid ML + Snort stream.

    With no ``?session=`` parameter we fall back to the *current* registry
    session (the only one allowed at a time). Old clients that hit this
    URL without a session id still get a coherent stream.
    """
    redis_pool: Optional[aioredis.Redis] = getattr(
        request.app.state, "redis_pool", None
    )
    if redis_pool is None:
        raise HTTPException(status_code=503, detail="Redis pool not initialized")

    registry: LiveSessionRegistry | None = getattr(
        request.app.state, "live_sessions", None
    )
    current = registry.current() if registry is not None else None
    if session and (current is None or current.id != session):
        # The session may have started on a different worker. Trust the
        # cross-worker Redis record for detection_mode; we won't have a
        # logger handle but the SSE filter still works.
        if registry is not None:
            shadow = await registry.current_from_redis()
            if shadow is not None and shadow.get("id") == session:
                current = LiveSession(
                    id=shadow["id"],
                    source=shadow["source"],
                    detection_mode=shadow["detection_mode"],
                    started_at=datetime.fromisoformat(shadow["started_at"]),
                    owner_user_id=int(shadow.get("owner_user_id", 0)),
                    pcap_speed=shadow.get("pcap_speed"),
                    pcap_attached=bool(shadow.get("pcap_attached")),
                    persist_to_alerts=bool(shadow.get("persist_to_alerts")),
                )

    return StreamingResponse(
        _sse_generator(request, redis_pool, current),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Session endpoints
# ---------------------------------------------------------------------------

def _registry(request: Request) -> LiveSessionRegistry:
    reg: LiveSessionRegistry | None = getattr(
        request.app.state, "live_sessions", None
    )
    if reg is None:
        raise HTTPException(status_code=503, detail="Session registry not initialized")
    return reg


@router.get("/session", response_model=Optional[LiveSessionOut])
async def get_current_session(
    request: Request,
    response: Response,
    _user: User = Depends(get_current_user),
):
    """Return the active session (in-process or cross-worker), or null."""
    # Live control-plane state — never cache, or a stopped session can look
    # active (or vice-versa) after a reconnect.
    response.headers["Cache-Control"] = "no-store"
    registry = _registry(request)
    current = registry.current()
    if current is not None:
        return LiveSessionOut(**current.to_public_dict())
    shadow = await registry.current_from_redis()
    if not shadow:
        return None
    return LiveSessionOut(
        session_id=shadow["id"],
        source=shadow["source"],
        detection_mode=shadow["detection_mode"],
        speed=shadow.get("pcap_speed"),
        started_at=datetime.fromisoformat(shadow["started_at"]),
        pcap_attached=bool(shadow.get("pcap_attached")),
        persist_to_alerts=bool(shadow.get("persist_to_alerts")),
        log_csv_url=f"/live/session/{shadow['id']}/log?format=csv",
        log_ndjson_url=f"/live/session/{shadow['id']}/log?format=ndjson",
        row_count=0,
    )


@router.post("/session", response_model=LiveSessionOut)
async def start_session(
    request: Request,
    payload: StartSessionRequest,
    user: User = Depends(get_current_user),
):
    """Start a new live session (auto-stops any existing one).

    ``source="interface"`` consumes the existing global flow_meter +
    snort_tailer publishes. ``source="pcap"`` returns immediately; the
    caller must follow up with ``POST /live/session/{id}/pcap``.
    """
    registry = _registry(request)
    if payload.source == "pcap" and payload.speed is not None and payload.speed < 0:
        raise HTTPException(status_code=400, detail="speed must be >= 0")

    session = await registry.start(
        source=payload.source,
        detection_mode=payload.detection_mode,
        owner_user_id=int(user.id),
        speed=payload.speed,
        persist_to_alerts=payload.persist_to_alerts,
    )
    return LiveSessionOut(**session.to_public_dict())


@router.delete("/session/{session_id}")
async def stop_session(
    request: Request,
    session_id: str,
    _user: User = Depends(get_current_user),
):
    """Stop the active session if it matches ``session_id``."""
    registry = _registry(request)
    stopped = await registry.stop(session_id=session_id)
    return {"stopped": stopped, "session_id": session_id}


@router.post("/session/{session_id}/pcap", response_model=LiveSessionOut)
async def attach_pcap(
    request: Request,
    session_id: str,
    file: UploadFile = File(...),
    _user: User = Depends(get_current_user),
):
    """Attach an uploaded PCAP to a pcap-mode session and start replay."""
    registry = _registry(request)
    current = registry.current()
    if current is None or current.id != session_id:
        raise HTTPException(status_code=404, detail="session not found")
    if current.source != "pcap":
        raise HTTPException(status_code=400, detail="session is not a pcap session")
    if current.pcap_attached:
        raise HTTPException(status_code=409, detail="pcap already attached")

    ext = (file.filename or "").lower()
    if not (ext.endswith(".pcap") or ext.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="file must be .pcap or .pcapng")

    suffix = ".pcapng" if ext.endswith(".pcapng") else ".pcap"
    tmp = tempfile.NamedTemporaryFile(
        prefix="live_pcap_", suffix=suffix, delete=False
    )
    written = 0
    try:
        try:
            while True:
                chunk = await file.read(1 << 20)
                if not chunk:
                    break
                written += len(chunk)
                if written > LIVE_PCAP_REPLAY_MAX_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"pcap exceeds {LIVE_PCAP_REPLAY_MAX_BYTES} bytes",
                    )
                tmp.write(chunk)
        finally:
            tmp.close()
    except HTTPException:
        Path(tmp.name).unlink(missing_ok=True)
        raise
    except Exception:
        Path(tmp.name).unlink(missing_ok=True)
        log.exception("pcap upload failed")
        raise HTTPException(status_code=500, detail="pcap upload failed")

    redis_pool = getattr(request.app.state, "redis_pool", None)
    if redis_pool is None:
        Path(tmp.name).unlink(missing_ok=True)
        raise HTTPException(status_code=503, detail="Redis pool not initialized")

    speed = float(current.pcap_speed or 0.0)
    task = asyncio.create_task(
        replay_pcap(
            pcap_path=tmp.name,
            speed=speed,
            detection_mode=current.detection_mode,
            session_id=current.id,
            redis_pool=redis_pool,
            stop_event=current.stop_event,
        )
    )

    await registry.attach_pcap(
        session_id=session_id,
        pcap_path=tmp.name,
        replay_task=task,
    )
    return LiveSessionOut(**current.to_public_dict())


@router.get("/session/{session_id}/log")
async def download_session_log(
    request: Request,
    session_id: str,
    format: str = Query("csv", regex="^(csv|ndjson)$"),
    _user: User = Depends(get_current_user),
):
    """Download the per-session log in CSV or NDJSON."""
    registry = _registry(request)
    current = registry.current()
    if current is None or current.id != session_id:
        raise HTTPException(status_code=404, detail="session not found")
    if current.logger is None:
        raise HTTPException(status_code=404, detail="session logger missing")

    path = (
        current.logger.csv_path if format == "csv" else current.logger.ndjson_path
    )
    if not path.exists():
        raise HTTPException(status_code=404, detail="log file not yet written")

    media = "text/csv" if format == "csv" else "application/x-ndjson"
    return FileResponse(
        path=str(path),
        media_type=media,
        filename=path.name,
    )


# ---------------------------------------------------------------------------
# Legacy log file management (preserved)
# ---------------------------------------------------------------------------

@router.get("/logs")
async def get_logs(
    request: Request,
    _user: User = Depends(get_current_user),
):
    """List all legacy traffic log files."""
    logger = request.app.state.traffic_logger
    return logger.get_log_files()


@router.get("/logs/{filename}")
async def download_log(
    request: Request,
    filename: str,
    _user: User = Depends(get_current_user),
):
    """Download a specific legacy traffic log CSV."""
    logger = request.app.state.traffic_logger
    path = logger.get_log_path(filename)

    if not path:
        raise HTTPException(status_code=404, detail="Log file not found")

    return FileResponse(
        path=str(path),
        media_type="text/csv",
        filename=filename,
    )
