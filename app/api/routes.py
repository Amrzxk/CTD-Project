"""HTTP routes for the analyst-facing API.

Refactored in Phase 2 of the persistence migration: every query that
previously touched the in-memory ``predictions_store`` list now goes
through ``app.db.repositories.predictions``. Response shapes are
preserved so the dashboard contract doesn't change.

What stayed in this file:
* The hybrid verdict logic (`_hybrid_source`, `_apply_hybrid_overrides`).
* `_format_predictions()` — the function that builds the
  per-flow dict from raw NFStream output + ML predictions + Snort
  alerts. The dict it produces is the insert payload for
  `predictions_repo.insert_many`.
* The upload + manual + streaming-upload endpoints — they orchestrate
  feature extraction, ML inference, Snort replay, suppression, then
  hand off to the repo.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pandas as pd
from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, require_admin
from app.core import snort_offline
from app.core.key_utils import flow_key as build_flow_key
from app.db import get_session
from app.db.models import User
from app.db.repositories import (
    ack_history as ack_history_repo,
    predictions as predictions_repo,
    suppressions as suppressions_repo,
)
from app.utils.validators import validate_flow_input
from .schemas import (
    AckRequest,
    BulkAckRequest,
    ManualFlowInput,
    SuppressionRequest,
)

log = logging.getLogger(__name__)

_upload_executor = ThreadPoolExecutor(max_workers=2)

router = APIRouter()

# Allowed ack states for body validation. Pydantic already enforces this
# via Literal, but the bare set is handy for the ack/by-match endpoint
# which takes an untyped body for flexibility.
_ACK_STATES = {"new", "reviewed", "escalated", "dismissed"}

_PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", 132: "SCTP"}


def _set_no_cache(response: Response) -> None:
    """Force the browser to never cache an API response.

    Live data; cached views would lie to the analyst within seconds.
    Applied to every endpoint reading prediction state.
    """
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"


# ----------------------------------------------------------------------
# Helpers preserved from the in-memory implementation
# ----------------------------------------------------------------------

def _get_val(row, keys, default):
    for k in keys:
        if k in row.index and pd.notna(row[k]):
            return row[k]
    return default


def _resolve_protocol(row) -> str:
    name = _get_val(row, ["protocol_name"], None)
    if name and str(name) not in ("nan", "0", ""):
        return str(name)
    num = _get_val(row, ["Protocol", "protocol"], None)
    if num is not None:
        try:
            return _PROTO_MAP.get(int(float(num)), str(num))
        except (ValueError, TypeError):
            return str(num)
    return "N/A"


def _hybrid_source(snort_hit: bool, ml_pred: dict) -> str:
    ml_mal = ml_pred.get("prediction") == "Malicious"
    if snort_hit and ml_mal:
        return "confirmed"
    if snort_hit and not ml_mal:
        return "signature_only"
    if not snort_hit and ml_mal:
        return "ml_only"
    return "benign"


def _apply_hybrid_overrides(p: dict, snort_payload: dict | None, source: str) -> None:
    """Rewrite user-visible fields based on the hybrid verdict cell.

    Hierarchy: signature wins on signature_only; ML leaf wins on
    confirmed; ml_only is demoted to "Suspicious + Low" because the eval
    data shows ml_only precision = 0.48 — most are calibration FPs.

    Confidence drops the stage1_p multiplier (stage 1 is
    calibration-shifted routing, not a trust signal). New confidence =
    stage2_p × stage3_p.
    """
    if source == "confirmed":
        p["prediction"] = "Malicious"
        if p.get("severity") == "Low":
            p["severity"] = "Medium"
        s2 = float(p.get("stage2_p") or 0.0)
        s3 = float(p.get("stage3_p") or 0.0)
        if s2 and s3:
            p["confidence"] = round(s2 * s3, 4)
    elif source == "signature_only":
        p["prediction"] = "Malicious"
        p["severity"] = "High"
        msg = (snort_payload or {}).get("snort_msg", "") if snort_payload else ""
        if msg:
            p["attack_type"] = msg
            p["subtype"] = msg
        p["family"] = "Signature"
        p["confidence"] = 1.0
    elif source == "ml_only":
        p["prediction"] = "Suspicious"
        p["severity"] = "Low"
        s2 = float(p.get("stage2_p") or 0.0)
        s3 = float(p.get("stage3_p") or 0.0)
        if s2 and s3:
            p["confidence"] = round(s2 * s3, 4)
    # benign — leave as-is.


def _format_predictions(
    df: "pd.DataFrame",
    predictions: list[dict],
    snort_alerts: dict[str, dict],
    mitre_mapper,
    model_version: str,
) -> list[dict]:
    """Build the API-shape per-flow response list.

    Shared between `/analyze/upload`, `/analyze/upload/stream`, and as
    the insert payload for `predictions_repo.insert_many`.
    """
    out: list[dict] = []
    for i, pred in enumerate(predictions):
        row = df.iloc[i]

        flow_ts: str | None = None
        first_seen = _get_val(row, ["bidirectional_first_seen_ms"], None)
        if first_seen is not None:
            try:
                ms = float(first_seen)
                if ms > 0:
                    flow_ts = datetime.fromtimestamp(ms / 1000.0).isoformat()
            except (ValueError, TypeError):
                pass
        if flow_ts is None:
            ts_csv = _get_val(row, ["Timestamp", "timestamp"], None)
            if ts_csv is not None:
                try:
                    parsed = pd.to_datetime(ts_csv, errors="coerce")
                    if parsed is not None and not pd.isna(parsed):
                        flow_ts = parsed.isoformat()
                except (ValueError, TypeError):
                    pass
        if flow_ts is None:
            flow_ts = datetime.now().isoformat()

        src_ip = str(_get_val(row, ["src_ip", "Source IP", "Src IP"], "N/A"))
        dst_ip = str(_get_val(row, ["dst_ip", "Destination IP", "Dst IP"], "N/A"))
        src_port = int(_get_val(row, ["src_port", "Source Port", "Src Port"], 0))
        dst_port = int(_get_val(row, ["Dst Port", "dst_port", "Destination Port"], 0))
        proto_name = _resolve_protocol(row)

        snort_payload = None
        if snort_alerts:
            k_fwd = build_flow_key(src_ip, dst_ip, src_port, dst_port, proto_name)
            k_rev = build_flow_key(dst_ip, src_ip, dst_port, src_port, proto_name)
            snort_payload = snort_alerts.get(k_fwd) or snort_alerts.get(k_rev)

        source = _hybrid_source(snort_hit=snort_payload is not None, ml_pred=pred)
        pred_view = dict(pred)
        _apply_hybrid_overrides(pred_view, snort_payload, source)

        prediction_obj = {
            "id": f"batch_{uuid.uuid4()}_{i}",
            "timestamp": flow_ts,
            "sourceIp": src_ip,
            "destinationIp": dst_ip,
            "sourcePort": src_port,
            "destinationPort": dst_port,
            "protocol": proto_name,
            "packetSize": int(_get_val(row, ["bidirectional_bytes", "Total Length of Fwd Packets"], 0)),
            "duration": float(_get_val(row, ["Flow Duration", "bidirectional_duration_ms", "duration"], 0)),
            "prediction": pred_view["prediction"],
            "attack_type": pred_view.get("attack_type"),
            "confidence": pred_view["confidence"],
            "severity": pred_view["severity"],
            "family": pred_view.get("family"),
            "subtype": pred_view.get("subtype") or pred_view.get("attack_type"),
            "stage1_p": pred.get("stage1_p", 0.0),
            "stage2_p": pred.get("stage2_p"),
            "stage2_probs": pred.get("stage2_probs"),
            "stage3_p": pred.get("stage3_p"),
            "stage3_probs": pred.get("stage3_probs"),
            "source": source,
            "model_version": model_version,
            "ack_state": "new",
            "ack_at": None,
            "ack_note": None,
            "snort_msg": (snort_payload or {}).get("snort_msg", ""),
            "snort_sid": int((snort_payload or {}).get("snort_sid", 0) or 0),
            "snort_classtype": (snort_payload or {}).get("snort_classtype", ""),
            "snort_priority": int((snort_payload or {}).get("snort_priority", 0) or 0),
            "mlFeatures": {
                "sbytes": float(df.iloc[i].get("sbytes", 0) if i < len(df) and "sbytes" in df.columns else 0),
                "dbytes": float(df.iloc[i].get("dbytes", 0) if i < len(df) and "dbytes" in df.columns else 0),
                "dur": float(df.iloc[i].get("dur", 0) if i < len(df) and "dur" in df.columns else 0),
                "spkts": float(df.iloc[i].get("spkts", 0) if i < len(df) and "spkts" in df.columns else 0),
                "dpkts": float(df.iloc[i].get("dpkts", 0) if i < len(df) and "dpkts" in df.columns else 0),
                "sload": float(df.iloc[i].get("sload", 0) if i < len(df) and "sload" in df.columns else 0),
                "dload": float(df.iloc[i].get("dload", 0) if i < len(df) and "dload" in df.columns else 0),
                "ct_srv_dst": float(df.iloc[i].get("ct_srv_dst", 0) if i < len(df) and "ct_srv_dst" in df.columns else 0),
                "sttl": float(df.iloc[i].get("sttl", 0) if i < len(df) and "sttl" in df.columns else 0),
                "dttl": float(df.iloc[i].get("dttl", 0) if i < len(df) and "dttl" in df.columns else 0),
            },
        }
        if mitre_mapper:
            prediction_obj = mitre_mapper.enrich_prediction(prediction_obj)
        else:
            prediction_obj["mitre"] = None
        out.append(prediction_obj)
    return out


# ----------------------------------------------------------------------
# Read endpoints
# ----------------------------------------------------------------------

@router.get("/predictions")
async def get_predictions(
    response: Response,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
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
    dir: str = "desc",
    group: str | None = None,
):
    """Paginated, filterable, optionally-grouped predictions list.

    Query parameters and response shape are identical to the legacy
    in-memory implementation — the dashboard does not need to change.
    """
    _set_no_cache(response)
    try:
        return await predictions_repo.list_page(
            session,
            limit=limit, offset=offset,
            ack_state=ack_state, severity=severity, source=source,
            q=q, src_cidr=src_cidr, dst_cidr=dst_cidr,
            port_min=port_min, port_max=port_max,
            sort=sort, dir_=dir, group=group,
        )
    except ValueError as e:
        # CIDR validation failures land here.
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/predictions/counts")
async def get_predictions_counts(
    response: Response,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """Per-ack-state row counts. Cheap aggregate used for the
    AlertsPage tab badges."""
    _set_no_cache(response)
    counts = await predictions_repo.counts_by_ack_state(session)
    counts["pid"] = os.getpid()
    return counts


@router.post("/_debug/clear")
async def debug_clear(
    response: Response,
    session: AsyncSession = Depends(get_session),
    _admin: User = Depends(require_admin),
):
    """Wipe the predictions table on demand. The dashboard's analytics
    page "Reset data" button calls this. Cascades to ack_history via
    ``ON DELETE CASCADE``.
    """
    _set_no_cache(response)
    n = await predictions_repo.clear_all(session)
    log.info("predictions table cleared via /_debug/clear (was %d)", n)
    return {
        "cleared": n,
        "pid": os.getpid(),
        "server_time": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/_debug/store")
async def debug_store(
    response: Response,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """Read-only diagnostic dump. Confirms whether the analytics
    empty-state is a real DB-is-empty case or a stale-cache problem."""
    _set_no_cache(response)
    total = await predictions_repo.total_rows(session)
    oldest, newest = await predictions_repo.timestamp_range(session)
    return {
        "pid": os.getpid(),
        "server_time": datetime.now(timezone.utc).isoformat(),
        "store_size": total,
        "oldest_timestamp": oldest.isoformat() if oldest else None,
        "newest_timestamp": newest.isoformat() if newest else None,
    }


@router.get("/predictions/{prediction_id}")
async def get_prediction_detail(
    prediction_id: str,
    response: Response,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """Full prediction including heavy fields (stage*_probs, mlFeatures,
    full MITRE technique list). Drawer fetches this on open."""
    _set_no_cache(response)
    row = await predictions_repo.get(session, prediction_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Prediction {prediction_id} not found")
    return predictions_repo.to_full_dict(row)


# ----------------------------------------------------------------------
# Ack endpoints
# ----------------------------------------------------------------------

@router.post("/predictions/{prediction_id}/ack")
async def ack_prediction(
    prediction_id: str,
    body: AckRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    row = await predictions_repo.ack(
        session,
        prediction_id=prediction_id,
        state=body.state,
        note=body.note,
        user_id=user.id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail=f"Prediction {prediction_id} not found")
    return predictions_repo.to_full_dict(row)


@router.post("/predictions/ack/bulk")
async def ack_predictions_bulk(
    body: BulkAckRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    return await predictions_repo.bulk_ack(
        session,
        ids=body.ids,
        state=body.state,
        note=body.note,
        user_id=user.id,
    )


@router.post("/predictions/ack/by-match")
async def ack_predictions_by_match(
    body: dict,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    state = body.get("state")
    if state not in _ACK_STATES:
        raise HTTPException(status_code=400, detail=f"Invalid ack state: {state!r}")
    try:
        return await predictions_repo.ack_by_match(
            session,
            source_ip=body.get("sourceIp"),
            destination_ip=body.get("destinationIp"),
            family=body.get("family"),
            state=state,
            note=body.get("note"),
            user_id=user.id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ----------------------------------------------------------------------
# Suppressions
# ----------------------------------------------------------------------

@router.get("/suppressions")
async def list_suppressions(
    response: Response,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    _set_no_cache(response)
    rules = await suppressions_repo.list_active(session)
    return [suppressions_repo.to_dict(r) for r in rules]


@router.post("/suppressions")
async def create_suppression(
    body: SuppressionRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    expires = None
    if body.expires_at:
        try:
            expires = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid expires_at: {e}")
    try:
        rule = await suppressions_repo.add(
            session,
            kind=body.kind,
            value=body.value,
            expires_at=expires,
            note=body.note,
            created_by=user.id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return suppressions_repo.to_dict(rule)


@router.delete("/suppressions/{rule_id}")
async def delete_suppression(
    rule_id: str,
    session: AsyncSession = Depends(get_session),
    _admin: User = Depends(require_admin),
):
    return {"removed": await suppressions_repo.remove(session, rule_id)}


# ----------------------------------------------------------------------
# Analytics
# ----------------------------------------------------------------------

@router.get("/analytics")
async def get_analytics(
    response: Response,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    range: str = "all",
):
    """Aggregate the predictions table into the dashboard's analytics
    response shape. All counts/breakdowns are SQL aggregates; nothing is
    materialised in Python beyond the small result rows."""
    _set_no_cache(response)
    return await predictions_repo.analytics_aggregates(session, range_key=range)


# ----------------------------------------------------------------------
# Upload + manual ingest
# ----------------------------------------------------------------------

def _temp_upload_path(ext: str) -> str:
    """Allocate a unique upload path inside the OS temp dir.

    Old behaviour wrote to the API's CWD, which left stray files when a
    request died mid-upload. The shutdown hook in app/main.py sweeps any
    ``hids_upload_*`` files older than 1h.
    """
    return os.path.join(tempfile.gettempdir(), f"hids_upload_{uuid.uuid4()}.{ext}")


@router.post("/analyze/upload")
async def analyze_upload(
    request: Request,
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    if not hasattr(request.app.state, "model_manager") or not hasattr(request.app.state, "data_standardizer"):
        raise HTTPException(status_code=503, detail="Services not initialized")

    model_manager = request.app.state.model_manager
    data_standardizer = request.app.state.data_standardizer
    mitre_mapper = getattr(request.app.state, "mitre_mapper", None)

    filename = file.filename or "unknown"
    ext = filename.split(".")[-1].lower()
    temp_filename = _temp_upload_path(ext)

    try:
        with open(temp_filename, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        file_size_mb = os.path.getsize(temp_filename) / (1024 * 1024)
        log.info("Upload: %s (%.1f MB), starting feature extraction...", filename, file_size_mb)

        loop = asyncio.get_event_loop()

        def _extract_and_predict():
            if ext == "csv":
                df = data_standardizer.from_csv(temp_filename)
            elif ext in ["xlsx", "xls"]:
                df = data_standardizer.from_excel(temp_filename)
            elif ext in ["pcap", "pcapng"]:
                df = data_standardizer.from_pcap(temp_filename)
            else:
                raise ValueError(f"Unsupported file format: {ext}")
            log.info("Feature extraction done: %d flows. Running prediction...", len(df))
            preds = model_manager.predict(df)
            log.info("Prediction done: %d results.", len(preds))
            return df, preds

        df, predictions = await loop.run_in_executor(_upload_executor, _extract_and_predict)

        snort_alerts: dict[str, dict] = {}
        if ext in ("pcap", "pcapng") and snort_offline.is_available():
            log.info("Replaying %s through Snort offline ...", filename)
            try:
                snort_alerts = await loop.run_in_executor(
                    _upload_executor, snort_offline.run, temp_filename
                )
                log.info("Snort offline returned %d alert flows", len(snort_alerts))
            except Exception:
                log.exception("Snort offline replay failed; continuing ML-only")
                snort_alerts = {}

        model_version = getattr(request.app.state, "model_version", "unknown")
        formatted_predictions = _format_predictions(
            df, predictions, snort_alerts, mitre_mapper, model_version,
        )

        kept, dropped = await suppressions_repo.filter_predictions(session, formatted_predictions)
        if dropped:
            log.info("suppression: dropped %d flows from upload (%d kept)", dropped, len(kept))
        await predictions_repo.insert_many(session, kept)

        return {
            "success": True,
            "total": len(formatted_predictions),
            "predictions": formatted_predictions,
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except OSError:
                pass


@router.post("/analyze/upload/stream")
async def analyze_upload_stream(
    request: Request,
    file: UploadFile = File(...),
    _user: User = Depends(get_current_user),
):
    """Streaming variant of `/analyze/upload`. Returns NDJSON progress
    events ending in result_begin/result_batch/result_end chunks so the
    dashboard can render a real progress bar.

    Manages its own DB session (rather than using `Depends(get_session)`)
    because the request lifetime is long-running and we want the
    session/transaction to be tightly scoped around the insert step.
    """
    from app.db import SessionLocal

    if not hasattr(request.app.state, "model_manager") or not hasattr(request.app.state, "data_standardizer"):
        raise HTTPException(status_code=503, detail="Services not initialized")

    model_manager = request.app.state.model_manager
    data_standardizer = request.app.state.data_standardizer
    mitre_mapper = getattr(request.app.state, "mitre_mapper", None)
    model_version = getattr(request.app.state, "model_version", "unknown")

    filename = file.filename or "unknown"
    ext = filename.split(".")[-1].lower()
    temp_filename = _temp_upload_path(ext)

    with open(temp_filename, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    file_size_mb = os.path.getsize(temp_filename) / (1024 * 1024)
    log.info("Upload (stream): %s (%.1f MB)", filename, file_size_mb)

    async def event_stream():
        def emit(event: dict) -> str:
            return json.dumps(event, default=str) + "\n"

        loop = asyncio.get_event_loop()
        progress_queue: asyncio.Queue = asyncio.Queue()

        def progress_cb(stage: str, info: dict | None = None):
            payload = {"event": "stage", "stage": stage}
            if info:
                payload.update(info)
            loop.call_soon_threadsafe(progress_queue.put_nowait, payload)

        try:
            yield emit({"event": "stage", "stage": "received",
                       "filename": filename, "sizeMB": round(file_size_mb, 2)})

            def _extract_and_predict():
                progress_cb("extract_start")
                t0 = time.perf_counter()
                if ext == "csv":
                    df = data_standardizer.from_csv(temp_filename)
                elif ext in ("xlsx", "xls"):
                    df = data_standardizer.from_excel(temp_filename)
                elif ext in ("pcap", "pcapng"):
                    df = data_standardizer.from_pcap(temp_filename, progress_cb=progress_cb)
                else:
                    raise ValueError(f"Unsupported file format: {ext}")
                progress_cb("extract_done", {
                    "flows": int(len(df)),
                    "elapsedMs": int((time.perf_counter() - t0) * 1000),
                })
                progress_cb("predict_start", {"total": int(len(df))})
                preds = model_manager.predict(df)
                progress_cb("predict_done")
                return df, preds

            extract_task = loop.run_in_executor(_upload_executor, _extract_and_predict)

            snort_task = None
            if ext in ("pcap", "pcapng") and snort_offline.is_available():
                progress_cb("snort_start")
                def _snort_run():
                    t0 = time.perf_counter()
                    alerts = snort_offline.run(temp_filename)
                    progress_cb("snort_done", {
                        "alerts": int(len(alerts) if alerts else 0),
                        "elapsedMs": int((time.perf_counter() - t0) * 1000),
                    })
                    return alerts
                snort_task = loop.run_in_executor(_upload_executor, _snort_run)

            pending_done = lambda: extract_task.done() and (snort_task is None or snort_task.done())
            while not pending_done():
                try:
                    evt = await asyncio.wait_for(progress_queue.get(), timeout=1.0)
                    yield emit(evt)
                except asyncio.TimeoutError:
                    yield emit({"event": "heartbeat"})

            while not progress_queue.empty():
                yield emit(progress_queue.get_nowait())

            df, predictions = await extract_task
            snort_alerts: dict[str, dict] = {}
            if snort_task is not None:
                try:
                    snort_alerts = await snort_task or {}
                except Exception:
                    log.exception("Snort offline replay failed; continuing ML-only")
                    snort_alerts = {}

            yield emit({"event": "stage", "stage": "format_start"})

            formatted = _format_predictions(
                df, predictions, snort_alerts, mitre_mapper, model_version,
            )

            # Open a fresh session for the write step. Keeps the
            # transaction tightly scoped — we don't hold a connection
            # for the duration of the stream.
            async with SessionLocal() as session:
                try:
                    kept, dropped = await suppressions_repo.filter_predictions(session, formatted)
                    if dropped:
                        log.info("suppression: dropped %d flows from streaming upload (%d kept)",
                                 dropped, len(kept))
                    await predictions_repo.insert_many(session, kept)
                    await session.commit()
                except Exception:
                    await session.rollback()
                    raise

            BATCH_SIZE = 1000
            total = len(formatted)
            yield emit({"event": "result_begin", "total": total})
            # Use the repo's summary helper but adapt — we have dicts,
            # not rows. Build summaries directly from the dict shape.
            for offset in range(0, total, BATCH_SIZE):
                batch = formatted[offset:offset + BATCH_SIZE]
                yield emit({
                    "event": "result_batch",
                    "offset": offset,
                    "predictions": [_dict_to_summary(p) for p in batch],
                })
            yield emit({"event": "result_end", "success": True, "total": total})

        except Exception as exc:
            log.exception("Streaming upload failed")
            yield emit({"event": "error", "detail": str(exc)})

        finally:
            if os.path.exists(temp_filename):
                try:
                    os.remove(temp_filename)
                except OSError:
                    pass

    return StreamingResponse(
        event_stream(),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


def _dict_to_summary(p: dict) -> dict:
    """Summary view built from a freshly-formatted prediction dict.

    The streaming upload yields summaries before the rows have been
    refetched from the DB; mirrors the shape returned by
    `predictions_repo.to_summary_dict()`.
    """
    mitre = p.get("mitre")
    mitre_summary: dict | None = None
    if isinstance(mitre, dict):
        mitre_summary = {
            "confidence_band": mitre.get("confidence_band"),
            "tactics": mitre.get("tactics", []),
        }
        if mitre.get("unmapped"):
            mitre_summary["unmapped"] = True
            mitre_summary["attack_type"] = mitre.get("attack_type")
            mitre_summary["description"] = mitre.get("description")
    return {
        "id": p["id"],
        "timestamp": p.get("timestamp"),
        "sourceIp": p.get("sourceIp"),
        "destinationIp": p.get("destinationIp"),
        "sourcePort": p.get("sourcePort"),
        "destinationPort": p.get("destinationPort"),
        "protocol": p.get("protocol"),
        "packetSize": p.get("packetSize"),
        "duration": p.get("duration"),
        "prediction": p.get("prediction"),
        "attack_type": p.get("attack_type"),
        "confidence": p.get("confidence"),
        "severity": p.get("severity"),
        "family": p.get("family"),
        "subtype": p.get("subtype"),
        "stage1_p": p.get("stage1_p"),
        "stage2_p": p.get("stage2_p"),
        "stage3_p": p.get("stage3_p"),
        "source": p.get("source"),
        "model_version": p.get("model_version"),
        "ack_state": p.get("ack_state", "new"),
        "ack_at": p.get("ack_at"),
        "ack_note": p.get("ack_note"),
        "snort_msg": p.get("snort_msg", ""),
        "snort_sid": p.get("snort_sid", 0),
        "snort_classtype": p.get("snort_classtype", ""),
        "snort_priority": p.get("snort_priority", 0),
        "mitre": mitre_summary,
    }


@router.post("/analyze/manual")
async def analyze_manual(
    request: Request,
    flow: ManualFlowInput,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """Manual flow input. Persisted like batch/streaming uploads so the
    analyst's record of "what they tested" survives restarts."""
    if not hasattr(request.app.state, "model_manager") or not hasattr(request.app.state, "data_standardizer"):
        raise HTTPException(status_code=503, detail="Services not initialized")

    model_manager = request.app.state.model_manager
    data_standardizer = request.app.state.data_standardizer
    mitre_mapper = getattr(request.app.state, "mitre_mapper", None)

    try:
        flow_dict = flow.model_dump() if hasattr(flow, "model_dump") else flow.dict()
        try:
            validate_flow_input(flow_dict)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))

        df = data_standardizer.from_records([flow_dict])
        predictions = model_manager.predict(df)
        if not predictions:
            raise HTTPException(status_code=500, detail="No prediction returned")

        result = predictions[0]
        source = "ml_only" if result.get("prediction") == "Malicious" else "benign"
        result_view = dict(result)
        _apply_hybrid_overrides(result_view, None, source)

        response = {
            "id": f"manual_{uuid.uuid4()}",
            "timestamp": datetime.now().isoformat(),
            "sourceIp": flow_dict.get("srcip") or "N/A",
            "destinationIp": flow_dict.get("dstip") or "N/A",
            "sourcePort": flow_dict.get("sport", 0),
            "destinationPort": flow_dict.get("dsport", 0),
            "protocol": flow_dict.get("proto", "N/A"),
            "packetSize": flow_dict.get("sbytes", 0),
            "duration": flow_dict.get("dur", 0),

            "prediction": result_view["prediction"],
            "attack_type": result_view.get("attack_type"),
            "confidence": result_view["confidence"],
            "severity": result_view["severity"],
            "family": result_view.get("family"),
            "subtype": result_view.get("subtype") or result_view.get("attack_type"),
            "stage1_p": result.get("stage1_p", 0.0),
            "stage2_p": result.get("stage2_p"),
            "stage2_probs": result.get("stage2_probs"),
            "stage3_p": result.get("stage3_p"),
            "stage3_probs": result.get("stage3_probs"),
            "source": source,
            "model_version": getattr(request.app.state, "model_version", "unknown"),
            "ack_state": "new",
            "ack_at": None,
            "ack_note": None,
            "mlFeatures": {
                "sbytes": float(df.iloc[0].get("sbytes", 0) if "sbytes" in df.columns else 0),
                "dbytes": float(df.iloc[0].get("dbytes", 0) if "dbytes" in df.columns else 0),
                "dur": float(df.iloc[0].get("dur", 0) if "dur" in df.columns else 0),
                "spkts": float(df.iloc[0].get("spkts", 0) if "spkts" in df.columns else 0),
                "dpkts": float(df.iloc[0].get("dpkts", 0) if "dpkts" in df.columns else 0),
                "sload": float(df.iloc[0].get("sload", 0) if "sload" in df.columns else 0),
                "dload": float(df.iloc[0].get("dload", 0) if "dload" in df.columns else 0),
                "ct_srv_dst": float(df.iloc[0].get("ct_srv_dst", 0) if "ct_srv_dst" in df.columns else 0),
                "sttl": float(df.iloc[0].get("sttl", 0) if "sttl" in df.columns else 0),
                "dttl": float(df.iloc[0].get("dttl", 0) if "dttl" in df.columns else 0),
            },
        }

        if mitre_mapper:
            response = mitre_mapper.enrich_prediction(response)
        else:
            response["mitre"] = None

        kept, _dropped = await suppressions_repo.filter_predictions(session, [response])
        await predictions_repo.insert_many(session, kept)

        return response

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
