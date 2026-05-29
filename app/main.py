"""
FastAPI application — Hybrid IDS entry-point.

Lifespan initializes:
  - ML model manager — single legacy LightGBM or 3-tier hierarchical,
    selected via ``MODEL_MODE`` (``legacy`` or ``hierarchical``).
  - CIC-IDS data standardizer.
  - Async Redis connection pool (for the SSE endpoint).
  - Traffic logger.
  - MITRE ATT&CK mapper.

Background workers (flow_meter_worker, snort_tailer_worker) run as
separate processes and are **not** started here.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import redis.asyncio as aioredis
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

load_dotenv(Path(__file__).resolve().parent / ".env")

from sqlalchemy import text as sa_text

from .core.model_manager import ModelManager, HierarchicalModelManager
from .core.data_standardizer import DataStandardizer
from .core.traffic_logger import TrafficLogger
from .core.mitre_mapper import MitreMapper
from .core.live_session import LiveSessionRegistry
from .api.routes import router
from .api.live import router as live_router
from .api.mitre import router as mitre_router
from .api.auth import router as auth_router
from .db import SessionLocal, engine as db_engine
from .db import retention as db_retention
from .db.seed import seed_initial_admin

log = logging.getLogger(__name__)


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


_HIERARCHICAL_REQUIRED = (
    "stage1_binary.lgb",
    "stage2_family.cbm",
    "scaler_S1.joblib",
    "manifest.json",
)


def _hierarchical_artifacts_present(models_dir: Path) -> bool:
    return all((models_dir / f).exists() for f in _HIERARCHICAL_REQUIRED)


def _sweep_stale_uploads(max_age_seconds: int = 3600) -> int:
    """Delete ``hids_upload_*`` files in the OS temp dir older than the
    given age. Cleans up files orphaned by requests that died before
    their `try/finally` ran (kill -9, SIGTERM during long IO, etc.).

    Called once on startup. Returns the count of files removed.
    """
    removed = 0
    tmp = Path(tempfile.gettempdir())
    now = time.time()
    try:
        for pattern in ("hids_upload_*", "live_pcap_*"):
            for entry in tmp.glob(pattern):
                try:
                    if now - entry.stat().st_mtime > max_age_seconds:
                        entry.unlink()
                        removed += 1
                except OSError:
                    continue
    except OSError:
        pass
    return removed


@asynccontextmanager
async def lifespan(app: FastAPI):
    base_dir = Path(__file__).resolve().parent
    models_dir = base_dir / "models"
    logs_dir = base_dir / "logs"

    # --- ML model selection ---
    requested_mode = _env("MODEL_MODE", "auto").lower()  # auto | legacy | hierarchical
    selected_mode = "legacy"

    app.state.model_manager = None
    app.state.data_standardizer = None
    app.state.model_version = "unknown"

    if requested_mode in ("auto", "hierarchical") and _hierarchical_artifacts_present(models_dir):
        try:
            mm = HierarchicalModelManager(models_dir=models_dir)
            ds = DataStandardizer(mm.selected_features)
            app.state.model_manager = mm
            app.state.data_standardizer = ds
            app.state.model_version = mm.model_version
            selected_mode = "hierarchical"
            print(f"Hierarchical model loaded ({mm.model_version}).")
        except Exception as exc:
            log.exception("Failed to load hierarchical model: %s", exc)
            if requested_mode == "hierarchical":
                # User asked for hierarchical explicitly — surface the failure
                raise
            print("Falling back to legacy model.")

    if app.state.model_manager is None:
        model_path = models_dir / "final_model.pkl"
        features_path = models_dir / "selected_features.json"
        labels_path = models_dir / "class_labels.json"
        scaler_candidates = [models_dir / "scaler.joblib", models_dir / "scaler.pkl"]
        scaler_path = next((p for p in scaler_candidates if p.exists()), None)

        print(f"Loading legacy model from: {models_dir}")
        if not model_path.exists():
            print("WARNING: Legacy model file not found — /live/stream ML inference disabled.")
        else:
            mm = ModelManager(
                model_path=str(model_path),
                features_path=str(features_path),
                labels_path=str(labels_path),
                scaler_path=str(scaler_path) if scaler_path else None,
            )
            ds = DataStandardizer(mm.selected_features)
            app.state.model_manager = mm
            app.state.data_standardizer = ds
            app.state.model_version = mm.model_version
            print("Legacy model loaded successfully.")

    app.state.model_mode = selected_mode

    # --- MITRE ATT&CK mapper ---
    mitre_path = base_dir / "data" / "mitre_mapping.json"
    if mitre_path.exists():
        app.state.mitre_mapper = MitreMapper(mitre_path)
        print(f"MITRE mapper loaded — {len(app.state.mitre_mapper.categories)} categories mapped.")
    else:
        app.state.mitre_mapper = None
        print("WARNING: mitre_mapping.json not found — MITRE enrichment disabled.")

    # --- Traffic logger ---
    app.state.traffic_logger = TrafficLogger(logs_dir)

    # --- Live session registry ---
    # Holds the single global active live session. The redis pool is set
    # below; we instantiate now and inject the pool once it's ready.
    app.state.live_sessions = LiveSessionRegistry(redis_pool=None, log_dir=logs_dir)

    # --- Async Redis pool ---
    redis_host = _env("REDIS_HOST", "127.0.0.1")
    redis_port = int(_env("REDIS_PORT", "6379"))
    redis_password = _env("REDIS_PASSWORD") or None

    app.state.redis_pool = aioredis.Redis(
        host=redis_host,
        port=redis_port,
        password=redis_password,
        decode_responses=True,
        socket_connect_timeout=10,
    )
    try:
        await app.state.redis_pool.ping()
        print(f"Async Redis connection OK ({redis_host}:{redis_port}).")
    except Exception as exc:
        print(f"WARNING: Could not connect to Redis — {exc}")
        app.state.redis_pool = None

    # Inject the (possibly None) redis pool into the live-session registry
    # so it can broadcast lifecycle events and maintain cross-worker state.
    app.state.live_sessions._redis = app.state.redis_pool  # type: ignore[attr-defined]
    # Late-bind the ML + MITRE handles so the per-session persister task
    # (spawned in registry.start when persist_to_alerts=True) can build the
    # same event payload the SSE generator does.
    app.state.live_sessions.model_manager = app.state.model_manager
    app.state.live_sessions.data_standardizer = app.state.data_standardizer
    app.state.live_sessions.mitre_mapper = app.state.mitre_mapper
    app.state.live_sessions.model_version = app.state.model_version

    # Sweep any stale Redis session record from a previous crash. With
    # API_WORKERS=1 this is unambiguous; with multi-worker we'd have to
    # tolerate other workers' live state and skip this.
    try:
        await app.state.live_sessions.clear_stale_redis_state()
    except Exception:
        log.exception("Failed to clear stale live-session state")

    # --- Database probe ---
    # The schema has already been applied by `alembic upgrade head` (run
    # from the container entrypoint or from the dev `start_workers.ps1`
    # script). Here we just probe the connection so a misconfigured
    # DATABASE_URL surfaces at startup rather than on the first request.
    app.state.db_ok = False
    try:
        async with db_engine.connect() as conn:
            await conn.execute(sa_text("SELECT 1"))
        app.state.db_ok = True
        print("Postgres connection OK.")
    except Exception as exc:
        print(f"WARNING: Could not connect to Postgres — {exc}")

    # --- Admin seed ---
    # Idempotent: if the users table is empty and ADMIN_USERNAME /
    # ADMIN_PASSWORD are both set, create the bootstrap admin. Logs a
    # warning when the table is empty but env vars are missing.
    if app.state.db_ok:
        try:
            await seed_initial_admin()
        except Exception:
            log.exception("admin seed failed (continuing)")

    # --- Retention worker ---
    # Spawn even when the DB probe failed: the worker has its own retry
    # via the next interval and will start trimming once the DB comes
    # back. Held on app.state so shutdown can cancel it cleanly.
    app.state.retention_task = db_retention.start()

    # --- Stale upload sweep ---
    # Files orphaned by aborted requests don't accumulate. Cheap one-off
    # scan; nothing in the hot path here.
    swept = _sweep_stale_uploads()
    if swept:
        log.info("startup: removed %d stale upload temp file(s)", swept)

    # --- Optional Snort tailer subprocess ---
    # Off by default so the `start_all.ps1` workflow (which launches the
    # tailer separately) doesn't end up with two tailers fighting over
    # alert_json.txt. Flip SNORT_TAILER_AUTOSTART=1 in single-container
    # deployments where the API process should own the tailer.
    app.state.snort_tailer_proc = None
    if os.getenv("SNORT_TAILER_AUTOSTART") == "1":
        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", "app.core.snort_tailer_worker"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            app.state.snort_tailer_proc = proc
            print(f"Snort tailer started as subprocess pid={proc.pid}")
        except Exception:
            log.exception("failed to autostart Snort tailer")

    yield

    # --- Shutdown ---
    task = getattr(app.state, "retention_task", None)
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    # Stop the Snort tailer subprocess if we own it. 5s grace then kill —
    # the tailer's own signal handler does the heavy lifting.
    proc = getattr(app.state, "snort_tailer_proc", None)
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception:
            log.exception("snort tailer shutdown failed")

    # Drop the active live session before tearing down Redis so any final
    # lifecycle event still has a transport.
    live_registry = getattr(app.state, "live_sessions", None)
    if live_registry is not None:
        await live_registry.shutdown()

    if app.state.redis_pool is not None:
        await app.state.redis_pool.close()
    app.state.traffic_logger.close()


app = FastAPI(lifespan=lifespan)

# CORS allow-list comes from env so docker-compose / AWS deployments can
# override without code changes. With credentialed CORS, wildcard origins
# are rejected by the browser — an explicit list is required.
_cors_origins = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """Readiness probe — pings the database with a cheap `SELECT 1` so an
    ALB / Compose healthcheck reflects real reachability instead of just
    "uvicorn is alive". Surfaces model + redis state alongside.
    """
    state = app.state
    db_ok = False
    try:
        async with db_engine.connect() as conn:
            await conn.execute(sa_text("SELECT 1"))
        db_ok = True
    except Exception:
        # Don't 500 the probe — return the diagnostic shape and let the
        # caller decide. ALB target-group health checks should treat
        # `status != "healthy"` as unhealthy.
        pass
    return {
        "status": "healthy" if db_ok else "degraded",
        "model_mode": getattr(state, "model_mode", "unknown"),
        "model_version": getattr(state, "model_version", "unknown"),
        "redis": state.redis_pool is not None,
        "database": db_ok,
    }


app.include_router(auth_router)
app.include_router(router)
app.include_router(live_router)
app.include_router(mitre_router)
