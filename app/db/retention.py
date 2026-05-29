"""Background retention worker.

Postgres can hold millions of prediction rows without sweating. The
right operational lever is age-based pruning + an optional hard row
cap, both governed by env vars:

* ``RETENTION_DAYS`` (default 90) — delete predictions whose
  ``flow_timestamp`` is older than this many days. Set to 0 to disable.
* ``MAX_PREDICTIONS_HARD_CAP`` (default unset) — if total row count
  exceeds this, delete the oldest rows over the limit. Belt-and-braces.
* ``SESSION_LOG_RETENTION_DAYS`` (default 30) — delete per-session
  ``session_*.csv`` / ``session_*.ndjson`` files older than this. Set
  to 0 to disable. The Alerts queue is the system-of-record once
  ``persist_to_alerts=True``; the log files are a forensic backup that
  doesn't need to outlive the analyst's review window.

Runs once at API startup (so a freshly-loaded service immediately
honours the policy) and then every 24h thereafter. Cleanly cancellable
on shutdown — the task is held on `app.state.retention_task`.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Optional

from app.db import SessionLocal
from app.db.repositories import predictions as predictions_repo

log = logging.getLogger(__name__)

_INTERVAL_SECONDS = 24 * 3600


def _read_int_env(name: str) -> int | None:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return None
    try:
        return int(value)
    except ValueError:
        log.warning("invalid %s value %r — ignoring", name, value)
        return None


def _purge_session_logs(log_dir: Path, retention_days: int) -> int:
    """Delete ``session_*.csv`` and ``session_*.ndjson`` older than
    ``retention_days``. Returns the count of removed files.

    Walks only files matching the session-logger naming convention so a
    misconfigured ``log_dir`` (e.g. accidentally pointed at /var/log)
    can't sweep unrelated content. mtime is used rather than parsing
    the timestamp out of the filename — robust to clock drift between
    workers, and matches what `find -mtime` would do.
    """
    if not log_dir.exists() or not log_dir.is_dir():
        return 0
    cutoff = time.time() - retention_days * 86400
    removed = 0
    for pattern in ("session_*.csv", "session_*.ndjson"):
        for path in log_dir.glob(pattern):
            try:
                if path.is_file() and path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            except OSError:
                log.debug("session-log purge: unlink failed for %s",
                          path, exc_info=True)
    return removed


async def _run_once() -> None:
    """One pass: predictions age-delete, predictions hard-cap, session-log purge."""
    retention_days = _read_int_env("RETENTION_DAYS")
    hard_cap = _read_int_env("MAX_PREDICTIONS_HARD_CAP")
    session_log_days = _read_int_env("SESSION_LOG_RETENTION_DAYS")
    if session_log_days is None:
        session_log_days = 30  # sensible default; explicit 0 disables

    if not retention_days and not hard_cap and not session_log_days:
        log.debug(
            "retention disabled (no RETENTION_DAYS, no MAX_PREDICTIONS_HARD_CAP, "
            "no SESSION_LOG_RETENTION_DAYS)"
        )
        return

    async with SessionLocal() as session:
        try:
            if retention_days and retention_days > 0:
                deleted = await predictions_repo.delete_older_than(session, retention_days)
                if deleted:
                    log.info("retention: deleted %d rows older than %dd", deleted, retention_days)
            if hard_cap and hard_cap > 0:
                trimmed = await predictions_repo.enforce_hard_cap(session, hard_cap)
                if trimmed:
                    log.info("retention: hard-cap evicted %d oldest rows (cap=%d)", trimmed, hard_cap)
            await session.commit()
        except Exception:
            await session.rollback()
            log.exception("retention pass failed")

    if session_log_days and session_log_days > 0:
        # `app/logs/` is the canonical dir — matches the lifespan handoff
        # in main.py and the SessionLogger default. Doing the lookup here
        # rather than reading from app.state keeps the worker stateless.
        log_dir = Path(__file__).resolve().parent.parent / "logs"
        try:
            removed = _purge_session_logs(log_dir, session_log_days)
            if removed:
                log.info(
                    "retention: removed %d session log files older than %dd",
                    removed, session_log_days,
                )
        except Exception:
            log.exception("session-log purge failed")


async def _loop() -> None:
    """Repeat ``_run_once`` every ``_INTERVAL_SECONDS``. Cancellation
    propagates out via the standard ``asyncio.CancelledError`` path."""
    # First pass runs immediately so a freshly-started service trims
    # stale data without waiting a day.
    await _run_once()
    while True:
        try:
            await asyncio.sleep(_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            log.info("retention loop cancelled")
            raise
        await _run_once()


def start() -> asyncio.Task:
    """Spawn the retention task. Caller should hold the returned task
    so it can be cancelled on shutdown."""
    return asyncio.create_task(_loop(), name="retention_worker")
