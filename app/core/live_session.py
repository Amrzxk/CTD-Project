"""
Live-session registry — owns the single global live-stream session.

The H-IDS dashboard runs at most one live session at a time. Starting a new
session auto-stops any existing one. State lives in two places:

1.  An in-process ``LiveSessionRegistry`` (this module). Holds the
    ``asyncio.Task`` running the PCAP replay (if any), the open
    ``SessionLogger``, the ``stop_event`` used for cooperative cancellation,
    and the canonical ``LiveSession`` dataclass.

2.  A Redis key ``live:active_session`` carrying the session metadata as JSON.
    With ``gunicorn -w 4`` only one worker actually holds the live Task, but
    every worker's SSE generator reads from this key to learn the detection
    mode for the active session. A worker that takes over a stream (e.g. on
    reconnect to a different worker) sees the same ``session_id`` and
    ``detection_mode`` as the originating worker.

3.  A Redis Pub/Sub channel ``live_session_events`` carries lifecycle pings
    (``started`` / ``stopped``). The SSE generator subscribes to this so a
    stop issued in worker A cleanly cancels a stream connected to worker B.

This module is *not* responsible for ML inference or for the SSE feed itself
— it only manages session lifecycle.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

import redis.asyncio as aioredis

from .session_logger import SessionLogger


log = logging.getLogger(__name__)


# Channel for {started, stopped} lifecycle events.
LIVE_SESSION_EVENTS_CHANNEL = "live_session_events"
# Mirror of the in-memory session for cross-worker visibility.
ACTIVE_SESSION_KEY = "live:active_session"


Source = Literal["interface", "pcap"]
DetectionMode = Literal["ml", "snort", "hybrid"]


@dataclass
class LiveSession:
    """Public, JSON-serializable description of an active live session."""

    id: str
    source: Source
    detection_mode: DetectionMode
    started_at: datetime
    owner_user_id: int
    pcap_path: Optional[str] = None
    pcap_speed: Optional[float] = None  # 0 == max
    pcap_attached: bool = False
    # When True the SSE generator persists non-benign events to the
    # predictions table so they show up in /alerts. Default is set per
    # source in registry.start() — pcap=True, interface=False.
    persist_to_alerts: bool = False

    # Runtime-only fields (not serialized to Redis):
    logger: Optional[SessionLogger] = field(default=None, repr=False)
    replay_task: Optional[asyncio.Task] = field(default=None, repr=False)
    persister_task: Optional[asyncio.Task] = field(default=None, repr=False)
    stop_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def to_public_dict(self) -> dict[str, Any]:
        """Shape returned by the API (omits runtime handles)."""
        return {
            "session_id": self.id,
            "source": self.source,
            "detection_mode": self.detection_mode,
            "speed": self.pcap_speed,
            "started_at": self.started_at.isoformat(),
            "pcap_attached": self.pcap_attached,
            "persist_to_alerts": self.persist_to_alerts,
            "log_csv_url": f"/live/session/{self.id}/log?format=csv",
            "log_ndjson_url": f"/live/session/{self.id}/log?format=ndjson",
            "row_count": self.logger.row_count if self.logger is not None else 0,
        }

    def to_redis_dict(self) -> dict[str, Any]:
        """Shape stored in the cross-worker Redis registry."""
        return {
            "id": self.id,
            "source": self.source,
            "detection_mode": self.detection_mode,
            "started_at": self.started_at.isoformat(),
            "owner_user_id": self.owner_user_id,
            "pcap_attached": self.pcap_attached,
            "pcap_speed": self.pcap_speed,
            "persist_to_alerts": self.persist_to_alerts,
        }


class LiveSessionRegistry:
    """Single-slot registry for the active live session.

    Held on ``app.state.live_sessions``. Methods are async because they may
    publish lifecycle events to Redis; the in-process state itself is
    guarded by a lock so concurrent ``start()`` calls from multiple workers
    are serialized within one worker process.
    """

    def __init__(self, redis_pool: aioredis.Redis | None, log_dir: Path) -> None:
        self._redis: aioredis.Redis | None = redis_pool
        self._log_dir = log_dir
        self._current: LiveSession | None = None
        self._lock = asyncio.Lock()
        # Late-bound after lifespan finishes wiring app.state. The persister
        # needs these to run ML inference + MITRE enrichment exactly the
        # same way the SSE generator does.
        self.model_manager: Any = None
        self.data_standardizer: Any = None
        self.mitre_mapper: Any = None
        self.model_version: str = "unknown"

    # ------------------------------------------------------------------
    # Read accessors
    # ------------------------------------------------------------------
    def current(self) -> LiveSession | None:
        """Return the in-process active session, or None."""
        return self._current

    async def current_from_redis(self) -> dict[str, Any] | None:
        """Read the cross-worker session record. Returns None if absent."""
        if self._redis is None:
            return None
        try:
            raw = await self._redis.get(ACTIVE_SESSION_KEY)
        except Exception:
            log.debug("registry: get active_session failed", exc_info=True)
            return None
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------
    async def start(
        self,
        source: Source,
        detection_mode: DetectionMode,
        owner_user_id: int,
        speed: float | None = None,
        persist_to_alerts: bool | None = None,
    ) -> LiveSession:
        """Allocate a new session, stopping any existing one first."""
        async with self._lock:
            if self._current is not None:
                await self._stop_locked("superseded")

            # Per-source default — pcap replays expect their findings to
            # land in /alerts for triage; interface mode does not, because
            # a busy NIC would generate orders of magnitude more rows than
            # an analyst can reasonably review (and would flood Postgres).
            if persist_to_alerts is None:
                persist_to_alerts = source == "pcap"

            session_id = uuid.uuid4().hex[:16]
            session = LiveSession(
                id=session_id,
                source=source,
                detection_mode=detection_mode,
                started_at=datetime.now(timezone.utc),
                owner_user_id=owner_user_id,
                pcap_speed=speed if source == "pcap" else None,
                persist_to_alerts=persist_to_alerts,
            )
            # Open per-session log files now so a few events arriving before
            # PCAP attach (interface mode) are still captured.
            logger = SessionLogger(self._log_dir, session_id)
            logger.start()
            session.logger = logger

            self._current = session

            await self._publish_redis_state(session)
            await self._publish_event("started", session_id)

            # Spawn the per-session DB writer. Independent of any SSE
            # subscriber — the analyst doesn't have to keep /live open
            # for findings to land in /alerts.
            if persist_to_alerts and self._redis is not None:
                from .live_persister import run_persister

                session.persister_task = asyncio.create_task(
                    run_persister(
                        session=session,
                        redis_pool=self._redis,
                        model_manager=self.model_manager,
                        data_standardizer=self.data_standardizer,
                        mitre_mapper=self.mitre_mapper,
                        model_version=self.model_version,
                    )
                )

            log.info(
                "live session started id=%s source=%s mode=%s persist=%s",
                session_id, source, detection_mode, persist_to_alerts,
            )
            return session

    async def attach_pcap(
        self,
        session_id: str,
        pcap_path: str,
        replay_task: asyncio.Task,
    ) -> None:
        """Wire the PCAP-replay background task into the active session."""
        async with self._lock:
            current = self._current
            if current is None or current.id != session_id:
                raise ValueError("session_id does not match the active session")
            if current.source != "pcap":
                raise ValueError("session is not a pcap session")
            current.pcap_path = pcap_path
            current.pcap_attached = True
            current.replay_task = replay_task
            await self._publish_redis_state(current)
            # Cross-worker pcap-attach signal — the SSE generator's
            # warm-up gate listens for this to start emitting events.
            await self._publish_event("pcap_attached", current.id)

    async def stop(self, session_id: str | None = None) -> bool:
        """Stop the active session. Returns True if a session was running.

        If ``session_id`` is given, only stops when it matches; this prevents
        a stale 'stop' from killing a freshly-started session.
        """
        async with self._lock:
            current = self._current
            if current is None:
                return False
            if session_id is not None and current.id != session_id:
                return False
            await self._stop_locked("stopped")
            return True

    async def clear_stale_redis_state(self) -> bool:
        """Drop a leftover ``live:active_session`` Redis key on startup.

        If the API crashed (or was forcibly killed) mid-session, the
        in-process registry vanishes but the Redis mirror sticks around
        because ``_stop_locked`` never ran. The SSE generator's shadow
        resolver would then think a session is active when nothing is.

        This is safe to call unconditionally at lifespan startup: the
        in-process registry is always empty at that point (we haven't
        served any requests yet), so any stale Redis state is by
        definition orphaned. Returns True if a key was removed.
        """
        if self._redis is None:
            return False
        try:
            existing = await self._redis.get(ACTIVE_SESSION_KEY)
        except Exception:
            log.debug("registry: stale-state probe failed", exc_info=True)
            return False
        if not existing:
            return False
        try:
            await self._redis.delete(ACTIVE_SESSION_KEY)
            log.info(
                "registry: cleared stale Redis active_session key on startup "
                "(left over from a previous crash)"
            )
            return True
        except Exception:
            log.debug("registry: stale-state delete failed", exc_info=True)
            return False

    async def shutdown(self) -> None:
        """Lifespan-shutdown hook — best-effort drop of the active session."""
        try:
            async with self._lock:
                if self._current is not None:
                    await self._stop_locked("shutdown")
        except Exception:
            log.exception("registry shutdown failed")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _stop_locked(self, reason: str) -> None:
        """Caller must hold ``self._lock``."""
        current = self._current
        if current is None:
            return
        current.stop_event.set()

        task = current.replay_task
        if task is not None and not task.done():
            task.cancel()
            try:
                # Give the task a brief moment to wind down cooperatively.
                await asyncio.wait_for(asyncio.shield(task), timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            except Exception:
                log.debug("registry: replay task ended with exception", exc_info=True)

        # The persister listens to LIVE_SESSION_EVENTS_CHANNEL for "stopped"
        # and exits on its own (with a final flush). But cancel as a backstop
        # in case it's wedged in get_message — we don't want to leak the
        # task. The persister handles CancelledError in `finally`.
        persister = current.persister_task
        if persister is not None and not persister.done():
            try:
                await asyncio.wait_for(asyncio.shield(persister), timeout=2.0)
            except asyncio.TimeoutError:
                persister.cancel()
                try:
                    await asyncio.wait_for(asyncio.shield(persister), timeout=1.0)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass
            except Exception:
                log.debug("registry: persister ended with exception", exc_info=True)

        if current.logger is not None:
            try:
                current.logger.close()
            except Exception:
                log.debug("registry: logger close failed", exc_info=True)

        # Best-effort clean-up of the uploaded PCAP. The cross-worker /tmp
        # sweep in main.py is the backstop.
        if current.pcap_path:
            try:
                Path(current.pcap_path).unlink(missing_ok=True)
            except OSError:
                log.debug("registry: pcap unlink failed", exc_info=True)

        ended_id = current.id
        self._current = None

        if self._redis is not None:
            try:
                await self._redis.delete(ACTIVE_SESSION_KEY)
            except Exception:
                log.debug("registry: delete active_session failed", exc_info=True)
        await self._publish_event("stopped", ended_id, reason=reason)
        log.info("live session stopped id=%s reason=%s", ended_id, reason)

    async def _publish_redis_state(self, session: LiveSession) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.set(
                ACTIVE_SESSION_KEY,
                json.dumps(session.to_redis_dict()),
            )
        except Exception:
            log.debug("registry: set active_session failed", exc_info=True)

    async def _publish_event(self, event: str, session_id: str, **extra: Any) -> None:
        if self._redis is None:
            return
        try:
            payload = {"event": event, "session_id": session_id, **extra}
            await self._redis.publish(
                LIVE_SESSION_EVENTS_CHANNEL,
                json.dumps(payload),
            )
        except Exception:
            log.debug("registry: publish lifecycle failed", exc_info=True)
