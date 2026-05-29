"""
In-API PCAP replay — feeds an uploaded PCAP into the live SSE pipeline.

Unlike ``/analyze/upload`` (which extracts + scores + persists in one shot),
this module *streams* flows out of NFStream's offline mode and publishes
them onto the same Redis Pub/Sub channels the global ``flow_meter_worker``
uses — so the existing SSE joiner in ``app/api/live.py`` consumes them
without modification.

Behaviour summary
-----------------
* For every flow emitted by NFStream:
    1.  Build CIC-IDS features via ``extract_cic_features`` (same function
        used by the live worker — guarantees feature parity).
    2.  ``HSET <flow_key>``, ``EXPIRE``, ``PUBLISH flow_completed <key>``.
* If ``detection_mode in {"snort", "hybrid"}`` and Snort is available,
  ``snort_offline.run()`` is invoked once at session start to produce a
  ``{flow_key -> alert}`` map. Each matching alert is published on
  ``snort_alerts`` immediately *before* its flow_completed event so the
  joiner correlates them naturally.
* Pacing:
    - ``speed > 0`` — wall-clock-respecting replay. Sleeps
      ``(now - last_seen_ms - prev) / (speed * 1000)`` between flows.
    - ``speed == 0`` — machine-speed replay ("Max"), capped at
      ``PCAP_REPLAY_MAX_EPS`` events/sec so it can't firehose the SSE
      client (set to 0 to disable the cap).
* The provided ``stop_event`` is polled on every flow; setting it causes
  the coroutine to exit within one flow.
* No new process. No subprocess. NFStream's iterator is wrapped in a
  thread executor because it is synchronous.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Literal

import redis.asyncio as aioredis

from .flow_meter_worker import extract_cic_features, FLOW_COMPLETED_CHANNEL
from .key_utils import flow_key as build_flow_key
from . import snort_offline


log = logging.getLogger(__name__)


SNORT_ALERTS_CHANNEL = "snort_alerts"
SNORT_HASH_PREFIX = "snort:"
DEFAULT_FLOW_TTL_SECONDS = 60
DEFAULT_SNORT_HASH_TTL_SECONDS = 60
# Max-speed (speed==0) emission ceiling, events/sec. Bounds the SSE rate so a
# large PCAP at "Max" can't overwhelm the browser / socket buffer. Overridable
# via the PCAP_REPLAY_MAX_EPS env var; 0 disables the cap (legacy behaviour).
DEFAULT_MAX_EPS = 1500
# Rate-limit window — we budget events per this slice and sleep the remainder,
# so we sleep occasionally instead of on every event.
_RATE_WINDOW_S = 0.1


def _strip_session_meta(features: dict[str, Any]) -> dict[str, str]:
    """Drop non-feature metadata fields and stringify the rest for Redis."""
    skip = {"src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "protocol_name", "application_name"}
    return {k: str(v) for k, v in features.items() if k not in skip}


def _flow_key_for(flow, features: dict[str, Any]) -> str:
    """Canonical flow key — prefers the live NFStream attrs, falls back to features."""
    try:
        return build_flow_key(
            src_ip=str(getattr(flow, "src_ip", features.get("src_ip", ""))),
            dst_ip=str(getattr(flow, "dst_ip", features.get("dst_ip", ""))),
            src_port=int(getattr(flow, "src_port", features.get("src_port", 0)) or 0),
            dst_port=int(getattr(flow, "dst_port", features.get("dst_port", 0)) or 0),
            protocol=int(getattr(flow, "protocol", features.get("protocol", 0)) or 0),
        )
    except (TypeError, ValueError):
        return build_flow_key(
            src_ip=str(features.get("src_ip", "")),
            dst_ip=str(features.get("dst_ip", "")),
            src_port=0,
            dst_port=0,
            protocol="TCP",
        )


def _safe_first_seen_ms(flow) -> float:
    """NFStream exposes ``bidirectional_first_seen_ms`` per flow."""
    val = getattr(flow, "bidirectional_first_seen_ms", None)
    try:
        return float(val) if val is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def _iter_flows_sync(pcap_path: str) -> list[Any]:
    """Drain NFStream into a list off the event loop.

    Why drain rather than yield-iterate: NFStream's iterator releases the
    GIL inside its C extension and does not play nicely with mixing
    sync-iteration into an asyncio loop. For our typical PCAPs (≤500 MB,
    ≤100 k flows) the memory cost of holding the list briefly is fine,
    and pacing is applied later when we publish.
    """
    from nfstream import NFStreamer  # local import to avoid heavy startup cost

    streamer = NFStreamer(
        source=pcap_path,
        # Match the live worker for feature parity.
        idle_timeout=int(__import__("os").getenv("NFSTREAM_IDLE_TIMEOUT", "30")),
        active_timeout=int(__import__("os").getenv("NFSTREAM_ACTIVE_TIMEOUT", "120")),
        n_dissections=0,
        statistical_analysis=True,
    )
    return list(streamer)


async def replay_pcap(
    pcap_path: str,
    speed: float,
    detection_mode: Literal["ml", "snort", "hybrid"],
    session_id: str,
    redis_pool: aioredis.Redis,
    stop_event: asyncio.Event,
    flow_ttl_seconds: int = DEFAULT_FLOW_TTL_SECONDS,
    snort_hash_ttl_seconds: int = DEFAULT_SNORT_HASH_TTL_SECONDS,
) -> None:
    """Replay *pcap_path* into the live Redis pipeline.

    Parameters
    ----------
    pcap_path : str
        Local path to the PCAP/PCAPNG file.
    speed : float
        Replay multiplier. ``1.0`` = wall-clock. ``0.0`` = max speed.
    detection_mode : "ml" | "snort" | "hybrid"
        Drives whether Snort is replayed alongside.
    session_id : str
        Tag for log lines; the SSE filter resolves verdicts itself.
    redis_pool : aioredis.Redis
        The same connection pool the SSE generator subscribes to.
    stop_event : asyncio.Event
        Setting this causes the coroutine to return promptly.

    Notes
    -----
    Exceptions are logged but not re-raised — the caller (live.py session
    endpoint) wraps this in a background ``asyncio.Task`` and observes
    completion via ``stop_event`` / task done state.
    """
    log.info(
        "pcap_replay: start id=%s pcap=%s speed=%s mode=%s",
        session_id, pcap_path, speed, detection_mode,
    )

    loop = asyncio.get_running_loop()

    # 1) Run Snort offline once (blocking, executor) if signature path is requested.
    snort_alerts: dict[str, dict[str, Any]] = {}
    if detection_mode in ("snort", "hybrid") and snort_offline.is_available():
        try:
            snort_alerts = await loop.run_in_executor(
                None, snort_offline.run, pcap_path
            )
            log.info(
                "pcap_replay: snort produced %d alert flows for session %s",
                len(snort_alerts), session_id,
            )
        except Exception:
            log.exception("pcap_replay: snort_offline.run failed")
            snort_alerts = {}
    elif detection_mode in ("snort", "hybrid"):
        log.info(
            "pcap_replay: snort requested but not available — falling back to ML",
        )

    if stop_event.is_set():
        log.info("pcap_replay: stop requested before extraction; aborting")
        return

    # 2) Drain NFStream off-loop. This is the expensive step for large PCAPs.
    try:
        flows = await loop.run_in_executor(None, _iter_flows_sync, pcap_path)
    except Exception:
        log.exception("pcap_replay: nfstream extraction failed")
        return

    log.info(
        "pcap_replay: extracted %d flows for session %s", len(flows), session_id,
    )

    # Sort flows by first-seen for sensible wall-clock pacing (NFStream emits
    # in completion order, not arrival order).
    flows.sort(key=_safe_first_seen_ms)

    # 3) Publish loop with cooperative cancellation and speed pacing.
    prev_seen_ms: float | None = None
    publish_only_snort = detection_mode == "snort"

    # Max-speed (speed==0) rate ceiling. Parsed once here. budget = events
    # allowed per _RATE_WINDOW_S slice; when hit we sleep the remainder of the
    # window (cancellable) so the SSE emission rate stays ~max_eps.
    max_eps = 0
    if not speed:
        try:
            max_eps = int(os.getenv("PCAP_REPLAY_MAX_EPS", str(DEFAULT_MAX_EPS)))
        except ValueError:
            max_eps = DEFAULT_MAX_EPS
        max_eps = max(0, max_eps)
    rate_budget = max(1, int(max_eps * _RATE_WINDOW_S)) if max_eps > 0 else 0
    rate_window_start = time.monotonic()
    rate_window_count = 0

    for flow in flows:
        if stop_event.is_set():
            log.info("pcap_replay: stop requested; aborting at %s", session_id)
            return

        try:
            features = extract_cic_features(flow)
        except Exception:
            log.debug("pcap_replay: feature extraction failed", exc_info=True)
            continue

        flow_key = _flow_key_for(flow, features)

        # --- Pacing -----------------------------------------------------
        if speed and speed > 0:
            first_ms = _safe_first_seen_ms(flow)
            if prev_seen_ms is not None and first_ms >= prev_seen_ms:
                delta_s = (first_ms - prev_seen_ms) / 1000.0 / speed
                # Cap any single sleep so a sparse PCAP doesn't pin the
                # session for hours — half a minute is plenty to feel "live".
                delta_s = min(delta_s, 30.0)
                if delta_s > 0:
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=delta_s)
                        # If we got here without timing out, stop was set.
                        return
                    except asyncio.TimeoutError:
                        pass
            prev_seen_ms = first_ms

        # --- Snort publish (if any) -------------------------------------
        alert = snort_alerts.get(flow_key)
        if alert is not None:
            try:
                # Persist a snort:<key> hash so the joiner's hash-lookup
                # path also finds the alert (mirrors snort_tailer_worker).
                snort_hash_payload = {k: ("" if v is None else str(v)) for k, v in alert.items()}
                pipe = redis_pool.pipeline(transaction=False)
                pipe.hset(f"{SNORT_HASH_PREFIX}{flow_key}", mapping=snort_hash_payload)
                pipe.expire(f"{SNORT_HASH_PREFIX}{flow_key}", snort_hash_ttl_seconds)
                pipe.publish(SNORT_ALERTS_CHANNEL, json.dumps(alert, default=str))
                await pipe.execute()
            except Exception:
                log.debug("pcap_replay: snort publish failed", exc_info=True)

        # --- Flow publish ------------------------------------------------
        # When mode == "snort" we still write the flow hash so the joiner
        # can render src/dst/etc, but we *only* publish flow_completed when
        # there's a matching alert; otherwise the joiner would also fire
        # benign/ML-only paths we want hidden.
        if publish_only_snort and alert is None:
            continue

        try:
            redis_features = _strip_session_meta(features)
            pipe = redis_pool.pipeline(transaction=False)
            pipe.hset(flow_key, mapping=redis_features)
            pipe.expire(flow_key, flow_ttl_seconds)
            pipe.publish(FLOW_COMPLETED_CHANNEL, flow_key)
            await pipe.execute()
        except Exception:
            log.debug("pcap_replay: flow publish failed", exc_info=True)
            continue

        # Max-speed pacing. With no cap (max_eps==0) just yield so we don't
        # starve the event loop. With a cap, spend a per-window event budget
        # then sleep out the rest of the window — keeps the SSE rate bounded
        # so a large PCAP can't firehose the client.
        if not speed:
            if rate_budget == 0:
                await asyncio.sleep(0)
            else:
                rate_window_count += 1
                if rate_window_count >= rate_budget:
                    remaining = _RATE_WINDOW_S - (time.monotonic() - rate_window_start)
                    if remaining > 0:
                        try:
                            await asyncio.wait_for(stop_event.wait(), timeout=remaining)
                            # Returned without timing out => stop was requested.
                            return
                        except asyncio.TimeoutError:
                            pass
                    rate_window_start = time.monotonic()
                    rate_window_count = 0

    log.info("pcap_replay: completed session=%s", session_id)
