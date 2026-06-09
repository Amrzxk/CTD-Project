"""
Flow Meter Worker — NFStream-based live flow capture with Redis storage.

Standalone background worker that:
  1. Listens on ``CAPTURE_INTERFACE`` via NFStream.
  2. Extracts CIC-IDS statistical features from each completed flow.
  3. Stores them in Redis Hashes keyed by the canonical 5-tuple string.
  4. Sets a TTL (default 60 s) on every key to prevent memory exhaustion.

Run as a module::

    python -m app.core.flow_meter_worker

All configuration comes from environment variables (or ``.env`` file).

.. note::
   This worker must **never** run inside the FastAPI Uvicorn event loop.
   It is a blocking process that iterates flows from NFStream indefinitely.

.. note::
   On AWS, VXLAN-encapsulated traffic from VPC Traffic Mirroring must be
   decapsulated at the OS / infrastructure layer (e.g. a Linux VXLAN
   interface) *before* it reaches NFStream.  This worker does not perform
   VXLAN parsing in Python for performance reasons.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Environment bootstrap — load .env before anything else
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv

    # Walk upward to find the .env closest to the project root
    _env_path = Path(__file__).resolve().parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
    else:
        load_dotenv()  # fall back to cwd
except ImportError:
    pass  # python-dotenv is optional; env vars can be set externally

# ---------------------------------------------------------------------------
# Third-party imports (deferred so env is loaded first)
# ---------------------------------------------------------------------------
import redis
from nfstream import NFStreamer

from app.core.key_utils import flow_key

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [flow_meter]  %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (all from environment)
# ---------------------------------------------------------------------------
CAPTURE_INTERFACE: str = os.getenv("CAPTURE_INTERFACE", "lo")
REDIS_HOST: str = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD: str | None = os.getenv("REDIS_PASSWORD") or None
FLOW_TTL_SECONDS: int = int(os.getenv("FLOW_TTL_SECONDS", "60"))

# NFStream flow timeout tunables. active_timeout=45s (was 120s) so sustained
# live attacks export their flow features within ~45s — that lets ML run and
# join the Snort hit into a `confirmed` verdict instead of leaving it
# signature_only. idle_timeout stays 30s (ML-precision-tuned). The batch/eval
# path (data_standardizer.from_pcap) hard-codes its own timeouts and is
# unaffected by these env defaults.
NFSTREAM_IDLE_TIMEOUT: int = int(os.getenv("NFSTREAM_IDLE_TIMEOUT", "30"))
NFSTREAM_ACTIVE_TIMEOUT: int = int(os.getenv("NFSTREAM_ACTIVE_TIMEOUT", "45"))

# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------
_PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}


def _proto_str(proto_num: int) -> str:
    return _PROTO_MAP.get(proto_num, str(proto_num))


# ---------------------------------------------------------------------------
# CIC-IDS Feature Extraction
# ---------------------------------------------------------------------------

def extract_cic_features(flow) -> dict[str, Any]:
    """Map NFStream flow attributes to CIC-IDS statistical features.

    Features that NFStream does not natively expose (bulk statistics,
    active/idle period metrics, initial TCP window bytes) are defaulted
    to ``0``.  This is consistent with how CIC-IDS datasets handle
    flows where those counters are not applicable.
    """
    duration_ms: float = getattr(flow, "bidirectional_duration_ms", 0) or 0
    duration_sec: float = duration_ms / 1000.0
    eps = 1e-9  # guard against division by zero

    src2dst_pkts: int = getattr(flow, "src2dst_packets", 0) or 0
    dst2src_pkts: int = getattr(flow, "dst2src_packets", 0) or 0
    src2dst_bytes: int = getattr(flow, "src2dst_bytes", 0) or 0
    dst2src_bytes: int = getattr(flow, "dst2src_bytes", 0) or 0
    bi_bytes: int = getattr(flow, "bidirectional_bytes", 0) or 0
    bi_pkts: int = getattr(flow, "bidirectional_packets", 0) or 0

    # Packet-size statistics
    src2dst_max_ps: float = getattr(flow, "src2dst_max_ps", 0) or 0
    src2dst_min_ps: float = getattr(flow, "src2dst_min_ps", 0) or 0
    src2dst_mean_ps: float = getattr(flow, "src2dst_mean_ps", 0) or 0
    src2dst_stddev_ps: float = getattr(flow, "src2dst_stddev_ps", 0) or 0

    dst2src_max_ps: float = getattr(flow, "dst2src_max_ps", 0) or 0
    dst2src_min_ps: float = getattr(flow, "dst2src_min_ps", 0) or 0
    dst2src_mean_ps: float = getattr(flow, "dst2src_mean_ps", 0) or 0
    dst2src_stddev_ps: float = getattr(flow, "dst2src_stddev_ps", 0) or 0

    bi_max_ps: float = getattr(flow, "bidirectional_max_ps", 0) or 0
    bi_min_ps: float = getattr(flow, "bidirectional_min_ps", 0) or 0
    bi_mean_ps: float = getattr(flow, "bidirectional_mean_ps", 0) or 0
    bi_stddev_ps: float = getattr(flow, "bidirectional_stddev_ps", 0) or 0

    # Inter-arrival time statistics
    bi_mean_piat: float = getattr(flow, "bidirectional_mean_piat_ms", 0) or 0
    bi_stddev_piat: float = getattr(flow, "bidirectional_stddev_piat_ms", 0) or 0
    bi_max_piat: float = getattr(flow, "bidirectional_max_piat_ms", 0) or 0
    bi_min_piat: float = getattr(flow, "bidirectional_min_piat_ms", 0) or 0

    s2d_mean_piat: float = getattr(flow, "src2dst_mean_piat_ms", 0) or 0
    s2d_stddev_piat: float = getattr(flow, "src2dst_stddev_piat_ms", 0) or 0
    s2d_max_piat: float = getattr(flow, "src2dst_max_piat_ms", 0) or 0
    s2d_min_piat: float = getattr(flow, "src2dst_min_piat_ms", 0) or 0
    s2d_duration_ms: float = getattr(flow, "src2dst_duration_ms", 0) or 0

    d2s_mean_piat: float = getattr(flow, "dst2src_mean_piat_ms", 0) or 0
    d2s_stddev_piat: float = getattr(flow, "dst2src_stddev_piat_ms", 0) or 0
    d2s_max_piat: float = getattr(flow, "dst2src_max_piat_ms", 0) or 0
    d2s_min_piat: float = getattr(flow, "dst2src_min_piat_ms", 0) or 0
    d2s_duration_ms: float = getattr(flow, "dst2src_duration_ms", 0) or 0

    # TCP flag counters
    s2d_syn: int = getattr(flow, "src2dst_syn_packets", 0) or 0
    d2s_syn: int = getattr(flow, "dst2src_syn_packets", 0) or 0
    s2d_fin: int = getattr(flow, "src2dst_fin_packets", 0) or 0
    d2s_fin: int = getattr(flow, "dst2src_fin_packets", 0) or 0
    s2d_rst: int = getattr(flow, "src2dst_rst_packets", 0) or 0
    d2s_rst: int = getattr(flow, "dst2src_rst_packets", 0) or 0
    s2d_psh: int = getattr(flow, "src2dst_psh_packets", 0) or 0
    d2s_psh: int = getattr(flow, "dst2src_psh_packets", 0) or 0
    s2d_ack: int = getattr(flow, "src2dst_ack_packets", 0) or 0
    d2s_ack: int = getattr(flow, "dst2src_ack_packets", 0) or 0
    s2d_urg: int = getattr(flow, "src2dst_urg_packets", 0) or 0
    d2s_urg: int = getattr(flow, "dst2src_urg_packets", 0) or 0

    # Derived rates
    flow_bytes_sec = bi_bytes / (duration_sec + eps)
    flow_pkts_sec = bi_pkts / (duration_sec + eps)
    fwd_pkts_sec = src2dst_pkts / (duration_sec + eps)
    bwd_pkts_sec = dst2src_pkts / (duration_sec + eps)

    # Down/Up ratio
    down_up = (dst2src_pkts / src2dst_pkts) if src2dst_pkts > 0 else 0

    # Packet-length variance = stddev²
    pkt_len_var = bi_stddev_ps ** 2

    # Header-length estimate (IP header ~20 bytes per packet)
    fwd_hdr_len = src2dst_pkts * 20
    bwd_hdr_len = dst2src_pkts * 20

    return {
        # --- 5-tuple metadata (not model features, but needed for key/display) ---
        "src_ip": str(getattr(flow, "src_ip", "")),
        "dst_ip": str(getattr(flow, "dst_ip", "")),
        "src_port": str(getattr(flow, "src_port", 0)),
        "dst_port": str(getattr(flow, "dst_port", 0)),
        "protocol": str(getattr(flow, "protocol", 0)),
        "protocol_name": _proto_str(getattr(flow, "protocol", 0)),
        "application_name": str(getattr(flow, "application_name", "Unknown")),

        # --- CIC-IDS statistical features ---
        "flow_duration": str(duration_ms),
        "total_fwd_packets": str(src2dst_pkts),
        "total_bwd_packets": str(dst2src_pkts),
        "total_length_fwd_packets": str(src2dst_bytes),
        "total_length_bwd_packets": str(dst2src_bytes),

        # Forward packet-size stats
        "fwd_packet_length_max": str(src2dst_max_ps),
        "fwd_packet_length_min": str(src2dst_min_ps),
        "fwd_packet_length_mean": str(src2dst_mean_ps),
        "fwd_packet_length_std": str(src2dst_stddev_ps),

        # Backward packet-size stats
        "bwd_packet_length_max": str(dst2src_max_ps),
        "bwd_packet_length_min": str(dst2src_min_ps),
        "bwd_packet_length_mean": str(dst2src_mean_ps),
        "bwd_packet_length_std": str(dst2src_stddev_ps),

        # Throughput
        "flow_bytes_per_sec": str(round(flow_bytes_sec, 6)),
        "flow_packets_per_sec": str(round(flow_pkts_sec, 6)),

        # Flow-level IAT
        "flow_iat_mean": str(bi_mean_piat),
        "flow_iat_std": str(bi_stddev_piat),
        "flow_iat_max": str(bi_max_piat),
        "flow_iat_min": str(bi_min_piat),

        # Forward IAT
        "fwd_iat_total": str(s2d_duration_ms),
        "fwd_iat_mean": str(s2d_mean_piat),
        "fwd_iat_std": str(s2d_stddev_piat),
        "fwd_iat_max": str(s2d_max_piat),
        "fwd_iat_min": str(s2d_min_piat),

        # Backward IAT
        "bwd_iat_total": str(d2s_duration_ms),
        "bwd_iat_mean": str(d2s_mean_piat),
        "bwd_iat_std": str(d2s_stddev_piat),
        "bwd_iat_max": str(d2s_max_piat),
        "bwd_iat_min": str(d2s_min_piat),

        # TCP flag counters — directional
        "fwd_psh_flags": str(s2d_psh),
        "bwd_psh_flags": str(d2s_psh),
        "fwd_urg_flags": str(s2d_urg),
        "bwd_urg_flags": str(d2s_urg),

        # Header length estimates
        "fwd_header_length": str(fwd_hdr_len),
        "bwd_header_length": str(bwd_hdr_len),

        # Packets per second — directional
        "fwd_packets_per_sec": str(round(fwd_pkts_sec, 6)),
        "bwd_packets_per_sec": str(round(bwd_pkts_sec, 6)),

        # Bidirectional packet-size stats
        "packet_length_min": str(bi_min_ps),
        "packet_length_max": str(bi_max_ps),
        "packet_length_mean": str(bi_mean_ps),
        "packet_length_std": str(bi_stddev_ps),
        "packet_length_variance": str(round(pkt_len_var, 6)),

        # TCP flag counters — aggregate
        "fin_flag_count": str(s2d_fin + d2s_fin),
        "syn_flag_count": str(s2d_syn + d2s_syn),
        "rst_flag_count": str(s2d_rst + d2s_rst),
        "psh_flag_count": str(s2d_psh + d2s_psh),
        "ack_flag_count": str(s2d_ack + d2s_ack),
        "urg_flag_count": str(s2d_urg + d2s_urg),

        # Ratio / averages
        "down_up_ratio": str(round(down_up, 6)),
        "avg_packet_size": str(bi_mean_ps),
        "avg_fwd_segment_size": str(src2dst_mean_ps),
        "avg_bwd_segment_size": str(dst2src_mean_ps),

        # Bulk stats — NFStream does not track these natively
        "fwd_avg_bytes_per_bulk": "0",
        "fwd_avg_packets_per_bulk": "0",
        "fwd_avg_bulk_rate": "0",
        "bwd_avg_bytes_per_bulk": "0",
        "bwd_avg_packets_per_bulk": "0",
        "bwd_avg_bulk_rate": "0",

        # Subflow counters (identical to directional totals for NFStream)
        "subflow_fwd_packets": str(src2dst_pkts),
        "subflow_fwd_bytes": str(src2dst_bytes),
        "subflow_bwd_packets": str(dst2src_pkts),
        "subflow_bwd_bytes": str(dst2src_bytes),

        # Init window bytes — not exposed by NFStream
        "init_win_bytes_forward": "0",
        "init_win_bytes_backward": "0",

        # Active data packets forward (approx = all fwd packets)
        "act_data_pkt_fwd": str(src2dst_pkts),
        "min_seg_size_forward": str(src2dst_min_ps),

        # Active / Idle period stats — NFStream does not export these
        "active_mean": "0",
        "active_std": "0",
        "active_max": "0",
        "active_min": "0",
        "idle_mean": "0",
        "idle_std": "0",
        "idle_max": "0",
        "idle_min": "0",
    }


# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

def _connect_redis() -> redis.Redis:
    """Create a blocking Redis client from environment variables."""
    client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        decode_responses=True,
        socket_connect_timeout=10,
        socket_keepalive=True,
        retry_on_timeout=True,
    )
    client.ping()
    return client


FLOW_COMPLETED_CHANNEL = "flow_completed"


def _store_flow(r: redis.Redis, key: str, features: dict[str, str]) -> None:
    """Write CIC-IDS features into a Redis Hash, set TTL, and announce the flow.

    Uses a pipeline to batch ``HSET`` + ``EXPIRE`` + ``PUBLISH`` into a
    single round-trip. The ``PUBLISH`` on the ``flow_completed`` channel
    lets the FastAPI SSE joiner run ML inference on every completed flow
    in parallel with Snort (rather than only on Snort-flagged flows).
    """
    pipe = r.pipeline(transaction=False)
    pipe.hset(key, mapping=features)
    pipe.expire(key, FLOW_TTL_SECONDS)
    pipe.publish(FLOW_COMPLETED_CHANNEL, key)
    pipe.execute()


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
_shutdown_requested = False


def _signal_handler(signum, frame):  # noqa: ARG001
    global _shutdown_requested
    log.info("Shutdown signal received (%s). Finishing current flow batch …", signum)
    _shutdown_requested = True


# ---------------------------------------------------------------------------
# Main worker loop
# ---------------------------------------------------------------------------

def run() -> None:
    """Entry-point: capture flows, extract features, write to Redis."""
    global _shutdown_requested

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    log.info("=" * 60)
    log.info("  Flow Meter Worker starting")
    log.info("  Interface : %s", CAPTURE_INTERFACE)
    log.info("  Redis     : %s:%s", REDIS_HOST, REDIS_PORT)
    log.info("  Flow TTL  : %s s", FLOW_TTL_SECONDS)
    log.info("  NFStream idle / active timeout: %s / %s s",
             NFSTREAM_IDLE_TIMEOUT, NFSTREAM_ACTIVE_TIMEOUT)
    log.info("=" * 60)

    # --- Redis connection ---
    try:
        r = _connect_redis()
        log.info("Redis connection OK.")
    except redis.ConnectionError as exc:
        log.error("Cannot connect to Redis at %s:%s — %s", REDIS_HOST, REDIS_PORT, exc)
        sys.exit(1)

    # --- NFStream capture loop ---
    # NFStreamer blocks while listening and yields flows as they expire.
    # We wrap it in a retry loop so transient interface errors don't kill
    # the worker permanently (important on EC2 where ENIs may flap).
    consecutive_errors = 0
    max_consecutive_errors = 10
    backoff_base = 2  # seconds

    while not _shutdown_requested:
        try:
            log.info("Opening NFStreamer on '%s' …", CAPTURE_INTERFACE)
            streamer = NFStreamer(
                source=CAPTURE_INTERFACE,
                idle_timeout=NFSTREAM_IDLE_TIMEOUT,
                active_timeout=NFSTREAM_ACTIVE_TIMEOUT,
                # Performance: disable DPI to reduce CPU on high-throughput links
                n_dissections=0,
                statistical_analysis=True,
            )

            flow_count = 0
            for flow in streamer:
                if _shutdown_requested:
                    break

                features = extract_cic_features(flow)

                key = flow_key(
                    src_ip=features["src_ip"],
                    dst_ip=features["dst_ip"],
                    src_port=int(features["src_port"]),
                    dst_port=int(features["dst_port"]),
                    protocol=getattr(flow, "protocol", 0),
                )

                try:
                    _store_flow(r, key, features)
                except redis.ConnectionError:
                    log.warning("Redis write failed for %s — reconnecting …", key)
                    try:
                        r = _connect_redis()
                        _store_flow(r, key, features)
                    except Exception:
                        log.exception("Redis reconnection failed. Skipping flow.")
                        continue

                flow_count += 1
                if flow_count % 100 == 0:
                    log.info("Processed %d flows so far …", flow_count)

            # If we reach here the streamer finished (e.g. pcap file replay)
            log.info("NFStreamer finished. Total flows processed: %d", flow_count)
            consecutive_errors = 0

            # For live interfaces the streamer should block indefinitely,
            # but if the interface goes away it may return.  Give it a
            # moment before retrying.
            if not _shutdown_requested:
                log.info("Restarting capture in 3 s …")
                time.sleep(3)

        except KeyboardInterrupt:
            _shutdown_requested = True

        except Exception:
            consecutive_errors += 1
            log.exception(
                "NFStreamer error (consecutive: %d/%d).",
                consecutive_errors,
                max_consecutive_errors,
            )
            if consecutive_errors >= max_consecutive_errors:
                log.critical("Too many consecutive errors. Shutting down.")
                sys.exit(1)
            backoff = min(backoff_base ** consecutive_errors, 60)
            log.info("Retrying in %d s …", backoff)
            time.sleep(backoff)

    log.info("Flow Meter Worker stopped.")


# ---------------------------------------------------------------------------
# Module entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    run()
