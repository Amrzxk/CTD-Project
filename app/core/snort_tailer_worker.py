"""
Snort Tailer Worker — watches Snort 3 JSON alert log and publishes to Redis.

Standalone background worker that:
  1. Tails the Snort 3 ``alert_json`` log file specified by ``SNORT_ALERT_LOG``.
  2. Parses each new JSON alert line for the 5-tuple and Snort metadata.
  3. Constructs the canonical flow key (shared with the flow meter worker).
  4. Publishes the alert payload to the ``snort_alerts`` Redis Pub/Sub channel.

Run as a module::

    python -m app.core.snort_tailer_worker

All configuration comes from environment variables (or ``.env`` file).

.. note::
   This worker must **never** run inside the FastAPI Uvicorn event loop.
   It is a blocking process that polls the alert log indefinitely.

.. note::
   **Required Snort 3 configuration** — add the following to ``snort.lua``::

       alert_json = {
           file = true,
           limit = 100,
           fields = 'timestamp src_addr src_port dst_addr dst_port '
                 .. 'proto sid gid rev msg action class priority'
       }

   Without these fields the tailer cannot construct valid flow keys or
   extract meaningful Snort metadata.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Generator, Optional

# ---------------------------------------------------------------------------
# Environment bootstrap — load .env before anything else
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv

    _env_path = Path(__file__).resolve().parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
    else:
        load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Third-party imports
# ---------------------------------------------------------------------------
import redis

from app.core.key_utils import flow_key

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [snort_tailer]  %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (all from environment)
# ---------------------------------------------------------------------------
SNORT_ALERT_LOG: str = os.getenv("SNORT_ALERT_LOG", "/var/log/snort/alert_json.txt")
REDIS_HOST: str = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD: str | None = os.getenv("REDIS_PASSWORD") or None
SNORT_POLL_INTERVAL: float = float(os.getenv("SNORT_POLL_INTERVAL", "0.25"))
# Keep the snort:<flow_key> hash alive past the NFStream flow-export delay so a
# flow exporting after Snort fired still finds the hash via the joiner's
# _lookup_snort fallback and emits `confirmed`. Keep >= SNORT_JOIN_WAIT_S; with
# the fast active timeout (~10s) 60s is comfortable.
SNORT_HASH_TTL: int = int(os.getenv("SNORT_HASH_TTL", "60"))

PUBSUB_CHANNEL = "snort_alerts"
SNORT_HASH_PREFIX = "snort:"

# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
_shutdown_requested = False


def _signal_handler(signum, frame):  # noqa: ARG001
    global _shutdown_requested
    log.info("Shutdown signal received (%s). Stopping tailer …", signum)
    _shutdown_requested = True


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


# ---------------------------------------------------------------------------
# Alert parsing
# ---------------------------------------------------------------------------

def _parse_address_port(ap_str: str) -> tuple[str, int]:
    """Parse Snort's combined ``addr:port`` format (``src_ap`` / ``dst_ap``).

    Examples
    --------
    >>> _parse_address_port("192.168.1.2:50284")
    ('192.168.1.2', 50284)
    >>> _parse_address_port("[::1]:443")
    ('::1', 443)
    """
    if ap_str.startswith("["):
        # IPv6 bracket notation: [::1]:443
        bracket_end = ap_str.rfind("]")
        addr = ap_str[1:bracket_end]
        port = int(ap_str[bracket_end + 2:]) if bracket_end + 2 < len(ap_str) else 0
        return addr, port
    # IPv4: 192.168.1.2:50284
    parts = ap_str.rsplit(":", 1)
    if len(parts) == 2:
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return ap_str, 0
    return ap_str, 0


def _parse_alert(line: str) -> Optional[dict[str, Any]]:
    """Parse a single Snort 3 JSON alert line into a structured payload.

    Returns ``None`` if the line is empty, malformed, or missing required
    fields.  The caller should skip and continue.
    """
    line = line.strip()
    if not line:
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        log.warning("Skipping malformed JSON line: %s — %s", line[:120], exc)
        return None

    # --- Extract 5-tuple ---
    # Prefer split fields (src_addr / src_port), fall back to combined
    # (src_ap / dst_ap) if split fields are absent.
    src_ip: Optional[str] = data.get("src_addr")
    dst_ip: Optional[str] = data.get("dst_addr")
    src_port: int = 0
    dst_port: int = 0

    if src_ip is not None:
        # Split fields available
        try:
            src_port = int(data.get("src_port", 0))
        except (ValueError, TypeError):
            src_port = 0
        try:
            dst_port = int(data.get("dst_port", 0))
        except (ValueError, TypeError):
            dst_port = 0
    else:
        # Fall back to combined address:port fields
        src_ap = data.get("src_ap", "")
        dst_ap = data.get("dst_ap", "")
        if src_ap:
            src_ip, src_port = _parse_address_port(str(src_ap))
        if dst_ap:
            dst_ip, dst_port = _parse_address_port(str(dst_ap))

    if not src_ip or not dst_ip:
        log.warning("Alert missing IP addresses — skipping: %s", line[:120])
        return None

    # Protocol — Snort 3 uses uppercase strings ("TCP", "UDP", "ICMP")
    protocol: str = str(data.get("proto", "TCP")).upper()

    # --- Construct canonical flow key ---
    key = flow_key(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
    )

    # --- Extract Snort metadata ---
    # ``rule`` field may be "gid:sid:rev" format, or sid/gid/rev may be separate
    sid = data.get("sid")
    if sid is None:
        rule_str = data.get("rule", "")
        if rule_str and ":" in str(rule_str):
            parts = str(rule_str).split(":")
            try:
                sid = int(parts[1]) if len(parts) >= 2 else 0
            except ValueError:
                sid = 0
        else:
            sid = 0

    return {
        "flow_key": key,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "snort_sid": int(sid) if sid else 0,
        "snort_msg": str(data.get("msg", "")),
        "snort_classtype": str(data.get("class", "")),
        "snort_priority": int(data.get("priority", 0)),
        "snort_action": str(data.get("action", "")),
        "snort_timestamp": str(data.get("timestamp", "")),
    }


# ---------------------------------------------------------------------------
# File tailer
# ---------------------------------------------------------------------------

def _wait_for_file(path: str) -> None:
    """Block until the alert log file exists, with exponential backoff."""
    backoff = 1.0
    max_backoff = 30.0
    while not _shutdown_requested:
        if os.path.isfile(path):
            return
        log.info("Waiting for alert log to appear: %s (retry in %.0fs)", path, backoff)
        time.sleep(backoff)
        backoff = min(backoff * 2, max_backoff)


def _get_inode(path: str) -> int:
    """Return the inode number (or 0 on Windows where inodes don't exist)."""
    try:
        return os.stat(path).st_ino
    except (OSError, AttributeError):
        return 0


def _tail_lines(path: str) -> Generator[str, None, None]:
    """Yield new lines appended to *path*, handling rotation and truncation.

    This is a polling-based ``tail -f`` implementation:

    * **Truncation**: If the file size shrinks (Snort restart or manual
      truncation), seek back to the beginning.
    * **Replacement / rotation**: If the inode changes (logrotate moved
      the file), reopen the new file from the beginning.
    * **File disappears**: Wait for it to reappear.

    The generator runs indefinitely until ``_shutdown_requested`` is set.
    """
    _wait_for_file(path)
    if _shutdown_requested:
        return

    fh = open(path, "r", encoding="utf-8", errors="replace")  # noqa: SIM115
    # Seek to end — we only want *new* alerts from this point forward.
    fh.seek(0, os.SEEK_END)
    current_inode = _get_inode(path)
    current_pos = fh.tell()

    log.info("Tailing alert log: %s (pos=%d)", path, current_pos)

    try:
        while not _shutdown_requested:
            # --- Check for rotation / replacement ---
            try:
                new_inode = _get_inode(path)
            except OSError:
                # File disappeared — wait for it to come back
                fh.close()
                log.warning("Alert log disappeared. Waiting for it to reappear …")
                _wait_for_file(path)
                if _shutdown_requested:
                    return
                fh = open(path, "r", encoding="utf-8", errors="replace")  # noqa: SIM115
                current_inode = _get_inode(path)
                current_pos = 0
                log.info("Alert log reappeared. Reading from beginning.")
                continue

            if new_inode != 0 and new_inode != current_inode:
                # Inode changed — file was rotated / replaced
                fh.close()
                log.info("Alert log rotated (inode %d → %d). Reopening …",
                         current_inode, new_inode)
                fh = open(path, "r", encoding="utf-8", errors="replace")  # noqa: SIM115
                current_inode = new_inode
                current_pos = 0

            # --- Check for truncation ---
            try:
                file_size = os.path.getsize(path)
            except OSError:
                file_size = 0

            if file_size < current_pos:
                log.info("Alert log truncated (size %d < pos %d). Seeking to start.",
                         file_size, current_pos)
                fh.seek(0)
                current_pos = 0

            # --- Read new lines ---
            lines_read = 0
            for line in fh:
                lines_read += 1
                yield line
            current_pos = fh.tell()

            # If no new content, sleep before polling again
            if lines_read == 0:
                time.sleep(SNORT_POLL_INTERVAL)
    finally:
        fh.close()


# ---------------------------------------------------------------------------
# Main worker loop
# ---------------------------------------------------------------------------

def run() -> None:
    """Entry-point: tail Snort alerts, parse, publish to Redis Pub/Sub."""
    global _shutdown_requested

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    log.info("=" * 60)
    log.info("  Snort Tailer Worker starting")
    log.info("  Alert log : %s", SNORT_ALERT_LOG)
    log.info("  Redis     : %s:%s", REDIS_HOST, REDIS_PORT)
    log.info("  Channel   : %s", PUBSUB_CHANNEL)
    log.info("  Poll interval : %.2f s", SNORT_POLL_INTERVAL)
    log.info("=" * 60)

    # --- Redis connection ---
    try:
        r = _connect_redis()
        log.info("Redis connection OK.")
    except redis.ConnectionError as exc:
        log.error("Cannot connect to Redis at %s:%s — %s", REDIS_HOST, REDIS_PORT, exc)
        sys.exit(1)

    # --- Tail and publish ---
    alert_count = 0
    skip_count = 0

    for line in _tail_lines(SNORT_ALERT_LOG):
        if _shutdown_requested:
            break

        payload = _parse_alert(line)
        if payload is None:
            skip_count += 1
            continue

        # Publish to Redis Pub/Sub AND store as a hash so the SSE joiner
        # can look up Snort verdicts by flow key without a race condition.
        message = json.dumps(payload)
        hash_key = f"{SNORT_HASH_PREFIX}{payload['flow_key']}"
        # Hash values must be strings — flatten ints.
        hash_payload = {k: str(v) for k, v in payload.items()}
        try:
            pipe = r.pipeline(transaction=False)
            pipe.hset(hash_key, mapping=hash_payload)
            pipe.expire(hash_key, SNORT_HASH_TTL)
            pipe.publish(PUBSUB_CHANNEL, message)
            pipe.execute()
        except redis.ConnectionError:
            log.warning("Redis publish failed — reconnecting …")
            try:
                r = _connect_redis()
                pipe = r.pipeline(transaction=False)
                pipe.hset(hash_key, mapping=hash_payload)
                pipe.expire(hash_key, SNORT_HASH_TTL)
                pipe.publish(PUBSUB_CHANNEL, message)
                pipe.execute()
            except Exception:
                log.exception("Redis reconnection failed. Skipping alert.")
                continue

        alert_count += 1
        if alert_count % 50 == 0:
            log.info("Published %d alerts (%d skipped) …", alert_count, skip_count)

        log.debug("Published alert: %s → %s", payload["flow_key"], payload["snort_msg"])

    log.info("Snort Tailer Worker stopped. Total published: %d, skipped: %d",
             alert_count, skip_count)


# ---------------------------------------------------------------------------
# Module entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    run()
