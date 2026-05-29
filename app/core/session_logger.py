"""
Per-session dual-format logger for /live sessions.

Each session writes two files in ``app/logs/``:

* ``session_<id>_<ts>.csv``     — flat, Excel-friendly summary row per event.
* ``session_<id>_<ts>.ndjson``  — one full JSON object per line (newline-delimited
                                  JSON), preserving the per-event payload including
                                  ``stage2_probs``/``stage3_probs`` arrays and the
                                  full MITRE enrichment.

This is intentionally separate from the legacy global ``traffic_logger.py``
(single file, all sessions concatenated) — the legacy logger keeps the older
``traffic_<ts>.csv`` contract for /live/logs backward compatibility, while
this module owns the new session-scoped artefacts that drive the
``GET /live/session/{id}/log`` download endpoint.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any


log = logging.getLogger(__name__)


SESSION_CSV_HEADERS: list[str] = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "verdict",        # confirmed | signature_only | ml_only | benign
    "prediction",     # Malicious | Suspicious | Normal | Snort-Only
    "family",
    "leaf",           # attack_type
    "severity",
    "confidence",
    "stage1_p",
    "stage2_p",
    "stage3_p",
    "snort_sid",
    "snort_msg",
    "snort_classtype",
    "mitre_tactic",
    "model_version",
]


def _first_mitre_tactic(mitre: Any) -> str:
    """Extract a single tactic name for the CSV cell; NDJSON keeps the full dict."""
    if not isinstance(mitre, dict):
        return ""
    tactics = mitre.get("tactics")
    if isinstance(tactics, list) and tactics:
        first = tactics[0]
        if isinstance(first, dict):
            return str(first.get("name", first.get("id", "")))
        return str(first)
    return ""


def _row_from_event(event: dict[str, Any]) -> dict[str, Any]:
    """Project a live SSE event into the flat CSV row schema."""
    return {
        "timestamp": event.get("timestamp", ""),
        "src_ip": event.get("src_ip", ""),
        "dst_ip": event.get("dst_ip", ""),
        "src_port": event.get("src_port", ""),
        "dst_port": event.get("dst_port", ""),
        "protocol": event.get("protocol", ""),
        "verdict": event.get("source", ""),
        "prediction": event.get("prediction", ""),
        "family": event.get("family") or "",
        "leaf": event.get("attack_type") or "",
        "severity": event.get("severity") or "",
        "confidence": event.get("confidence", ""),
        "stage1_p": event.get("stage1_p", ""),
        "stage2_p": event.get("stage2_p", ""),
        "stage3_p": event.get("stage3_p", ""),
        "snort_sid": event.get("snort_sid", "") or "",
        "snort_msg": event.get("snort_msg", "") or "",
        "snort_classtype": event.get("snort_classtype", "") or "",
        "mitre_tactic": _first_mitre_tactic(event.get("mitre")),
        "model_version": event.get("model_version", ""),
    }


class SessionLogger:
    """Owns one CSV + one NDJSON file for a single live session.

    Files are opened in ``start()`` and closed in ``close()``. Each ``log()``
    call writes one row to the CSV and one line to the NDJSON, flushing both
    immediately so a kill-9 mid-session still yields a usable artefact for
    the download endpoint.
    """

    __slots__ = (
        "_log_dir",
        "_session_id",
        "_csv_path",
        "_ndjson_path",
        "_csv_handle",
        "_ndjson_handle",
        "_csv_writer",
        "_row_count",
        "_closed",
    )

    def __init__(self, log_dir: Path, session_id: str) -> None:
        self._log_dir = log_dir
        self._session_id = session_id
        self._log_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        safe_id = session_id.replace("/", "_").replace("..", "_")[:32]
        stem = f"session_{safe_id}_{ts}"
        self._csv_path: Path = self._log_dir / f"{stem}.csv"
        self._ndjson_path: Path = self._log_dir / f"{stem}.ndjson"

        self._csv_handle: io.TextIOWrapper | None = None
        self._ndjson_handle: io.TextIOWrapper | None = None
        self._csv_writer: csv.DictWriter | None = None
        self._row_count: int = 0
        self._closed: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        self._csv_handle = open(
            self._csv_path, "w", newline="", encoding="utf-8"
        )
        self._csv_writer = csv.DictWriter(
            self._csv_handle,
            fieldnames=SESSION_CSV_HEADERS,
            extrasaction="ignore",
        )
        self._csv_writer.writeheader()
        self._csv_handle.flush()

        self._ndjson_handle = open(
            self._ndjson_path, "w", encoding="utf-8"
        )
        self._closed = False

    def log(self, event: dict[str, Any]) -> None:
        """Append one event to both files. Silently no-ops after close()."""
        if self._closed:
            return
        try:
            if self._csv_writer is not None and self._csv_handle is not None:
                self._csv_writer.writerow(_row_from_event(event))
                self._csv_handle.flush()
            if self._ndjson_handle is not None:
                self._ndjson_handle.write(
                    json.dumps(event, default=str, ensure_ascii=False) + "\n"
                )
                self._ndjson_handle.flush()
            self._row_count += 1
        except Exception:
            # Logging must never break the SSE generator. Diagnostics only.
            log.exception("SessionLogger.log failed for session %s", self._session_id)

    def close(self) -> None:
        """Flush and close both handles. Idempotent."""
        if self._closed:
            return
        self._closed = True
        for handle in (self._csv_handle, self._ndjson_handle):
            if handle is not None and not handle.closed:
                try:
                    handle.close()
                except OSError:
                    log.debug("SessionLogger.close handle error", exc_info=True)
        self._csv_writer = None
        self._csv_handle = None
        self._ndjson_handle = None

    # ------------------------------------------------------------------
    # Accessors used by the download endpoint
    # ------------------------------------------------------------------
    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def row_count(self) -> int:
        return self._row_count

    @property
    def csv_path(self) -> Path:
        return self._csv_path

    @property
    def ndjson_path(self) -> Path:
        return self._ndjson_path
