import csv
import io
from datetime import datetime
from pathlib import Path
from typing import Optional


LOG_HEADERS = [
    "timestamp", "src_ip", "dst_ip", "sport", "dport", "protocol",
    "service", "state", "duration", "sbytes", "dbytes", "spkts", "dpkts",
    "prediction", "confidence", "severity", "attack_type",
]


class TrafficLogger:
    """Appends classified packets to per-session CSV log files."""

    def __init__(self, log_dir: Path):
        self._log_dir = log_dir
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._current_file: Optional[Path] = None
        self._writer: Optional[csv.DictWriter] = None
        self._handle: Optional[io.TextIOWrapper] = None
        self._row_count = 0

    @property
    def current_file(self) -> Optional[str]:
        return self._current_file.name if self._current_file else None

    @property
    def row_count(self) -> int:
        return self._row_count

    def start_session(self):
        """Open a new CSV log file for this capture session."""
        self.close()
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self._current_file = self._log_dir / f"traffic_{ts}.csv"
        self._handle = open(self._current_file, "w", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._handle, fieldnames=LOG_HEADERS, extrasaction="ignore")
        self._writer.writeheader()
        self._handle.flush()
        self._row_count = 0

    def log(self, packet: dict):
        """Append a single classified packet to the current log file."""
        if self._writer is None:
            return
        self._writer.writerow(packet)
        self._handle.flush()
        self._row_count += 1

    def close(self):
        """Flush and close the current log file."""
        if self._handle and not self._handle.closed:
            self._handle.close()
        self._handle = None
        self._writer = None

    def get_log_files(self) -> list[dict]:
        """List all CSV log files with metadata."""
        files = sorted(self._log_dir.glob("traffic_*.csv"), reverse=True)
        result = []
        for f in files:
            stat = f.stat()
            result.append({
                "filename": f.name,
                "size_bytes": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            })
        return result

    def get_log_path(self, filename: str) -> Optional[Path]:
        """Return the full path if the file exists in the log directory, else None."""
        # Prevent directory traversal
        safe_name = Path(filename).name
        path = self._log_dir / safe_name
        if path.exists() and path.suffix == ".csv":
            return path
        return None
