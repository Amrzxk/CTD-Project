"""
Snort offline replay — runs Snort 3 against an uploaded PCAP and returns
the alerts indexed by canonical flow key.

Used by ``/analyze/upload`` so batch PCAP analysis exercises the **hybrid**
ML + signature path, not just ML alone.  If Snort is unavailable (the
``SNORT_BIN`` environment variable is unset or the binary is missing) the
helper returns an empty dict and the caller transparently falls back to
ML-only.

Usage::

    from app.core.snort_offline import run as snort_replay
    alerts = snort_replay("/tmp/upload.pcap")
    # alerts is dict[flow_key, snort_payload]

Environment
-----------
SNORT_BIN
    Path to ``snort`` executable. When ``SNORT_WSL_DISTRO`` is set this can
    be just the binary name (e.g. ``snort``) since execution goes through
    ``wsl.exe`` — ``$PATH`` inside the distro is used.  When unset, the
    helper is a no-op and returns ``{}``.
SNORT_CONFIG
    Path to ``snort.lua``.  Required when ``SNORT_BIN`` is set.  When using
    WSL mode this should be a WSL-style path (e.g.
    ``/mnt/f/GradProject/Testing/snort/snort.lua``).
SNORT_WSL_DISTRO
    Optional. When set, Snort is invoked via ``wsl.exe -d <distro> --`` and
    Windows-style path arguments (``-c``, ``-r``, ``-l``) are translated to
    ``/mnt/<drive>/...`` form automatically.
SNORT_DAQ_DIR
    Optional. Passed as ``--daq-dir`` when set.  Required for source-built
    Snort installs that don't have the DAQ plugin dir on the default path
    (typically ``/usr/local/lib/daq``).
SNORT_OFFLINE_TIMEOUT
    Max seconds to wait for the Snort subprocess (default 300).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .key_utils import flow_key

log = logging.getLogger(__name__)


def _parse_address_port(ap_str: str) -> tuple[str, int]:
    """Parse Snort's combined ``addr:port`` format (mirrors snort_tailer_worker)."""
    if ap_str.startswith("["):
        bracket_end = ap_str.rfind("]")
        addr = ap_str[1:bracket_end]
        try:
            port = int(ap_str[bracket_end + 2:]) if bracket_end + 2 < len(ap_str) else 0
        except ValueError:
            port = 0
        return addr, port
    parts = ap_str.rsplit(":", 1)
    if len(parts) == 2:
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return ap_str, 0
    return ap_str, 0


def _parse_alert_line(line: str) -> dict[str, Any] | None:
    """Parse a single Snort 3 JSON alert line."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    src_ip = data.get("src_addr")
    dst_ip = data.get("dst_addr")
    src_port = 0
    dst_port = 0

    if src_ip is not None:
        try:
            src_port = int(data.get("src_port", 0))
        except (ValueError, TypeError):
            src_port = 0
        try:
            dst_port = int(data.get("dst_port", 0))
        except (ValueError, TypeError):
            dst_port = 0
    else:
        src_ap = data.get("src_ap", "")
        dst_ap = data.get("dst_ap", "")
        if src_ap:
            src_ip, src_port = _parse_address_port(str(src_ap))
        if dst_ap:
            dst_ip, dst_port = _parse_address_port(str(dst_ap))

    if not src_ip or not dst_ip:
        return None

    protocol = str(data.get("proto", "TCP")).upper()
    key = flow_key(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port,
                   dst_port=dst_port, protocol=protocol)

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


def _to_wsl_path(p: str | Path) -> str:
    """Translate a Windows path (``F:\\GradProject\\…``) to a WSL mount path
    (``/mnt/f/GradProject/…``).  Idempotent on already-POSIX paths.

    Relative paths are resolved against the current working directory first,
    because Snort-in-WSL has a different CWD than the Python process on the
    host and would otherwise fail to find the file.
    """
    s = str(p)
    if s.startswith("/"):
        return s
    pw = Path(s)
    if not pw.is_absolute():
        pw = pw.resolve()
    pw_posix = pw.as_posix()  # Windows backslashes → forward slashes
    if len(pw_posix) >= 2 and pw_posix[1] == ":":
        drive = pw_posix[0].lower()
        rest = pw_posix[2:]
        if not rest.startswith("/"):
            rest = "/" + rest
        return f"/mnt/{drive}{rest}"
    return pw_posix


_wsl_snort_probed: bool | None = None


def _wsl_snort_available(distro: str, bin_name: str) -> bool:
    """Cached one-shot probe: does ``wsl -d <distro> -- which <bin>`` succeed?"""
    global _wsl_snort_probed
    if _wsl_snort_probed is not None:
        return _wsl_snort_probed
    try:
        result = subprocess.run(
            ["wsl.exe", "-d", distro, "--", "which", bin_name],
            capture_output=True, text=True, timeout=10, check=False,
        )
        _wsl_snort_probed = result.returncode == 0 and bool(result.stdout.strip())
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("snort_offline: WSL probe failed — %s", exc)
        _wsl_snort_probed = False
    return _wsl_snort_probed


def is_available() -> bool:
    """True iff a usable Snort binary + config are configured.

    Two modes are supported:

    * **Native** — ``SNORT_BIN`` is a path that exists on the host running
      Python (Linux deploy, or Snort-on-Windows).
    * **WSL bridge** — ``SNORT_WSL_DISTRO`` is set; Snort runs inside that
      distro. We probe with ``wsl -d <distro> -- which snort`` once and
      cache the result.

    In both modes ``SNORT_CONFIG`` must be a path the Snort binary can read
    (a WSL-style path in WSL mode).
    """
    bin_path = os.getenv("SNORT_BIN")
    cfg_path = os.getenv("SNORT_CONFIG")
    if not bin_path or not cfg_path:
        return False

    distro = os.getenv("SNORT_WSL_DISTRO")
    if distro:
        # In WSL mode we cannot Path.exists() a Linux path from Windows.
        # Probe the binary's PATH-resolvability inside the distro instead.
        return _wsl_snort_available(distro, bin_path)

    # Native mode — both paths must exist on the host. `SNORT_BIN` may be
    # a bare name (e.g. "snort") to be resolved against $PATH, or an
    # absolute path. subprocess.run() already resolves names against $PATH
    # on the run path, so we mirror that here for the availability check.
    if os.path.isabs(bin_path):
        if not Path(bin_path).exists():
            return False
    else:
        if shutil.which(bin_path) is None:
            return False
    if not Path(cfg_path).exists():
        return False
    return True


def run(pcap_path: str) -> dict[str, dict[str, Any]]:
    """Replay *pcap_path* through Snort 3 offline and return alerts by flow key.

    Returns an empty dict (and logs) if Snort is unavailable, the PCAP is
    missing, or the subprocess fails.  Callers should treat that as
    "no signature hits" rather than a hard error.
    """
    if not is_available():
        log.info("Snort offline disabled (SNORT_BIN/SNORT_CONFIG not set).")
        return {}

    if not Path(pcap_path).exists():
        log.warning("snort_offline: PCAP not found at %s", pcap_path)
        return {}

    bin_path = os.environ["SNORT_BIN"]
    cfg_path = os.environ["SNORT_CONFIG"]
    timeout = int(os.getenv("SNORT_OFFLINE_TIMEOUT", "300"))
    distro = os.getenv("SNORT_WSL_DISTRO")
    daq_dir = os.getenv("SNORT_DAQ_DIR")

    # In WSL mode the temp dir must live somewhere both sides can write
    # cheaply. /mnt/c/.../Temp/ works but is very slow over the WSL2 9P
    # bridge. Use the project-local .tmp dir (already gitignored, already
    # used for the tailer log). Resolve to absolute so the path is the
    # same regardless of the caller's cwd.
    if distro:
        env_root = os.getenv("SNORT_OFFLINE_TMP")
        if env_root:
            tmp_root = Path(env_root)
        else:
            # Locate project root via this file's location: app/core/snort_offline.py
            project_root = Path(__file__).resolve().parent.parent.parent
            tmp_root = project_root / ".tmp" / "snort" / "offline"
        tmp_root.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="run_", dir=str(tmp_root)))
    else:
        work = Path(tempfile.mkdtemp(prefix="snort_offline_"))
    try:
        if distro:
            # WSL bridge: prefix with wsl.exe and translate Windows paths
            # to /mnt/<drive>/... so the snort process (running in WSL) can
            # read them. cfg_path is assumed to already be a WSL path.
            cmd = [
                "wsl.exe", "-d", distro, "--",
                bin_path,
            ]
            if daq_dir:
                cmd += ["--daq-dir", daq_dir]
            cmd += [
                "-c", _to_wsl_path(cfg_path),
                "-r", _to_wsl_path(pcap_path),
                "-A", "alert_json",
                "-l", _to_wsl_path(str(work)),
                "-q",
            ]
        else:
            cmd = [bin_path]
            if daq_dir:
                cmd += ["--daq-dir", daq_dir]
            cmd += [
                "-c", cfg_path,
                "-r", pcap_path,
                "-A", "alert_json",
                "-l", str(work),
                "-q",
            ]
        log.info("snort_offline: running %s", " ".join(cmd))
        try:
            subprocess.run(cmd, check=False, timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.TimeoutExpired:
            log.warning("snort_offline: timeout after %ss replaying %s", timeout, pcap_path)
            return {}

        alerts: dict[str, dict[str, Any]] = {}
        for alert_file in work.glob("alert_json*"):
            try:
                with open(alert_file, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        payload = _parse_alert_line(line)
                        if payload is None:
                            continue
                        alerts.setdefault(payload["flow_key"], payload)
            except OSError as exc:
                log.warning("snort_offline: cannot read %s — %s", alert_file, exc)

        log.info("snort_offline: %d unique alert flows from %s", len(alerts), pcap_path)
        return alerts

    finally:
        shutil.rmtree(work, ignore_errors=True)
