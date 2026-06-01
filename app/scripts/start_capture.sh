#!/usr/bin/env bash
# Bring up the on-box live-capture tier (host-IDS mode) on the deployment host.
#
# This starts three `capture`-profile sidecars alongside the already-running
# stack so the dashboard's Live tab works in ML / Snort / Hybrid mode against
# traffic addressed to THIS box (real internet scans on public ports, plus any
# controlled attack you launch at the public IP):
#
#   flow_meter   — NFStream live capture  → Redis  (ML path)
#   snort_live   — Snort 3 live sensor    → alert_json.txt
#   snort_tailer — tails alert_json.txt   → Redis  (signature path)
#
# It does NOT see other machines' traffic — that needs VPC Traffic Mirroring.
#
# Prereqs:
#   * The main stack is already up: `docker compose up -d` (or the §9 TLS path).
#   * The api image is built so snort_live can reuse it:
#       docker compose build api      # produces hids-api:local
#
# Usage:
#   bash app/scripts/start_capture.sh           # auto-detect primary NIC
#   CAPTURE_INTERFACE=ens5 bash app/scripts/start_capture.sh   # force it
#
# Run from the repo root (where docker-compose.yml lives).

set -euo pipefail

# --- 1. Detect the primary interface ---------------------------------------
# On Nitro EC2 (t3/c7i-flex/…) this is ens5/enX0, NOT eth0. The default route's
# device is the NIC that sees traffic to/from the box.
if [ -z "${CAPTURE_INTERFACE:-}" ]; then
  CAPTURE_INTERFACE="$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)"
fi

if [ -z "${CAPTURE_INTERFACE:-}" ]; then
  echo "[start_capture] ERROR: could not auto-detect the primary interface." >&2
  echo "                Set it explicitly, e.g. CAPTURE_INTERFACE=ens5 $0" >&2
  exit 1
fi
export CAPTURE_INTERFACE

# --- 2. Ensure the shared Snort log dir exists -----------------------------
SNORT_LOG_DIR="${SNORT_LOG_DIR:-./snort_logs}"
mkdir -p "$SNORT_LOG_DIR"
export SNORT_LOG_DIR

echo "[start_capture] primary interface : ${CAPTURE_INTERFACE}"
echo "[start_capture] snort log dir      : ${SNORT_LOG_DIR}"

# --- 3. Bring up the capture tier ------------------------------------------
echo "[start_capture] starting flow_meter + snort_live + snort_tailer …"
docker compose --profile capture up -d flow_meter snort_live snort_tailer

echo
echo "[start_capture] done. Capture sidecars:"
docker compose --profile capture ps flow_meter snort_live snort_tailer
echo
echo "Next: open the dashboard → Live → source 'Interface', pick a mode"
echo "      (ML / Snort / Hybrid), and Start. Toggle 'persist to alerts' on"
echo "      if you want detections to land in the Alerts queue."
echo
echo "Stop capture with:"
echo "      docker compose --profile capture stop flow_meter snort_live snort_tailer"
