#!/usr/bin/env bash
# -------------------------------------------------------
#  start_workers.sh — Hybrid IDS process orchestrator
#
#  Starts all three background processes:
#    1. NFStream Flow Meter Worker
#    2. Snort Tailer Worker
#    3. FastAPI / Uvicorn API server
#
#  Usage:
#    chmod +x start_workers.sh
#    ./start_workers.sh            # foreground (dev)
#    ./start_workers.sh --daemon   # background (prod)
#
#  Environment:
#    All configuration comes from .env (auto-loaded by
#    each worker via python-dotenv).
#
#  Prerequisites:
#    - Redis must be running
#    - Snort 3 must be running and writing alert_json
#    - Python venv with requirements.txt installed
# -------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$SCRIPT_DIR/app"

# --- Defaults --------------------------------------------------------
DAEMON_MODE=false
UVICORN_HOST="${UVICORN_HOST:-0.0.0.0}"
UVICORN_PORT="${UVICORN_PORT:-8000}"

# --- Parse args ------------------------------------------------------
for arg in "$@"; do
    case $arg in
        --daemon) DAEMON_MODE=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# --- Helpers ---------------------------------------------------------
PIDS=()

cleanup() {
    echo ""
    echo "[orchestrator] Shutting down workers …"
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait
    echo "[orchestrator] All workers stopped."
}

trap cleanup EXIT INT TERM

start_worker() {
    local name="$1"
    shift
    echo "[orchestrator] Starting $name …"
    if $DAEMON_MODE; then
        "$@" &
    else
        "$@" &
    fi
    PIDS+=($!)
    echo "[orchestrator]   PID=${PIDS[-1]}"
}

# --- Start workers ---------------------------------------------------

# 1. Flow Meter Worker (NFStream → Redis)
start_worker "flow_meter_worker" \
    python -m app.core.flow_meter_worker

# 2. Snort Tailer Worker (Snort JSON log → Redis Pub/Sub)
start_worker "snort_tailer_worker" \
    python -m app.core.snort_tailer_worker

# 3. FastAPI / Uvicorn API server
start_worker "uvicorn" \
    uvicorn app.main:app \
        --host "$UVICORN_HOST" \
        --port "$UVICORN_PORT" \
        --reload

# --- Wait ------------------------------------------------------------
echo ""
echo "[orchestrator] All workers started. PIDs: ${PIDS[*]}"
echo "[orchestrator] Press Ctrl+C to stop all workers."
echo ""

wait
