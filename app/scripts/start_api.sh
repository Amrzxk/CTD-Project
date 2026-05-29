#!/bin/sh
# Container entrypoint for the FastAPI tier.
#
# 1. Apply any pending DB migrations. Safe to run concurrently across
#    multiple API replicas — Postgres' DDL locks serialize the work and
#    Alembic's version table prevents double application.
# 2. Hand off to gunicorn with uvicorn workers. Worker count comes from
#    API_WORKERS (default 4) so the same image scales by env var.
#
# `set -e` makes any failed step abort the boot — we don't want gunicorn
# starting against an un-migrated schema.

set -e

echo "[start_api] applying migrations…"
alembic upgrade head

WORKERS="${API_WORKERS:-4}"
# Worker timeout needs to cover large PCAP uploads: NFStream feature
# extraction + ML inference + Snort offline replay on a 400+ MB PCAP
# takes well over the default 30s. 600s gives comfortable headroom
# without hiding genuinely stuck workers.
TIMEOUT="${API_WORKER_TIMEOUT:-600}"
echo "[start_api] launching gunicorn (workers=${WORKERS}, timeout=${TIMEOUT}s)"
exec gunicorn app.main:app \
  -k uvicorn.workers.UvicornWorker \
  -w "${WORKERS}" \
  --timeout "${TIMEOUT}" \
  -b 0.0.0.0:8000 \
  --access-logfile - \
  --error-logfile -
