#!/usr/bin/env bash
# On-box deploy — pull prebuilt GHCR images and (re)start the FULL stack,
# including the live-capture tier (host-IDS mode). Invoked by the SSM Run
# Command in .github/workflows/deploy.yml after `git pull`, and usable by
# hand for a manual GHCR deploy (Docs/AWS_DEPLOYMENT.md §8).
#
# Brings up, in one shot:
#   default profile : postgres, redis, api, dashboard
#   tls profile     : caddy (HTTPS)
#   capture profile : flow_meter, snort_live, snort_tailer (live capture)
#
# Run from the repo root on the box:
#   IMAGE_TAG=latest bash app/scripts/deploy_on_box.sh
#
# Disable the always-on live capture by exporting CAPTURE=0 before running
# (the site + PCAP replay still work; only the host-IDS sidecars are skipped).

set -euo pipefail

IMAGE_TAG="${IMAGE_TAG:-latest}"
CAPTURE="${CAPTURE:-1}"
export IMAGE_TAG

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.deploy.yml)
PROFILES=(--profile tls)

if [ "$CAPTURE" = "1" ]; then
  PROFILES+=(--profile capture)
  # Detect the primary NIC for flow_meter + snort_live. On Nitro EC2 this is
  # ens5/enX0, NOT eth0 — a wrong value crash-loops those two sidecars (the
  # rest of the stack is unaffected; they carry restart: unless-stopped).
  if [ -z "${CAPTURE_INTERFACE:-}" ]; then
    CAPTURE_INTERFACE="$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)"
  fi
  export CAPTURE_INTERFACE
  mkdir -p snort_logs
  echo "[deploy_on_box] capture ON — interface=${CAPTURE_INTERFACE:-<unresolved>}"
else
  echo "[deploy_on_box] capture OFF (CAPTURE=0) — live host-IDS sidecars skipped"
fi

echo "[deploy_on_box] image tag=${IMAGE_TAG}; profiles=${PROFILES[*]}"

"${COMPOSE[@]}" "${PROFILES[@]}" pull
"${COMPOSE[@]}" "${PROFILES[@]}" up -d
docker image prune -f

echo "[deploy_on_box] up. Running services:"
"${COMPOSE[@]}" "${PROFILES[@]}" ps
