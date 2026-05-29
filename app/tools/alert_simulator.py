"""
Alert Simulator — publishes fake Snort alerts to Redis using REAL flow keys.

This replaces the need for Snort during testing. It:
  1. Scans Redis for flow keys stored by the flow_meter_worker
  2. Picks random keys and publishes realistic Snort-style alerts
  3. The SSE endpoint picks them up, runs ML inference, and pushes to the UI

Usage:
    python -m app.tools.alert_simulator            # 10 alerts, 2s interval
    python -m app.tools.alert_simulator --count 50 --interval 1
    python -m app.tools.alert_simulator --continuous
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone

import redis

# Simulated Snort alert templates
SNORT_RULES = [
    {"sid": 2001219, "msg": "ET SCAN Potential SSH Scan", "classtype": "attempted-recon", "priority": 2},
    {"sid": 2002910, "msg": "ET SCAN Nmap Scripting Engine User-Agent", "classtype": "web-application-attack", "priority": 1},
    {"sid": 2013028, "msg": "ET POLICY curl User-Agent Outbound", "classtype": "policy-violation", "priority": 3},
    {"sid": 2024364, "msg": "ET DOS Excessive DNS Queries", "classtype": "attempted-dos", "priority": 1},
    {"sid": 2100498, "msg": "GPL ATTACK_RESPONSE id check returned root", "classtype": "bad-unknown", "priority": 2},
    {"sid": 2003068, "msg": "ET SCAN Potential FTP Brute-Force Attempt", "classtype": "attempted-recon", "priority": 2},
    {"sid": 2010935, "msg": "ET MALWARE Suspicious User-Agent", "classtype": "trojan-activity", "priority": 1},
    {"sid": 2016360, "msg": "ET INFO Possible SSL/TLS Downgrade Attack", "classtype": "attempted-admin", "priority": 1},
]


def get_flow_keys(r: redis.Redis) -> list[str]:
    """Get all flow keys from Redis (keys containing TCP/UDP/ICMP)."""
    keys = []
    for pattern in ["*TCP*", "*UDP*", "*ICMP*"]:
        keys.extend([k for k in r.keys(pattern) if r.type(k) == "hash"])
    return keys


def parse_flow_key(key: str) -> dict:
    """Parse a flow key like '192.168.10.16:53856-192.168.10.3:389-TCP'."""
    try:
        parts = key.rsplit("-", 1)
        protocol = parts[1]
        endpoints = parts[0].split("-")
        src_parts = endpoints[0].rsplit(":", 1)
        dst_parts = endpoints[1].rsplit(":", 1)
        return {
            "src_ip": src_parts[0],
            "src_port": int(src_parts[1]),
            "dst_ip": dst_parts[0],
            "dst_port": int(dst_parts[1]),
            "protocol": protocol,
        }
    except (IndexError, ValueError):
        return {}


def publish_alert(r: redis.Redis, flow_key: str):
    """Build and publish a fake Snort alert for the given flow key."""
    parsed = parse_flow_key(flow_key)
    if not parsed:
        return False

    rule = random.choice(SNORT_RULES)
    now = datetime.now(timezone.utc).isoformat()

    alert = {
        "timestamp": now,
        "src_ip": parsed["src_ip"],
        "src_port": parsed["src_port"],
        "dst_ip": parsed["dst_ip"],
        "dst_port": parsed["dst_port"],
        "protocol": parsed["protocol"],
        "snort_msg": rule["msg"],
        "snort_sid": rule["sid"],
        "snort_classtype": rule["classtype"],
        "snort_priority": rule["priority"],
        "snort_action": "alert",
        "snort_timestamp": now,
        "flow_key": flow_key,
    }

    subscribers = r.publish("snort_alerts", json.dumps(alert))
    return subscribers > 0


def main():
    parser = argparse.ArgumentParser(description="Simulate Snort alerts using real Redis flow keys")
    parser.add_argument("--host", default="127.0.0.1", help="Redis host")
    parser.add_argument("--port", type=int, default=6379, help="Redis port")
    parser.add_argument("--count", type=int, default=10, help="Number of alerts to send")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between alerts")
    parser.add_argument("--continuous", action="store_true", help="Run forever until Ctrl+C")
    args = parser.parse_args()

    r = redis.Redis(host=args.host, port=args.port, decode_responses=True)

    try:
        r.ping()
    except redis.ConnectionError:
        print("ERROR: Cannot connect to Redis. Is it running?", flush=True)
        sys.exit(1)

    print(f"Connected to Redis at {args.host}:{args.port}", flush=True)
    print("Scanning for flow keys...", flush=True)

    flow_keys = get_flow_keys(r)
    if not flow_keys:
        print("ERROR: No flow keys found in Redis!", flush=True)
        print("Make sure the flow_meter_worker is running first.", flush=True)
        sys.exit(1)

    print(f"Found {len(flow_keys)} flow keys", flush=True)
    mode = "continuous" if args.continuous else f"{args.count} alerts"
    print(f"Mode: {mode}, interval: {args.interval}s", flush=True)
    print("-" * 50, flush=True)

    # Wait briefly for an SSE subscriber (dashboard must be open)
    print("Waiting for SSE subscriber (up to 30s)...", flush=True)
    waited = 0
    while waited < 30:
        subs = r.publish("snort_alerts", '{"ping": true}')
        if subs > 0:
            print(f"  SSE subscriber detected ({subs} listeners)", flush=True)
            break
        time.sleep(1)
        waited += 1
    else:
        print("  No subscriber yet — publishing anyway (events queue until dashboard connects)", flush=True)
    print("Starting alert simulation!\n", flush=True)

    sent = 0
    try:
        while True:
            # Refresh keys periodically (flows expire with TTL)
            if sent % 10 == 0:
                fresh_keys = get_flow_keys(r)
                if fresh_keys:
                    flow_keys = fresh_keys

            if not flow_keys:
                print("  Waiting for flow keys...", flush=True)
                time.sleep(args.interval)
                continue

            key = random.choice(flow_keys)
            delivered = publish_alert(r, key)

            sent += 1
            status = "✓ delivered" if delivered else "✗ no subscribers"
            parsed = parse_flow_key(key)
            print(f"  [{sent:>4}] {parsed.get('src_ip', '?')}:{parsed.get('src_port', '?')} -> "
                  f"{parsed.get('dst_ip', '?')}:{parsed.get('dst_port', '?')} "
                  f"({parsed.get('protocol', '?')}) -- {status}", flush=True)

            if not args.continuous and sent >= args.count:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\nStopped. Total alerts sent: {sent}", flush=True)

    print(f"Done. {sent} alerts published.", flush=True)


if __name__ == "__main__":
    main()
