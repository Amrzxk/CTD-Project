"""
Extract a large multi-attack sample from the CIC-IDS 2017 Wednesday PCAP.

This script targets the known Wednesday attack windows and writes a standard
PCAP that can be uploaded through the dashboard batch-analysis flow.

Why this script exists:
- `extract_attack_sample.py` grabs packets by packet offset, which is quick but
  does not guarantee that the selected packets cover the known attack windows.
- This script selects packets by timestamp, keeps the original packet timing,
  and caps each attack window so the output is not dominated by only one very
  large DoS burst.

Default output target is about 2 GiB.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


INPUT = Path(r"F:\GradProject\Testing\pcap\Wednesday-workingHours.8FLhsdtM.pcap.part")
OUTPUT = Path(r"F:\GradProject\Testing\pcap\test_wednesday_multi_attack_2gb.pcap")

# CIC-IDS 2017 Wednesday attack schedule, dataset local time.
# July in New Brunswick, Canada is Atlantic Daylight Time (UTC-3).
ATTACK_TIMEZONE = timezone(timedelta(hours=-3))
ATTACK_DATE = "2017-07-05"

TARGET_GIB = 2.0


@dataclass(frozen=True)
class AttackWindow:
    name: str
    start: str
    end: str
    quota_mib: int


ATTACK_WINDOWS = [
    AttackWindow("DoS Slowloris", "09:47:00", "10:10:00", 250),
    AttackWindow("DoS SlowHTTPTest", "10:14:00", "10:35:00", 250),
    AttackWindow("DoS Hulk", "10:43:00", "11:00:00", 700),
    AttackWindow("DoS GoldenEye", "11:10:00", "11:23:00", 300),
    AttackWindow("Heartbleed", "15:12:00", "15:32:00", 548),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract a timestamp-based CIC-IDS Wednesday multi-attack PCAP sample."
    )
    parser.add_argument("--input", type=Path, default=INPUT, help="Source PCAP/PCAPNG path.")
    parser.add_argument("--output", type=Path, default=OUTPUT, help="Destination PCAP path.")
    parser.add_argument(
        "--target-gib",
        type=float,
        default=TARGET_GIB,
        help="Stop when output reaches this size, in GiB.",
    )
    parser.add_argument(
        "--timezone-offset",
        type=int,
        default=-3,
        help="Attack schedule timezone offset from UTC. CIC-IDS Wednesday defaults to -3.",
    )
    parser.add_argument(
        "--no-window-quotas",
        action="store_true",
        help="Disable per-window quotas and write matching packets until target size is reached.",
    )
    return parser.parse_args()


def build_epoch_windows(timezone_offset: int) -> list[dict]:
    tz = timezone(timedelta(hours=timezone_offset))
    windows = []

    for window in ATTACK_WINDOWS:
        start_dt = datetime.fromisoformat(f"{ATTACK_DATE}T{window.start}").replace(tzinfo=tz)
        end_dt = datetime.fromisoformat(f"{ATTACK_DATE}T{window.end}").replace(tzinfo=tz)
        windows.append(
            {
                "name": window.name,
                "start": start_dt.timestamp(),
                "end": end_dt.timestamp(),
                "quota_bytes": window.quota_mib * 1024 * 1024,
                "written_bytes": 0,
                "written_packets": 0,
                "start_dt": start_dt,
                "end_dt": end_dt,
            }
        )

    return windows


def find_window(packet_ts: float, windows: list[dict]) -> dict | None:
    for window in windows:
        if window["start"] <= packet_ts <= window["end"]:
            return window
    return None


def format_size(num_bytes: int) -> str:
    gib = num_bytes / (1024**3)
    mib = num_bytes / (1024**2)
    return f"{gib:.2f} GiB ({mib:.1f} MiB)"


def main() -> None:
    args = parse_args()

    if not args.input.exists():
        print(f"ERROR: Input file not found: {args.input}")
        sys.exit(1)

    args.output.parent.mkdir(parents=True, exist_ok=True)

    target_bytes = int(args.target_gib * (1024**3))
    windows = build_epoch_windows(args.timezone_offset)

    print(f"Input : {args.input} ({format_size(args.input.stat().st_size)})")
    print(f"Output: {args.output}")
    print(f"Target: {format_size(target_bytes)}")
    print(f"Window quotas: {'disabled' if args.no_window_quotas else 'enabled'}")
    print()
    print("Attack windows:")
    for window in windows:
        quota = "unlimited" if args.no_window_quotas else format_size(window["quota_bytes"])
        print(f"  - {window['name']}: {window['start_dt']} -> {window['end_dt']} | quota={quota}")
    print()

    try:
        import dpkt
        from scapy.utils import PcapNgReader
    except ImportError as exc:
        print(f"ERROR: Missing dependency: {exc}")
        print("Install with: pip install scapy dpkt")
        sys.exit(1)

    total_packets = 0
    written_packets = 0
    matched_packets = 0
    first_packet_ts: float | None = None
    last_packet_ts: float | None = None

    bad_packets = 0
    last_heartbeat = time.monotonic()
    HEARTBEAT_SEC = 15.0

    print("Scanning source PCAP and writing selected packets...", flush=True)
    with open(args.output, "wb") as output_file:
        writer = dpkt.pcap.Writer(output_file)
        reader = PcapNgReader(str(args.input))

        while True:
            now = time.monotonic()
            if now - last_heartbeat >= HEARTBEAT_SEC:
                last_heartbeat = now
                current_size = output_file.tell()
                print(
                    f"  ... heartbeat: good_packets={total_packets:,} bad_skips={bad_packets:,} "
                    f"matched={matched_packets:,} written={written_packets:,} "
                    f"size={format_size(current_size)}",
                    flush=True,
                )

            try:
                pkt = reader.read_packet()
                if pkt is None:
                    break
            except StopIteration:
                break
            except (KeyError, EOFError, Exception) as exc:
                bad_packets += 1
                if bad_packets <= 3:
                    print(f"  WARNING: skipped bad packet #{bad_packets}: {exc}", flush=True)
                elif bad_packets == 4:
                    print("  (suppressing further bad-packet detail; still counting skips)", flush=True)
                elif bad_packets % 250_000 == 0:
                    print(
                        f"  ... still skipping corrupt blocks: bad_skips={bad_packets:,} "
                        f"good_packets={total_packets:,} size={format_size(output_file.tell())}",
                        flush=True,
                    )
                continue

            total_packets += 1

            packet_ts = float(getattr(pkt, "time", 0.0) or 0.0)
            if first_packet_ts is None:
                first_packet_ts = packet_ts
            last_packet_ts = packet_ts

            if total_packets % 500_000 == 0:
                last_heartbeat = time.monotonic()
                current_size = output_file.tell()
                pkt_time_str = ""
                if packet_ts > 1e9:
                    pkt_time_str = f" pkt_time={datetime.fromtimestamp(packet_ts, tz=timezone.utc).strftime('%H:%M:%S')} UTC"
                print(
                    f"  scanned={total_packets:,} matched={matched_packets:,} "
                    f"written={written_packets:,} size={format_size(current_size)}"
                    f"{pkt_time_str} bad={bad_packets}",
                    flush=True,
                )

            window = find_window(packet_ts, windows)
            if window is None:
                continue

            matched_packets += 1
            raw = bytes(pkt)
            next_size = output_file.tell() + len(raw)

            if not args.no_window_quotas:
                if window["written_bytes"] + len(raw) > window["quota_bytes"]:
                    continue

            if next_size > target_bytes:
                break

            writer.writepkt(raw, ts=packet_ts)
            written_packets += 1
            window["written_packets"] += 1
            window["written_bytes"] += len(raw)

        reader.close()

    output_size = args.output.stat().st_size if args.output.exists() else 0

    print()
    print("Done.")
    print(f"Scanned packets : {total_packets:,}")
    print(f"Matched packets : {matched_packets:,}")
    print(f"Written packets : {written_packets:,}")
    print(f"Skipped (bad)   : {bad_packets:,}")
    print(f"Output size     : {format_size(output_size)}")

    if first_packet_ts is not None and last_packet_ts is not None:
        first_seen = datetime.fromtimestamp(first_packet_ts, tz=timezone.utc)
        last_seen = datetime.fromtimestamp(last_packet_ts, tz=timezone.utc)
        print(f"Source time span: {first_seen} -> {last_seen} (UTC)")

    print()
    print("Per-window output:")
    for window in windows:
        print(
            f"  - {window['name']}: {window['written_packets']:,} packets, "
            f"{format_size(window['written_bytes'])}"
        )

    if written_packets == 0:
        print()
        print("WARNING: No packets were written.")
        print("If the source time span looks shifted, rerun with a different --timezone-offset.")
        print("Examples: --timezone-offset 0, --timezone-offset -4, --timezone-offset 3")
        sys.exit(2)

    if output_size < target_bytes * 0.8:
        print()
        print("WARNING: Output is much smaller than the target.")
        print("Try --no-window-quotas to let high-volume windows fill the remaining size.")


if __name__ == "__main__":
    main()
