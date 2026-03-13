"""
Live packet capture using scapy's AsyncSniffer.

Captures raw packets, aggregates them into bidirectional flows via FlowTable,
and pushes completed flows to an asyncio queue for ML classification.
"""
import asyncio
import sys
import socket
import threading
import time
from typing import Optional

from app.core.flow_aggregator import FlowTable


def check_pcap_available() -> bool:
    try:
        from scapy.all import conf  # noqa: F401
        if sys.platform == "win32":
            return conf.use_npcap or conf.use_pcap
        return True
    except (ImportError, OSError):
        return False


def get_pcap_install_hint() -> str:
    if sys.platform == "win32":
        return (
            "Npcap is required for live capture on Windows.\n"
            "Download from https://npcap.com/#download\n"
            "During install, check 'Install Npcap in WinPcap API-compatible Mode'."
        )
    return "libpcap is required. Install via: sudo apt install libpcap-dev"


def list_interfaces() -> list[dict]:
    """Return available network interfaces, preferring real physical NICs."""
    import psutil
    results = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    # Skip virtual/link-local adapters that can't see real internet traffic
    SKIP_PREFIXES = ("loopback", "bluetooth", "local area connection")

    for name, addr_list in addrs.items():
        stat = stats.get(name)
        if not stat or not stat.isup:
            continue
        if name.lower().startswith(tuple(SKIP_PREFIXES)):
            continue

        ipv4 = next((a.address for a in addr_list if a.family == socket.AF_INET), None)
        if not ipv4 or ipv4 == "127.0.0.1" or ipv4.startswith("169.254."):
            continue

        is_virtual = "virtual" in name.lower() or "vethernet" in name.lower()
        results.append({
            "name": name,
            "description": f"{name} ({ipv4})",
            "is_up": True,
            "speed": stat.speed,
            "ipv4": ipv4,
            "is_virtual": is_virtual,
        })

    # Physical NICs first, then by speed
    results.sort(key=lambda i: (i["is_virtual"], -i["speed"]))
    return results


def _resolve_iface(friendly_name: str):
    """
    On Windows, map a psutil-style name to the scapy interface object.
    Scapy on Windows expects either the GUID or the dev_name.
    On Linux, return as-is.
    """
    if sys.platform != "win32":
        return friendly_name

    try:
        from scapy.config import conf as scapy_conf
        for iface_obj in scapy_conf.ifaces.values():
            if getattr(iface_obj, "name", "") == friendly_name:
                return iface_obj
            if getattr(iface_obj, "description", "") == friendly_name:
                return iface_obj
    except Exception:
        pass
    return friendly_name


def _detect_default_interface() -> Optional[str]:
    candidates = list_interfaces()
    if not candidates:
        return None
    return candidates[0]["name"]


class CaptureManager:
    """Manages live packet capture via scapy in a background thread."""

    IDLE_TIMEOUT = 2.0
    ACTIVE_TIMEOUT = 30.0
    SWEEP_INTERVAL = 1.0

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        self._queue: asyncio.Queue[Optional[dict]] = asyncio.Queue()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._interface: Optional[str] = None
        self._interface_display: Optional[str] = None
        self._packet_count = 0
        self._sniffer = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def interface(self) -> Optional[str]:
        return self._interface_display

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def queue(self) -> asyncio.Queue:
        return self._queue

    def start(self, interface: Optional[str] = None):
        if self._running:
            raise RuntimeError("Capture is already running")

        if not check_pcap_available():
            raise RuntimeError(get_pcap_install_hint())

        friendly = interface or _detect_default_interface()
        if not friendly:
            raise RuntimeError("No active network interface found")

        self._interface_display = friendly
        self._interface = _resolve_iface(friendly)
        self._running = True
        self._packet_count = 0

        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        self._thread = threading.Thread(
            target=self._capture_loop,
            name="scapy-capture",
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._thread = None

    def _emit_flow(self, flow_dict: dict):
        self._packet_count += 1
        asyncio.run_coroutine_threadsafe(
            self._queue.put(flow_dict), self._loop
        )

    def _capture_loop(self):
        from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP

        flow_table = FlowTable(
            idle_timeout=self.IDLE_TIMEOUT,
            active_timeout=self.ACTIVE_TIMEOUT,
        )

        def process_packet(pkt):
            if not self._running:
                return

            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                return

            src_ip = ip.src
            dst_ip = ip.dst
            proto = ip.proto if hasattr(ip, "proto") else (6 if pkt.haslayer(TCP) else 17 if pkt.haslayer(UDP) else 0)
            ttl = getattr(ip, "ttl", getattr(ip, "hlim", 64))
            length = len(pkt)

            sport, dport, tcp_flags, tcp_seq, tcp_win = 0, 0, 0, 0, 0

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                sport, dport = tcp.sport, tcp.dport
                tcp_flags = int(tcp.flags)
                tcp_seq = tcp.seq
                tcp_win = tcp.window
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                sport, dport = udp.sport, udp.dport

            pkt_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "sport": sport,
                "dport": dport,
                "proto": proto,
                "length": length,
                "ttl": ttl,
                "tcp_flags": tcp_flags,
                "tcp_seq": tcp_seq,
                "tcp_win": tcp_win,
                "time": float(pkt.time),
            }

            completed = flow_table.ingest(pkt_info)
            if completed:
                self._emit_flow(completed)

        try:
            iface = self._interface
            print(f"[CaptureManager] Starting scapy capture on: {iface}")

            self._sniffer = AsyncSniffer(
                iface=iface,
                prn=process_packet,
                store=False,
                filter="ip or ip6",
            )
            self._sniffer.start()

            while self._running:
                time.sleep(self.SWEEP_INTERVAL)
                expired = flow_table.sweep_expired()
                for flow_dict in expired:
                    self._emit_flow(flow_dict)

            # Flush remaining flows
            for flow_dict in flow_table.flush_all():
                self._emit_flow(flow_dict)

        except Exception as exc:
            asyncio.run_coroutine_threadsafe(
                self._queue.put(None), self._loop
            )
            print(f"[CaptureManager] Capture error: {exc}")
        finally:
            self._running = False
            if self._sniffer:
                try:
                    self._sniffer.stop()
                except Exception:
                    pass
                self._sniffer = None
