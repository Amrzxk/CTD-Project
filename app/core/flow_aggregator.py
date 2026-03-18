"""
Aggregates raw packets into bidirectional network flows with features
matching the UNSW-NB15 dataset schema the ML model expects.
"""
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


WELL_KNOWN_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
    143: "imap", 443: "ssl", 993: "ssl", 995: "ssl", 8080: "http",
    3306: "mysql", 5432: "postgres", 6379: "redis", 1900: "ssdp",
    5353: "mdns", 123: "ntp", 161: "snmp", 389: "ldap", 636: "ssl",
}

PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp"}


@dataclass
class FlowState:
    """Mutable state for a single bidirectional flow being tracked."""
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    proto: int

    start_time: float = 0.0
    last_time: float = 0.0

    sbytes: int = 0
    dbytes: int = 0
    spkts: int = 0
    dpkts: int = 0

    sttl: int = 0
    dttl: int = 0

    swin: int = 0
    dwin: int = 0
    stcpb: int = 0
    dtcpb: int = 0

    # TCP handshake timing
    syn_time: float = 0.0
    synack_time: float = 0.0
    ack_time: float = 0.0

    # TCP flags seen
    src_flags: int = 0
    dst_flags: int = 0

    # Packet inter-arrival times
    _src_times: list = field(default_factory=list)
    _dst_times: list = field(default_factory=list)

    # Packet sizes for mean calculation
    _src_sizes: list = field(default_factory=list)
    _dst_sizes: list = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(self.last_time - self.start_time, 0.0)

    @property
    def service(self) -> str:
        for port in (self.dport, self.sport):
            if port in WELL_KNOWN_PORTS:
                return WELL_KNOWN_PORTS[port]
        return "-"

    def to_model_dict(self) -> dict:
        """Export flow as a dict with keys matching the model's feature names."""
        dur = self.duration

        sload = (self.sbytes * 8 / dur) if dur > 0 else 0.0
        dload = (self.dbytes * 8 / dur) if dur > 0 else 0.0
        smeansz = (self.sbytes / self.spkts) if self.spkts > 0 else 0.0
        dmeansz = (self.dbytes / self.dpkts) if self.dpkts > 0 else 0.0

        synack = (self.synack_time - self.syn_time) if self.syn_time and self.synack_time else 0.0
        ackdat = (self.ack_time - self.synack_time) if self.synack_time and self.ack_time else 0.0
        tcprtt = synack + ackdat

        sintpkt = _mean_interarrival(self._src_times)
        dintpkt = _mean_interarrival(self._dst_times)
        sjit = _jitter(self._src_times)
        djit = _jitter(self._dst_times)

        state = self._derive_state()
        is_sm = 1 if (self.src_ip == self.dst_ip and self.sport == self.dport) else 0

        return {
            "srcip": self.src_ip,
            "dstip": self.dst_ip,
            "sport": self.sport,
            "dsport": self.dport,
            "proto": PROTO_MAP.get(self.proto, "others"),
            "state": state,
            "dur": round(dur, 6),
            "sbytes": self.sbytes,
            "dbytes": self.dbytes,
            "sttl": self.sttl,
            "dttl": self.dttl,
            "service": self.service,
            "sload": round(sload, 4),
            "dload": round(dload, 4),
            "spkts": self.spkts,
            "dpkts": self.dpkts,
            "swin": self.swin,
            "dwin": self.dwin,
            "stcpb": self.stcpb,
            "dtcpb": self.dtcpb,
            "smeansz": round(smeansz, 4),
            "dmeansz": round(dmeansz, 4),
            "trans_depth": 0,
            "res_bdy_len": 0,
            "sjit": round(sjit, 6),
            "djit": round(djit, 6),
            "sintpkt": round(sintpkt, 6),
            "dintpkt": round(dintpkt, 6),
            "tcprtt": round(tcprtt, 6),
            "synack": round(synack, 6),
            "ackdat": round(ackdat, 6),
            "is_sm_ips_ports": is_sm,
        }

    def _derive_state(self) -> str:
        if self.proto != 6:
            return "CON"

        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        ACK = 0x10

        sf, df = self.src_flags, self.dst_flags

        if (sf & RST) or (df & RST):
            return "RST"
        if (sf & FIN) and (df & FIN):
            return "FIN"
        if (sf & SYN) and (df & SYN) and (df & ACK):
            return "CON"
        if (sf & SYN) and not (df & SYN):
            return "REQ"
        return "CON"


def _mean_interarrival(times: list) -> float:
    if len(times) < 2:
        return 0.0
    diffs = [times[i] - times[i - 1] for i in range(1, len(times))]
    return (sum(diffs) / len(diffs)) * 1000  # ms

def _jitter(times: list) -> float:
    if len(times) < 3:
        return 0.0
    diffs = [times[i] - times[i - 1] for i in range(1, len(times))]
    jitters = [abs(diffs[i] - diffs[i - 1]) for i in range(1, len(diffs))]
    return (sum(jitters) / len(jitters)) * 1000 if jitters else 0.0  # ms


class FlowTable:
    """
    Tracks active flows and emits completed ones.

    A flow is identified by the 5-tuple (src_ip, dst_ip, sport, dport, proto),
    normalised so that both directions map to the same entry.
    """

    def __init__(self, idle_timeout: float = 2.0, active_timeout: float = 30.0):
        self._flows: dict[tuple, FlowState] = {}
        self._idle_timeout = idle_timeout
        self._active_timeout = active_timeout

    def _make_key(self, src_ip: str, dst_ip: str, sport: int, dport: int, proto: int):
        """Normalise the 5-tuple so both directions share a key."""
        forward = (src_ip, dst_ip, sport, dport, proto)
        reverse = (dst_ip, src_ip, dport, sport, proto)
        return min(forward, reverse)

    def ingest(self, pkt_info: dict) -> Optional[dict]:
        """
        Add a packet to the flow table. Returns a completed flow dict
        if a TCP FIN/RST closes the connection, else None.
        """
        src_ip = pkt_info["src_ip"]
        dst_ip = pkt_info["dst_ip"]
        sport = pkt_info["sport"]
        dport = pkt_info["dport"]
        proto = pkt_info["proto"]
        length = pkt_info["length"]
        ttl = pkt_info["ttl"]
        tcp_flags = pkt_info.get("tcp_flags", 0)
        tcp_seq = pkt_info.get("tcp_seq", 0)
        tcp_win = pkt_info.get("tcp_win", 0)
        ts = pkt_info["time"]

        key = self._make_key(src_ip, dst_ip, sport, dport, proto)
        is_forward = (key == (src_ip, dst_ip, sport, dport, proto))

        flow = self._flows.get(key)
        if flow is None:
            flow = FlowState(
                src_ip=key[0], dst_ip=key[1],
                sport=key[2], dport=key[3], proto=proto,
                start_time=ts, last_time=ts,
            )
            self._flows[key] = flow

        flow.last_time = ts

        if is_forward:
            flow.sbytes += length
            flow.spkts += 1
            flow.sttl = ttl
            flow._src_times.append(ts)
            flow._src_sizes.append(length)
            flow.src_flags |= tcp_flags
            if tcp_win and not flow.swin:
                flow.swin = tcp_win
            if tcp_seq and not flow.stcpb:
                flow.stcpb = tcp_seq
        else:
            flow.dbytes += length
            flow.dpkts += 1
            flow.dttl = ttl
            flow._dst_times.append(ts)
            flow._dst_sizes.append(length)
            flow.dst_flags |= tcp_flags
            if tcp_win and not flow.dwin:
                flow.dwin = tcp_win
            if tcp_seq and not flow.dtcpb:
                flow.dtcpb = tcp_seq

        # Track TCP handshake times
        SYN, ACK = 0x02, 0x10
        if proto == 6:
            if (tcp_flags & SYN) and not (tcp_flags & ACK) and not flow.syn_time:
                flow.syn_time = ts
            elif (tcp_flags & SYN) and (tcp_flags & ACK) and not flow.synack_time:
                flow.synack_time = ts
            elif (tcp_flags & ACK) and not (tcp_flags & SYN) and flow.synack_time and not flow.ack_time:
                flow.ack_time = ts

        # Emit on FIN or RST
        FIN, RST = 0x01, 0x04
        if proto == 6 and (tcp_flags & (FIN | RST)):
            completed = flow.to_model_dict()
            del self._flows[key]
            return completed

        return None

    def sweep_expired(self) -> list[dict]:
        """Check for idle/active-timed-out flows and return them."""
        now = time.time()
        expired = []
        to_delete = []

        for key, flow in self._flows.items():
            idle = now - flow.last_time
            active = now - flow.start_time
            if idle >= self._idle_timeout or active >= self._active_timeout:
                expired.append(flow.to_model_dict())
                to_delete.append(key)

        for key in to_delete:
            del self._flows[key]

        return expired

    def flush_all(self) -> list[dict]:
        """Emit all active flows (used on capture stop)."""
        results = [f.to_model_dict() for f in self._flows.values()]
        self._flows.clear()
        return results
