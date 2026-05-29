"""
Shared utilities for constructing canonical flow keys.

Every component that reads or writes per-flow data in Redis MUST use
``flow_key()`` so that the flow-meter worker, Snort tailer, and the
FastAPI SSE layer all reference the exact same Redis hash.

Key format:  ``<src_ip>:<src_port>-<dst_ip>:<dst_port>-<PROTO>``
Example:     ``192.168.1.5:443-10.0.0.2:54321-TCP``
"""

_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: int | str,
) -> str:
    """Return the canonical Redis key for a network flow.

    Parameters
    ----------
    src_ip : str
        Source IP address.
    dst_ip : str
        Destination IP address.
    src_port : int
        Source port number.
    dst_port : int
        Destination port number.
    protocol : int | str
        Protocol number (6, 17, 1) **or** string name ("TCP", "UDP").

    Returns
    -------
    str
        Deterministic key string, e.g. ``192.168.1.5:443-10.0.0.2:54321-TCP``.
    """
    if isinstance(protocol, int):
        proto_str = _PROTO_NAMES.get(protocol, str(protocol))
    else:
        proto_str = protocol.upper()
    return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto_str}"
