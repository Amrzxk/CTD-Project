from datetime import datetime
from pydantic import BaseModel, Field
from typing import List, Literal, Optional


class AckRequest(BaseModel):
    """Body for POST /predictions/{id}/ack.

    `state` flips the prediction's ack_state. `note` is a free-text analyst
    annotation captured at acknowledgement time.
    """
    state: Literal["new", "reviewed", "escalated", "dismissed"]
    note: Optional[str] = None


class BulkAckRequest(BaseModel):
    """Body for POST /predictions/ack/bulk.

    Applies one ack state + optional note to many ids in a single backend
    pass over predictions_store. Response is {updated, missing[]}.
    """
    ids: List[str]
    state: Literal["new", "reviewed", "escalated", "dismissed"]
    note: Optional[str] = None


class SuppressionRequest(BaseModel):
    """Body for POST /suppressions.

    A suppression *enforces* — matched flows are dropped before they reach
    predictions_store (not just labelled). `expires_at` is an ISO-8601
    timestamp; null means "until manually removed".
    """
    kind: Literal["sid", "src_ip", "src_cidr", "flow_key"]
    value: str
    expires_at: Optional[str] = None
    note: Optional[str] = None


class ManualFlowInput(BaseModel):
    # Categorical
    proto: Optional[str] = Field("tcp", description="Protocol (e.g., tcp, udp)")
    service: Optional[str] = Field("-", description="Service (e.g., http, dns, -)")
    
    # Basic Flow
    sport: Optional[int] = Field(0, description="Source Port")
    dsport: Optional[int] = Field(0, description="Destination Port")
    dur: Optional[float] = Field(0.0, description="Duration (seconds)")
    
    # Bytes & Packets
    sbytes: Optional[int] = Field(0, description="Source Bytes")
    dbytes: Optional[int] = Field(0, description="Destination Bytes")
    spkts: Optional[int] = Field(0, description="Source Packets")
    dpkts: Optional[int] = Field(0, description="Destination Packets")
    
    # TTL
    sttl: Optional[int] = Field(0, description="Source TTL")
    dttl: Optional[int] = Field(0, description="Destination TTL")
    
    # IPs (Used for malicious check / identity, not passed to model directly)
    srcip: Optional[str] = Field(None, description="Source IP Address")
    dstip: Optional[str] = Field(None, description="Destination IP Address")


class StartSessionRequest(BaseModel):
    """Body for POST /live/session.

    Creates a live session. ``source="interface"`` consumes the global
    flow_meter + snort_tailer streams. ``source="pcap"`` waits for a
    subsequent multipart upload to ``/live/session/{id}/pcap`` to begin
    replay. ``detection_mode`` is enforced server-side in the SSE filter.
    """

    source: Literal["interface", "pcap"]
    detection_mode: Literal["ml", "snort", "hybrid"] = "hybrid"
    speed: Optional[float] = Field(
        None,
        description="Replay speed for pcap mode (0 = max, 1 = wall-clock, "
                    "2/10 = faster). Ignored for interface mode.",
    )
    persist_to_alerts: Optional[bool] = Field(
        None,
        description=(
            "Persist live events to the Alerts queue (Postgres). "
            "Defaults: pcap=True (analysts expect to triage replay results), "
            "interface=False (a busy NIC would flood the DB)."
        ),
    )


class LiveSessionOut(BaseModel):
    """Response shape for live-session endpoints."""

    session_id: str
    source: Literal["interface", "pcap"]
    detection_mode: Literal["ml", "snort", "hybrid"]
    speed: Optional[float] = None
    started_at: datetime
    pcap_attached: bool
    persist_to_alerts: bool = False
    log_csv_url: str
    log_ndjson_url: str
    row_count: int = 0
