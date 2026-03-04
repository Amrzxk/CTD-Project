from pydantic import BaseModel, Field
from typing import Optional

class ManualFlowInput(BaseModel):
    # Categorical
    proto: Optional[str] = Field("tcp", description="Protocol (e.g., tcp, udp)")
    state: Optional[str] = Field("CON", description="State (e.g., CON, FIN, INT)")
    service: Optional[str] = Field("-", description="Service (e.g., http, dns, -)")

    # Basic Flow
    sport: Optional[int] = Field(0, description="Source Port")
    dsport: Optional[int] = Field(0, description="Destination Port")
    dur: Optional[float] = Field(0.0, description="Duration (seconds)")
    sbytes: Optional[int] = Field(0, description="Source Bytes")
    dbytes: Optional[int] = Field(0, description="Destination Bytes")
    sttl: Optional[int] = Field(0, description="Source TTL")
    dttl: Optional[int] = Field(0, description="Destination TTL")
    
    # Packets (needed for mean size calculations)
    spkts: Optional[int] = Field(0, description="Source Packets")
    dpkts: Optional[int] = Field(0, description="Destination Packets")
    
    # TCP
    swin: Optional[int] = Field(0, description="Source Window")
    stcpb: Optional[int] = Field(0, description="Source TCP Base Seq")
    dtcpb: Optional[int] = Field(0, description="Destination TCP Base Seq")
    
    # Content
    trans_depth: Optional[int] = Field(0, description="Transaction Depth")
    res_bdy_len: Optional[int] = Field(0, description="Response Body Length")
    
    # Jitter
    sjit: Optional[float] = Field(0.0, description="Source Jitter")
    djit: Optional[float] = Field(0.0, description="Destination Jitter")
    
    # Inter-packet arrival
    sintpkt: Optional[float] = Field(0.0, description="Source Inter-packet Arrival")
    dintpkt: Optional[float] = Field(0.0, description="Destination Inter-packet Arrival")
    
    # TCP Time
    synack: Optional[float] = Field(0.0, description="SYN-ACK Time")
    ackdat: Optional[float] = Field(0.0, description="ACK-Data Time")
