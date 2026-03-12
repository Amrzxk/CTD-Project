from pydantic import BaseModel, Field
from typing import Optional

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
