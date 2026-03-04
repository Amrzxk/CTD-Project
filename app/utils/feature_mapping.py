# Mapping from NFStream flow attributes to Model feature names
NFSTREAM_TO_MODEL = {
    # Basic Flow Features
    "src_port": "sport",
    "dst_port": "dsport",
    "protocol": "proto",
    "bidirectional_duration_ms": "dur",  # Note: Model expects seconds, needs conversion
    "src2dst_bytes": "sbytes",
    "dst2src_bytes": "dbytes",
    "src2dst_packets": "spkts",
    "dst2src_packets": "dpkts", # Helper for calculation
    
    # Time Features
    "src2dst_mean_piat_ms": "sintpkt",
    "dst2src_mean_piat_ms": "dintpkt",
    "src2dst_jitter_ms": "sjit",
    "dst2src_jitter_ms": "djit",
    
    # Application/Service
    "application_name": "service",
    
    # TCP Features (Approximations/Direct mappings if available)
    "src2dst_tcp_win": "swin",
    
    # TTL
    "src2dst_min_ttl": "sttl",
    "dst2src_min_ttl": "dttl",
}

# Features that need to be calculated or are not directly available in basic NFStream
# These will need custom logic in the feature extraction pipeline
CALCULATED_FEATURES = [
    "state",            # Derived from TCP flags/connection state
    "sload",            # sbytes * 8 / dur
    "dload",            # dbytes * 8 / dur
    "smeansz",          # sbytes / spkts
    "dmeansz",          # dbytes / dpkts
    "trans_depth",      # HTTP transaction depth
    "res_bdy_len",      # HTTP response body length
    "stcpb",            # Source TCP base sequence number
    "dtcpb",            # Destination TCP base sequence number
    "tcprtt",           # synack + ackdat
    "synack",           # TCP connection setup time (SYN -> SYN_ACK)
    "ackdat",           # TCP connection setup time (SYN_ACK -> ACK)
    "is_sm_ips_ports",  # src_ip == dst_ip && src_port == dst_port
    "ct_state_ttl",     # Count of connections with same state and TTL
    "ct_flw_http_mthd", # Count of flows with HTTP methods
    "is_ftp_login",     # FTP login check
    "ct_srv_src",       # Count of connections with same service and src_ip
    "ct_srv_dst",       # Count of connections with same service and dst_ip
    "ct_dst_ltm",       # Count of connections with same dst_ip
    "ct_src_ltm",       # Count of connections with same src_ip
    "ct_src_dport_ltm", # Count of connections with same src_ip and dst_port
    "ct_dst_sport_ltm", # Count of connections with same dst_ip and src_port
    "ct_dst_src_ltm"    # Count of connections with same src_ip and dst_ip
]

# Full list of features expected by the model (38 features)
MODEL_FEATURES = [
    "sport", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl",
    "dttl", "service", "sload", "dload", "spkts", "swin", "stcpb", "dtcpb",
    "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "sjit", "djit",
    "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports",
    "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_srv_src",
    "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm"
]
