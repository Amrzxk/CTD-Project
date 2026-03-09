import re

def validate_port(port: int, field_name: str = "Port"):
    """
    Validates that a port number is within the valid range (0-65535).
    """
    if not (0 <= port <= 65535):
        raise ValueError(f"{field_name} must be between 0 and 65535. Got: {port}")
    return port

def validate_protocol(protocol: str):
    """
    Validates that the protocol is one of the supported types (tcp, udp, icmp).
    Case-insensitive.
    """
    valid_protocols = {"tcp", "udp", "icmp"}
    if protocol.lower() not in valid_protocols:
        raise ValueError(f"Protocol must be one of {valid_protocols}. Got: {protocol}")
    return protocol.lower()

def validate_non_negative(value: float, field_name: str):
    """
    Validates that a numeric value is non-negative.
    """
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative. Got: {value}")
    return value

def validate_ip(ip_address: str, field_name: str = "IP Address"):
    """
    Validates that a string is a valid IPv4 address.
    """
    if not ip_address:
        return None # Optional
        
    # Simple regex for IPv4
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(ipv4_pattern, ip_address):
        raise ValueError(f"{field_name} is not a valid IPv4 address. Got: {ip_address}")
    
    # Check octets
    octets = ip_address.split('.')
    for octet in octets:
        if not (0 <= int(octet) <= 255):
             raise ValueError(f"{field_name} has invalid octet: {octet}")
             
    return ip_address

def validate_flow_input(flow_data: dict):
    """
    Validates a dictionary of flow data against all rules.
    """
    # Validate Ports
    validate_port(flow_data.get("sport", 0), "Source Port")
    validate_port(flow_data.get("dsport", 0), "Destination Port")

    # Validate Protocol
    if "proto" in flow_data:
        validate_protocol(flow_data["proto"])
        
    # Validate IPs
    if "srcip" in flow_data and flow_data["srcip"]:
        validate_ip(flow_data["srcip"], "Source IP")
    if "dstip" in flow_data and flow_data["dstip"]:
        validate_ip(flow_data["dstip"], "Destination IP")

    # Validate Non-negative fields
    non_negative_fields = [
        "dur", "sbytes", "dbytes", "sttl", "dttl", 
        "spkts", "dpkts", "swin", "stcpb", "dtcpb",
        "trans_depth", "res_bdy_len", "sjit", "djit",
        "sintpkt", "dintpkt", "synack", "ackdat"
    ]
    
    for field in non_negative_fields:
        if field in flow_data:
            validate_non_negative(flow_data[field], field)
            
    return True
