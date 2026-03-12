# Sample CSV Data for Cyber Threat Detection Dashboard

This directory contains sample CSV files that can be used to test the batch upload functionality.

## CSV Format

The CSV file must contain the following columns in this exact order:

```
source_ip,destination_ip,source_port,destination_port,protocol,packet_size,duration
```

## Column Descriptions

- **source_ip**: Source IP address (IPv4 format, e.g., 192.168.1.100)
- **destination_ip**: Destination IP address (IPv4 format, e.g., 10.0.0.50)
- **source_port**: Source port number (0-65535)
- **destination_port**: Destination port number (0-65535)
- **protocol**: Network protocol (TCP, UDP, ICMP, HTTP, HTTPS)
- **packet_size**: Size of packet in bytes (positive integer)
- **duration**: Connection duration in seconds (positive decimal)

## Sample Data

### Example 1: Normal Traffic
```csv
source_ip,destination_ip,source_port,destination_port,protocol,packet_size,duration
192.168.1.100,10.0.0.50,8080,443,TCP,1024,5.2
172.16.0.5,8.8.8.8,53,53,UDP,512,0.1
10.10.10.10,192.168.1.1,49152,80,TCP,1500,3.5
192.168.1.101,10.0.0.51,3389,3389,TCP,2048,15.7
172.16.0.10,172.16.0.20,1024,1025,TCP,256,1.2
```

### Example 2: Mixed Traffic (Normal + Suspicious)
```csv
source_ip,destination_ip,source_port,destination_port,protocol,packet_size,duration
192.168.1.100,10.0.0.50,8080,443,HTTPS,1024,5.2
172.16.0.5,8.8.8.8,53,53,UDP,512,0.1
10.10.10.10,192.168.1.1,49152,22,TCP,64,0.5
192.168.1.55,185.220.101.5,12345,4444,TCP,8192,120.5
172.16.0.10,172.16.0.20,1024,1025,TCP,256,1.2
203.0.113.50,192.168.1.100,6667,6667,TCP,4096,300.0
192.168.1.101,10.0.0.51,3389,3389,TCP,2048,15.7
```

## Validation Rules

1. **IP Addresses**: Must be valid IPv4 format (e.g., 192.168.1.1)
2. **Ports**: Must be between 0 and 65535
3. **Protocol**: Should be one of: TCP, UDP, ICMP, HTTP, HTTPS
4. **Packet Size**: Must be a positive integer
5. **Duration**: Must be a positive number (can be decimal)
6. **File Size**: Maximum 10MB
7. **File Format**: Must be .csv extension

## Common Suspicious Patterns

The AI model may flag traffic as malicious based on patterns like:
- Unusual port combinations (e.g., 4444, 6667)
- Large packet sizes with long durations
- Known malicious IP ranges
- Unusual protocols for specific ports
- Multiple connections to the same destination

## How to Use

1. Create a CSV file with the required columns
2. Add your network traffic data
3. Navigate to the Upload page in the dashboard
4. Drag and drop the file or click to browse
5. Preview the first 5 rows
6. Click "Analyze File" to process

## Downloading Sample Data

You can download a sample CSV file directly from the Upload page using the "Download Sample CSV" button.
