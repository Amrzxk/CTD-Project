Enhance the "Batch Analysis" upload page of the Cyber Threat Detection platform to include a packet analyzer interface after file upload.

Keep the existing two-column layout:

Left side:
Upload Network Packet File

Right side:
Data Preview panel

Do not remove the existing layout or dark cybersecurity design theme.

Modify the page behavior as follows:

1. Upload Component

Replace the simple CSV upload box with a modern drag-and-drop uploader titled:

"Upload Network Packet File"

Inside the upload card include:

Drag & Drop area text:
"Drag & Drop your network packet file here"

Below it show:
"or"

Add a button:
"Browse Files"

Supported file types:

.pcap • .pcapng • .csv • .json • .log

Helper text:
"Supports Wireshark packet captures and network traffic files."

2. Packet Processing State

After a file is uploaded, show a processing status panel with steps:

Parsing packet capture
Extracting network flows
Generating ML features
Running AI threat detection

Include a progress bar.

3. Packet Analyzer Interface

After processing is complete, transform the Data Preview panel into a packet analyzer.

Add three stacked sections:

Packet List Table

Columns:
timestamp
src_ip
dst_ip
protocol
src_port
dst_port
packet_length
prediction
risk_level

Color coding:
Green = Normal
Red = Malicious
Yellow = Suspicious

Packet Details Panel

When clicking a packet row show:

Source IP
Destination IP
Ports
Protocol
Packet size
TTL
Flags
Duration
Feature values used by the ML model

Feature Explanation Panel

Display AI explanation such as:

"High packet rate detected"
"Abnormal destination port behavior"
"Suspicious connection duration"

Design should resemble a lightweight Wireshark-style packet inspection interface integrated into the existing cybersecurity dashboard.

Maintain the neon green cybersecurity UI style and dark theme used in the application.
