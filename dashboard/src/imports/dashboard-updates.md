Update the existing Cyber Threat Detection Dashboard design while keeping the same dark cybersecurity theme and layout style.

Apply the following UI modifications:

1. Replace the current "Traffic Distribution" chart with a new chart titled:
   "Attack Category Distribution".

Display a pie chart showing attack categories:

* DDoS
* Port Scan
* Brute Force
* SQL Injection
* XSS

Use neon cybersecurity colors and show percentage labels.

This chart should appear in the Analytics page where the old traffic distribution chart currently exists.

2. Update the "Traffic Over Time" chart.

Instead of a single line for normal traffic, show two lines:

* Normal traffic (green)
* Suspicious traffic (orange or red)

Keep the time axis (24-hour timeline).

3. Add a new section below the traffic chart:

"Top 10 Feature Importance"

Display a horizontal bar chart showing the most influential machine learning features used in the threat detection model.

Example features:
sbytes, dbytes, dur, spkts, dpkts, sload, dload, rate, sttl, dttl.

4. Add a new monitoring section to the Dashboard page:

Title:
"Live Packet Monitoring"

Include a real-time table with columns:

src_ip
dst_ip
sport
dport
protocol
service
duration
sbytes
dbytes
spkts
dpkts
state
prediction

Use colors:
Green = Normal
Red = Malicious
Yellow = Suspicious

Next to the table, add a packet details panel that displays full packet information when a row is selected.

5. Update the file upload component.

Instead of accepting only CSV files, allow multiple network packet file formats:

Supported formats:
CSV
PCAP
PCAPNG
JSON
LOG
TXT
TSV

Add helper text:
"Supports Wireshark packet captures and network traffic datasets."

Keep the drag-and-drop style and the existing design theme.
