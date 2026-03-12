Update the Cyber Threat Detection web dashboard layout while keeping the existing dark cybersecurity theme.

Apply the following layout and styling updates:

1. Dashboard Page Updates

Move the "Live Packet Monitoring" component to the bottom of the Dashboard page.

Place it directly after the "Prediction Results" table.

Create a two-column layout:

Left side:
Live Packet Monitoring Table

Columns:
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

Right side:
Packet Details Panel

The Packet Details panel should appear when a row in the Live Packet Monitoring table is clicked.

Display the following sections:

Risk Level
Model Confidence
Basic Information
Traffic Metrics
Advanced Features

Ensure the design matches the reference style with card layout, neon accents, and dark theme.

2. Analytics Page Updates

At the bottom of the Analytics page add two charts placed side-by-side:

Left chart:
Protocol Distribution

Bar chart showing:
TCP
UDP
ICMP

Right chart:
Top 5 Malicious Source IPs

Horizontal bar chart displaying the most malicious source IP addresses.

Both charts should appear as smaller dashboard cards placed next to each other.

3. Top 10 ML Feature Importance Styling

Update the "Top 10 Feature Importance" chart on the Analytics page.

Remove the multi-color gradient bars.

Use a single consistent neon lime-green color for all feature bars.

Maintain the same chart layout but unify the color styling to match the cybersecurity theme.

4. Maintain Theme Consistency

Ensure all components use the same dashboard background, border styles, and glow accents.

Charts should follow the global UI theme so the entire platform keeps a consistent cybersecurity dashboard design.
