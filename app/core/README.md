# Core Module Documentation

**Welcome!** This folder is the **heart** of the cybersecurity analysis system. Think of it as the engine room where all the heavy lifting happens: capturing network traffic, transforming it into analyzable data, running ML predictions, and logging the results.

If you're new to the codebase, start here. This guide breaks down each file and explains what it does, how it works, and why we built it that way.

---

## 📂 Files Overview

| File | Purpose | Lines of Code |
|------|---------|---------------|
| `capture_manager.py` | Captures live network packets using scapy | ~270 |
| `flow_aggregator.py` | Transforms raw packets into bidirectional flows | ~280 |
| `data_standardizer.py` | Cleans and prepares flow data for the ML model | ~290 |
| `model_manager.py` | Loads ML models and runs predictions | ~65 |
| `traffic_logger.py` | Saves classified flows to downloadable CSV files | ~80 |
| `mitre_mapper.py` | Maps ML attack categories to MITRE ATT&CK tactics and techniques | ~100 |

---

## 1️⃣ `capture_manager.py` — Live Packet Capture

### What it does
Listens to your network interface, captures every packet flying by, and aggregates them into **flows** (a flow = a conversation between two endpoints, like your browser talking to a web server).

### Key Concepts

**Why flows instead of individual packets?**
- Individual packets are too granular. A single web page load = hundreds of packets.
- Flows give us the big picture: "This computer sent 5 KB to that server over 2 seconds using HTTPS."
- Our ML model is trained on flow-level features, not raw packets.

**Why scapy?**
- **nfstream** (the original choice) is broken on Windows + Python 3.13 due to multiprocessing issues.
- **scapy** is battle-tested, works cross-platform, and gives us full control over packet parsing.

### Architecture

```
Network Interface (Ethernet/Wi-Fi)
         ↓
    scapy AsyncSniffer (captures raw packets in background thread)
         ↓
    process_packet() (extracts IP, TCP/UDP headers)
         ↓
    FlowTable.ingest() (groups packets into bidirectional flows)
         ↓
    asyncio.Queue (sends completed flows to main thread)
         ↓
    ML Classification + Logging
```

### Code Walkthrough

#### Interface Detection (`list_interfaces()`)
```python
def list_interfaces() -> list[dict]:
    """Return available network interfaces, preferring real physical NICs."""
```

**Problem it solves:** Windows has a dozen virtual adapters (Hyper-V, VirtualBox, Bluetooth). We need to pick the **real** one connected to the internet.

**How it works:**
1. Use `psutil` to list all network interfaces
2. Filter out:
   - Loopback (`127.0.0.1`)
   - Link-local (`169.254.x.x` = no DHCP)
   - Bluetooth, virtual adapters
3. Sort physical NICs first, then by speed

#### Interface Resolution (`_resolve_iface()`)
```python
def _resolve_iface(friendly_name: str):
    """Map psutil name like 'Wi-Fi' to scapy's interface object."""
```

**Problem:** `psutil` returns friendly names like `"Ethernet"`. Scapy on Windows needs the actual interface object from its internal registry.

**Solution:** Iterate through `scapy.config.conf.ifaces` and match by name or description.

#### The Capture Loop (`_capture_loop()`)
This runs in a **background thread** (because scapy's sniffer blocks the thread).

```python
def _capture_loop(self):
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP
    
    flow_table = FlowTable(idle_timeout=2.0, active_timeout=30.0)
```

**Key parameters:**
- `idle_timeout=2s` — Emit flow if no packets for 2 seconds (connection is idle)
- `active_timeout=30s` — Force-emit long-running flows every 30 seconds (prevents memory buildup)

**Packet Processing:**
```python
def process_packet(pkt):
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return  # Skip non-IP traffic (ARP, etc.)
```

We extract:
- **5-tuple**: `(src_ip, dst_ip, sport, dport, protocol)` — uniquely identifies a flow
- **TCP flags**: SYN, ACK, FIN, RST (for connection state tracking)
- **TCP metadata**: sequence number, window size (for RTT/jitter calculations)
- **Timestamps**: Used to calculate inter-arrival times and durations

**Flow completion:**
```python
completed = flow_table.ingest(pkt_info)
if completed:
    self._emit_flow(completed)  # Send to asyncio queue for ML classification
```

**Periodic sweep:**
```python
while self._running:
    time.sleep(1.0)  # Every second...
    expired = flow_table.sweep_expired()  # Check for idle/active timeouts
    for flow_dict in expired:
        self._emit_flow(flow_dict)
```

This ensures flows get emitted even if we never see a FIN/RST packet.

---

## 2️⃣ `flow_aggregator.py` — Packet → Flow Transformation

### What it does
Takes raw packet info (IPs, ports, length, timestamp) and builds a **bidirectional flow record** with 38 statistical features matching the UNSW-NB15 dataset schema.

### Key Concepts

**Bidirectional flow:**
- Your browser → server = "forward direction" (sbytes, spkts, sttl)
- Server → your browser = "reverse direction" (dbytes, dpkts, dttl)
- Both directions are tracked in a single `FlowState` object

**Flow normalization:**
```python
def _make_key(self, src_ip, dst_ip, sport, dport, proto):
    forward = (src_ip, dst_ip, sport, dport, proto)
    reverse = (dst_ip, src_ip, dport, sport, proto)
    return min(forward, reverse)
```

**Why?** A packet from A→B and a packet from B→A are part of the same conversation. We use `min()` to ensure both directions map to the same flow key.

### The `FlowState` Class

This is a **mutable container** tracking all the stats for one flow:

```python
@dataclass
class FlowState:
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    proto: int
    
    start_time: float       # First packet timestamp
    last_time: float        # Most recent packet timestamp
    
    sbytes: int = 0         # Bytes sent from src → dst
    dbytes: int = 0         # Bytes sent from dst → src
    spkts: int = 0          # Packets sent src → dst
    dpkts: int = 0          # Packets sent dst → src
    
    sttl: int = 0           # Time-to-live (IP header)
    dttl: int = 0
    
    swin: int = 0           # TCP window size
    stcpb: int = 0          # TCP base sequence number
    
    syn_time: float = 0.0   # TCP handshake timing
    synack_time: float = 0.0
    ack_time: float = 0.0
    
    _src_times: list = []   # Packet arrival timestamps (for jitter)
    _src_sizes: list = []   # Packet sizes (for mean calculation)
```

### Feature Calculation (`to_model_dict()`)

When a flow expires, we calculate 38 features:

**Duration & throughput:**
```python
dur = self.duration  # last_time - start_time
sload = (self.sbytes * 8 / dur) if dur > 0 else 0.0  # bits/sec
dload = (self.dbytes * 8 / dur) if dur > 0 else 0.0
```

**Mean packet size:**
```python
smeansz = (self.sbytes / self.spkts) if self.spkts > 0 else 0.0
```

**TCP RTT (Round-Trip Time):**
```python
synack = (self.synack_time - self.syn_time)       # SYN → SYN+ACK
ackdat = (self.ack_time - self.synack_time)       # SYN+ACK → ACK
tcprtt = synack + ackdat                          # Total handshake time
```

**Jitter (variance in inter-arrival times):**
```python
def _jitter(times: list) -> float:
    if len(times) < 3:
        return 0.0
    diffs = [times[i] - times[i-1] for i in range(1, len(times))]
    jitters = [abs(diffs[i] - diffs[i-1]) for i in range(1, len(diffs))]
    return (sum(jitters) / len(jitters)) * 1000  # milliseconds
```

**Connection state:**
```python
def _derive_state(self) -> str:
    if self.proto != 6:
        return "CON"  # UDP/ICMP = always "connected"
    
    FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10
    sf, df = self.src_flags, self.dst_flags
    
    if (sf & RST) or (df & RST):
        return "RST"  # Connection reset
    if (sf & FIN) and (df & FIN):
        return "FIN"  # Clean shutdown
    if (sf & SYN) and (df & SYN) and (df & ACK):
        return "CON"  # Successful 3-way handshake
    if (sf & SYN) and not (df & SYN):
        return "REQ"  # SYN sent but no response (connection attempt)
    return "CON"
```

### The `FlowTable` Class

Tracks all active flows and emits completed ones:

```python
def ingest(self, pkt_info: dict) -> Optional[dict]:
    key = self._make_key(...)
    flow = self._flows.get(key)
    
    if flow is None:
        flow = FlowState(...)  # New flow
        self._flows[key] = flow
    
    # Update stats
    if is_forward:
        flow.sbytes += length
        flow.spkts += 1
    else:
        flow.dbytes += length
        flow.dpkts += 1
    
    # Emit on TCP FIN/RST
    if proto == 6 and (tcp_flags & (FIN | RST)):
        completed = flow.to_model_dict()
        del self._flows[key]
        return completed
    
    return None
```

**Sweep expired flows:**
```python
def sweep_expired(self) -> list[dict]:
    now = time.time()
    expired = []
    
    for key, flow in self._flows.items():
        idle = now - flow.last_time
        active = now - flow.start_time
        
        if idle >= self._idle_timeout or active >= self._active_timeout:
            expired.append(flow.to_model_dict())
            # Mark for deletion...
    
    return expired
```

---

## 3️⃣ `data_standardizer.py` — Feature Engineering & Cleaning

### What it does
Takes raw flow data (from live capture, CSV upload, or PCAP file) and transforms it into a clean DataFrame with exactly 38 features in the exact order the ML model expects.

### The Problem It Solves

**Input diversity:**
- Live flows from `flow_aggregator` already have most features
- CSV files might have extra columns or different names
- PCAP files need full feature extraction from scratch

**Model requirements:**
- Must have exactly 38 features (not 37, not 39)
- Must be in the correct order: `["sport", "dsport", "proto", "state", ...]`
- Missing features must be filled with defaults (0 or calculated values)

### Key Methods

#### `from_live_flow(flow_dict)`
```python
def from_live_flow(self, flow_dict: dict):
    df = pd.DataFrame([flow_dict])
    df = self._calculate_derived_features(df)
    return self._process_dataframe(df)
```

**Use case:** Live capture flows (already preprocessed by `flow_aggregator`)

**Steps:**
1. Wrap dict in a DataFrame
2. Calculate derived features (CT stats, rates)
3. Drop non-feature columns (`srcip`, `dstip`)
4. Fill missing values
5. Select final 38 features in correct order

#### `from_csv(file_path)` / `from_excel(file_path)`
```python
def from_csv(self, file_path):
    df = pd.read_csv(file_path)
    return self._process_dataframe(df)
```

**Use case:** User uploads a CSV/Excel file for batch prediction

**Assumption:** File has column names matching the model features (or close enough after cleaning)

#### `from_pcap(file_path)`
```python
def from_pcap(self, file_path):
    from nfstream import NFStreamer
    
    flows = []
    streamer = NFStreamer(source=file_path)
    
    for flow in streamer:
        # Extract nfstream attributes
        raw = {...}
        renamed = {NFSTREAM_TO_MODEL.get(k, k): v for k, v in raw.items()}
        flows.append(renamed)
    
    df = pd.DataFrame(flows)
    df = self._calculate_derived_features(df)
    return self._process_dataframe(df)
```

**Use case:** User uploads a `.pcap` packet capture file

**Why nfstream here but not in live capture?** PCAP file processing is offline (no multiprocessing issues) and nfstream's DPI (Deep Packet Inspection) is useful for extracting application-layer protocols.

### Feature Calculation (`_calculate_derived_features()`)

**State derivation:**
```python
def _derive_state(self, row):
    """Infer TCP connection state from protocol and byte counts."""
    if row['proto'] in [17, 1]:  # UDP or ICMP
        return 'CON'
    
    if row['sbytes'] > 0 and row['dbytes'] > 0:
        return 'CON'  # Bidirectional = established
    elif row['sbytes'] > 0:
        return 'REQ'  # Only outbound = request attempt
    else:
        return 'INT'  # Only inbound = weird, maybe scan
```

**Rate calculations:**
```python
df['sload'] = (df['sbytes'] * 8) / df['dur'].replace(0, 1)  # bits/sec
df['dload'] = (df['dbytes'] * 8) / df['dur'].replace(0, 1)
df['smeansz'] = df['sbytes'] / df['spkts'].replace(0, 1)   # bytes/packet
df['dmeansz'] = df['dbytes'] / df['dpkts'].replace(0, 1)
```

**Connection tracking (CT stats):**
```python
df['ct_dst_ltm'] = df.groupby('dstip')['dstip'].transform('count')
df['ct_src_ltm'] = df.groupby('srcip')['srcip'].transform('count')
df['ct_src_dport_ltm'] = df.groupby(['srcip', 'dsport']).size()
```

These count how many connections share the same:
- Destination IP (`ct_dst_ltm`)
- Source IP (`ct_src_ltm`)
- Source IP + destination port (`ct_src_dport_ltm`)

**Why?** Attackers often exhibit patterns like:
- Port scanning: same `srcip`, many different `dsport` values
- DDoS: many different `srcip` → same `dstip`

### Final Processing (`_process_dataframe()`)

```python
def _process_dataframe(self, df):
    # 1. Drop identifiers
    df = df.drop(columns=['srcip', 'dstip'], errors='ignore')
    
    # 2. Handle infinities (division by zero)
    df.replace([np.inf, -np.inf], 0, inplace=True)
    
    # 3. Fill missing values
    for col in self.selected_features:
        if col not in df.columns:
            df[col] = 0  # Model expects this feature, so default to 0
        else:
            df[col].fillna(0, inplace=True)
    
    # 4. Select and order features
    return df[self.selected_features]
```

**Why drop `srcip`/`dstip`?** The model is trained to detect attack **patterns**, not specific IP addresses. Including IPs would cause overfitting ("this IP is always malicious").

---

## 4️⃣ `model_manager.py` — ML Inference

### What it does
Loads the trained ML models and runs predictions on cleaned flow data.

### Architecture: Two-Stage Classification

**Stage 1: Binary Classifier**
```python
binary_pred = self.binary_model.predict(X)
binary_proba = self.binary_model.predict_proba(X)
```

**Output:** `0` (Normal) or `1` (Attack)

**Stage 2: Multi-Class Classifier** (only for attacks)
```python
multi_pred = self.multi_model.predict(X)
```

**Output:** Attack category (DoS, Reconnaissance, Exploits, etc.)

**Why two stages?**
- Most traffic is normal → binary classifier is fast
- Multi-class is only needed for attacks (fewer rows to process)
- Allows us to fine-tune binary recall (catch all attacks) vs. multi-class precision (correctly categorize attacks)

### Confidence & Severity

```python
confidence = float(binary_proba[i].max())

if is_attack:
    if confidence > 0.9:
        severity = "High"
    elif confidence > 0.8:
        severity = "Medium"
    else:
        severity = "Low"
```

**Thresholds explained:**
- **High (>90%)**: Model is very confident → immediate investigation
- **Medium (80-90%)**: Likely malicious, worth checking
- **Low (<80%)**: Suspicious but may be false positive

### Batch Processing

```python
for i in range(len(df)):
    is_attack = (binary_pred[i] == 1)
    result = {
        "prediction": "Malicious" if is_attack else "Normal",
        "confidence": confidence,
        "severity": severity,
        "attack_type": str(multi_pred[i]) if is_attack else None,
        # ... metadata ...
    }
    results.append(result)
```

**Why loop instead of vectorized?** Each row needs conditional logic (attack_type is only set if `is_attack`). Pandas vectorization doesn't handle this well.

---

## 5️⃣ `traffic_logger.py` — CSV Export

### What it does
Saves classified flows to timestamped CSV files that users can download.

### Key Features

**Session-based logging:**
```python
def start_session(self):
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    self._current_file = self._log_dir / f"traffic_{ts}.csv"
```

Each capture session gets its own file: `traffic_2026-03-12_15-30-42.csv`

**Real-time writing:**
```python
def log(self, packet: dict):
    if self._writer is None:
        return
    self._writer.writerow(packet)
    self._handle.flush()  # Write immediately (don't buffer)
```

**Why flush?** If the server crashes mid-capture, we don't lose data.

**File listing:**
```python
def get_log_files(self) -> list[dict]:
    files = sorted(self._log_dir.glob("traffic_*.csv"), reverse=True)
    return [
        {
            "filename": f.name,
            "size_bytes": f.stat().st_size,
            "created": datetime.fromtimestamp(f.stat().st_ctime).isoformat(),
        }
        for f in files
    ]
```

Returns most recent files first (reverse chronological).

**Security:**
```python
def get_log_path(self, filename: str) -> Optional[Path]:
    safe_name = Path(filename).name  # Strip directory traversal
    path = self._log_dir / safe_name
    if path.exists() and path.suffix == ".csv":
        return path
    return None
```

**Why `Path(filename).name`?** Prevents directory traversal attacks like `../../../etc/passwd`.

---

---

## 6️⃣ `mitre_mapper.py` — MITRE ATT&CK Enrichment

### What it does
After the ML model classifies a flow as malicious, `MitreMapper` answers the next question: **"What kind of attack is this, in industry-standard terms?"**

It translates the model's internal attack category labels (like `"DoS"`, `"Exploits"`, `"Reconnaissance"`) into structured [MITRE ATT&CK](https://attack.mitre.org/) tactics and techniques — the global standard used by SOC analysts, threat intelligence teams, and security tools like Splunk and CrowdStrike.

### Why MITRE ATT&CK?

The ML model outputs a label. That's useful internally, but it doesn't tell an analyst:
- **What the attacker was trying to do** (tactic)
- **How they did it** (technique)
- **Where to look for more info** (external links to the ATT&CK knowledge base)

MITRE ATT&CK is the bridge between our ML output and real-world threat intelligence.

### Architecture

```
ML Model Output
  { prediction: "Malicious", attack_type: "DoS", confidence: 0.91 }
         ↓
  MitreMapper.enrich_prediction()
         ↓
  Confidence check: 0.91 >= 0.70 threshold? ✅
         ↓
  Lookup "DoS" in mitre_mapping.json
         ↓
  Resolve confidence band: 0.91 → "high" (0.85–0.95)
         ↓
  Enriched output:
  {
    prediction: "Malicious",
    attack_type: "DoS",
    confidence: 0.91,
    mitre: {
      confidence_band: "high",
      tactics: [{ id: "TA0040", name: "Impact" }],
      techniques: [{ id: "T1498", name: "Network Denial of Service", url: "..." }]
    }
  }
```

### The Knowledge Base (`app/data/mitre_mapping.json`)

All the MITRE data lives in a static JSON file — not hardcoded in Python. This is intentional:

- **Easy to update**: When MITRE releases a new ATT&CK version, you update the JSON, not the code.
- **Readable by non-developers**: A security analyst can open the JSON and understand/edit the mappings.
- **Configurable thresholds**: The `min_confidence` and `confidence_bands` are also in the JSON, not buried in code.

The JSON structure:
```json
{
  "version": "1.0",
  "framework": "MITRE ATT&CK v14",
  "min_confidence": 0.70,
  "confidence_bands": {
    "low":       { "min": 0.70, "max": 0.85, "label": "Low Confidence" },
    "high":      { "min": 0.85, "max": 0.95, "label": "High Confidence" },
    "very_high": { "min": 0.95, "max": 1.00, "label": "Very High" }
  },
  "mappings": {
    "DoS": {
      "description": "Denial of Service attacks...",
      "tactics": [
        {
          "id": "TA0040",
          "name": "Impact",
          "techniques": [
            { "id": "T1498", "name": "Network Denial of Service", "url": "https://attack.mitre.org/..." }
          ]
        }
      ]
    }
  }
}
```

### Code Walkthrough

#### Constructor
```python
def __init__(self, mapping_path: Path):
    raw = json.loads(mapping_path.read_text(encoding="utf-8"))
    self._min_confidence: float = raw.get("min_confidence", 0.70)
    self._bands: dict = raw.get("confidence_bands", {})
    self._mappings: dict = raw.get("mappings", {})
```

Everything is loaded once at startup (in `main.py`'s lifespan handler) and kept in memory. No file I/O on every request.

#### `enrich_prediction(prediction: dict) -> dict`

This is the main method. It takes a prediction dict and returns a new dict with a `mitre` field added.

**Three cases where `mitre` is set to `None`:**

```python
# 1. Not an attack — no MITRE data needed
if prediction.get("prediction") != "Malicious":
    enriched["mitre"] = None
    return enriched

# 2. Model isn't confident enough — don't mislead the analyst
if confidence < self._min_confidence:  # default: 0.70
    enriched["mitre"] = None
    return enriched

# 3. Unknown attack type — no mapping exists
mapping = self._mappings.get(attack_type)
if not mapping:
    enriched["mitre"] = None
    return enriched
```

**Why the 70% confidence threshold?**

Below 70%, the model is essentially guessing. Showing MITRE data for a low-confidence prediction would give analysts false confidence in a potentially wrong classification. Industry standard for actionable threat intelligence is ≥70% model confidence.

**When all checks pass:**
```python
enriched["mitre"] = {
    "confidence_band": self._resolve_band(confidence),
    "tactics": [{"id": t["id"], "name": t["name"]} for t in ...],
    "techniques": [{"id": t["id"], "name": t["name"], "url": t["url"]} for t in ...],
}
```

#### `_resolve_band(confidence: float) -> str`

Maps a confidence score to a human-readable band:

```python
def _resolve_band(self, confidence: float) -> str:
    for band_key, band in self._bands.items():
        if band["min"] <= confidence < band["max"]:
            return band_key  # "low", "high", or "very_high"
    if confidence >= 0.95:
        return "very_high"  # Fallback for edge case at exactly 1.0
    return "low"
```

The frontend uses this band to color-code the confidence indicator:
- `low` → yellow badge (70–85%)
- `high` → orange badge (85–95%)
- `very_high` → red badge (95–100%)

#### `get_matrix() -> dict`

Returns the full MITRE matrix for the frontend's `/mitre` page:

```python
def get_matrix(self) -> dict:
    return {
        "version": self._version,
        "framework": self._framework,
        "min_confidence": self._min_confidence,
        "confidence_bands": self._bands,
        "entries": [
            {
                "category": category,
                "description": data["description"],
                "tactics": data["tactics"],
            }
            for category, data in self._mappings.items()
        ],
    }
```

This powers the interactive MITRE matrix visualization page in the dashboard.

#### `lookup(attack_category: str) -> Optional[dict]`

Simple dict lookup for a single category — used by the `/mitre/lookup/{category}` API endpoint.

### Where It's Used

`MitreMapper` is initialized once in `main.py` and stored on `app.state`:

```python
app.state.mitre_mapper = MitreMapper(mitre_path)
```

Then it's pulled from app state and called in three places:

| File | Where | What it enriches |
|------|-------|-----------------|
| `api/live.py` | `_classify_live_flow()` | Every live-captured flow |
| `api/routes.py` | `analyze_upload()` | Every row in a batch CSV/Excel upload |
| `api/routes.py` | `analyze_manual()` | Single manual flow input |

### Design Decisions

**Why not hardcode the mappings in Python?**
The JSON approach means a security analyst can update the threat intelligence without touching Python. It also makes the mappings version-controlled and diffable.

**Why not call the MITRE ATT&CK API live?**
- Network latency on every prediction would be unacceptable
- The ATT&CK framework doesn't change frequently
- Offline operation (air-gapped environments) is a requirement for security tools

**Why a flat `techniques` list in the enrichment output?**
The raw JSON has techniques nested under tactics. The enrichment flattens them so the frontend doesn't need to traverse nested structures — simpler rendering logic.

---

## 🧠 How It All Works Together

### Live Capture Flow

```
1. User clicks "Start Capture" in dashboard
         ↓
2. FastAPI → CaptureManager.start()
         ↓
3. scapy AsyncSniffer starts in background thread
         ↓
4. Each packet → FlowTable.ingest()
         ↓
5. Completed flows → asyncio.Queue
         ↓
6. Main thread pulls from queue
         ↓
7. DataStandardizer.from_live_flow() → clean DataFrame
         ↓
8. ModelManager.predict() → ML classification
         ↓
9. MitreMapper.enrich_prediction() → MITRE tactics/techniques added (if confidence ≥ 70%)
         ↓
10. TrafficLogger.log() → append to CSV
         ↓
11. SSE stream → dashboard updates in real-time
```

### File Upload Flow

```
1. User uploads CSV/Excel file
         ↓
2. FastAPI receives file → save to /tmp
         ↓
3. DataStandardizer.from_csv() → clean DataFrame
         ↓
4. ModelManager.predict() → batch classification
         ↓
5. MitreMapper.enrich_prediction() → MITRE data added per row (if confidence ≥ 70%)
         ↓
6. Return JSON results to frontend
```

---

## 🛠️ Design Decisions

### Why threading + asyncio?

**Problem:** scapy's `AsyncSniffer` blocks the thread it runs on.

**Solution:**
- Capture runs in a **background thread** (doesn't block FastAPI)
- Use `asyncio.run_coroutine_threadsafe()` to push flows from thread → asyncio event loop
- Main thread handles ML inference + SSE streaming

### Why not multiprocessing?

nfstream tried this and it failed on Windows. Threading is simpler and sufficient for our use case (I/O-bound, not CPU-bound).

### Why 2-second idle timeout?

**Trade-offs:**
- **Lower (1s)**: Flows appear faster, but short bursts might get split into multiple flows
- **Higher (5s+)**: More accurate flow aggregation, but slow user experience
- **2s**: Sweet spot for most connections (web browsing, API calls)

### Why not store flows in a database?

**Current:** CSV files (simple, portable, Excel-compatible)

**Future:** If you need querying/filtering, consider PostgreSQL or ClickHouse. But for now, CSV is fine for manual analysis.

---

## 🚀 Next Steps for Junior Devs

1. **Add tests** — Write unit tests for `FlowState.to_model_dict()`, `_derive_state()`, and `MitreMapper.enrich_prediction()`.
2. **Metrics** — Add counters: flows/sec, packets/sec, avg duration, MITRE enrichment hit rate.
3. **HTTP/DNS parsing** — Extract HTTP methods, DNS queries for richer features.
4. **Alert system** — Webhook notifications when High severity attacks are detected.
5. **Performance** — Profile the ML inference step (likely bottleneck for high traffic).
6. **MITRE versioning** — When MITRE releases ATT&CK v15+, update `mitre_mapping.json` and bump the `version` field.
7. **Expand MITRE coverage** — Add sub-techniques (e.g., `T1498.001`) for finer-grained mapping.

---

## 📚 Further Reading

- [scapy documentation](https://scapy.readthedocs.io/)
- [UNSW-NB15 dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- [Python asyncio](https://docs.python.org/3/library/asyncio.html)
- [MITRE ATT&CK framework](https://attack.mitre.org/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — visualize coverage

**Questions?** Ask in #engineering-support on Slack.
