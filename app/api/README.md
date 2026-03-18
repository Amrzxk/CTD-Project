# API Module Documentation

**Welcome!** This folder contains all the FastAPI route handlers — the HTTP layer that sits between the frontend and the core engine.

If the `core/` folder is the engine room, think of `api/` as the **control panel**: it receives requests from the outside world, delegates work to the right core service, and sends back clean, structured responses.

---

## 📂 Files Overview

| File | Purpose | Prefix |
|------|---------|--------|
| `routes.py` | Batch predictions, analytics, manual input | (no prefix) |
| `live.py` | Live capture lifecycle and SSE streaming | `/live` |
| `mitre.py` | MITRE ATT&CK matrix and category lookup | `/mitre` |
| `schemas.py` | Pydantic request/response models | — |

---

## How FastAPI Routing Works (Quick Primer)

Each file defines an `APIRouter`. Routers are like mini-apps — they group related endpoints together. They're all registered in `main.py`:

```python
app.include_router(router)          # routes.py  → /predictions, /analytics, /analyze/*
app.include_router(live_router)     # live.py    → /live/*
app.include_router(mitre_router)    # mitre.py   → /mitre/*
```

Every endpoint function is `async` — FastAPI runs them on an asyncio event loop, so they don't block each other.

---

## 1️⃣ `routes.py` — Batch Analysis & Analytics

### Endpoints

| Method | Path | What it does |
|--------|------|-------------|
| `GET` | `/predictions` | Return all stored predictions (most recent first) |
| `GET` | `/analytics` | Aggregate stats: counts, timeline, top IPs, feature importance |
| `POST` | `/analyze/upload` | Accept a CSV/Excel/PCAP file, run batch ML prediction |
| `POST` | `/analyze/manual` | Accept manually entered flow features, run single prediction |

### In-Memory Store

```python
predictions_store = []
```

All predictions (from uploads and manual input) are kept in a module-level list. This is intentional for the current scope — simple, zero-dependency, fast.

> **Future note:** When you move to production on EC2, replace this with a database (PostgreSQL or Redis). The list resets every time the server restarts.

---

### `GET /predictions`

```python
@router.get("/predictions")
async def get_predictions():
    return list(reversed(predictions_store))
```

Returns the full history, newest first. The `reversed()` call avoids mutating the original list.

---

### `GET /analytics`

This is the most complex endpoint. It loops through `predictions_store` once and builds several aggregations simultaneously:

**What it calculates:**

| Output field | How it's built |
|---|---|
| `normalCount` / `maliciousCount` | Count by `prediction` field |
| `timelineData` | Splits predictions into 20 bins, counts normal/malicious per bin |
| `topMaliciousIPs` | `Counter` on `sourceIp` for malicious predictions, top 5 |
| `severityCounts` | Count high/medium/low severity across malicious predictions |
| `attackCategories` | `Counter` on `attack_type`, with color assignment |
| `protocolDistribution` | `Counter` on `protocol` (TCP/UDP/ICMP) |
| `featureImportance` | Average value of 10 key ML features across all predictions |

**Timeline logic:**
```python
num_bins = 20
bin_size = max(1, total_preds // num_bins)

for b in range(actual_bins):
    batch = predictions_store[b * bin_size : (b + 1) * bin_size]
    timeline_data.append({
        "step": b + 1,
        "normal": count of Normal in batch,
        "suspicious": count of Malicious in batch
    })
```

This creates a wave chart on the frontend — you can see traffic spikes over time.

---

### `POST /analyze/upload`

Accepts a file upload (CSV, Excel, or PCAP), runs it through the full ML pipeline, and returns enriched predictions.

**Flow:**
```
File upload (multipart/form-data)
         ↓
Save to temp file (uuid-named to avoid collisions)
         ↓
DataStandardizer.from_csv() / from_excel() / from_pcap()
         ↓
ModelManager.predict() → list of raw predictions
         ↓
Format each prediction (add id, timestamp, IP fields)
         ↓
MitreMapper.enrich_prediction() → add MITRE data
         ↓
Append to predictions_store
         ↓
Return { success, total, predictions }
```

**Error handling:**
```python
finally:
    if os.path.exists(temp_filename):
        os.remove(temp_filename)  # Always clean up temp files
```

Even if the prediction fails, the temp file is deleted. This prevents disk bloat on the server.

**MITRE enrichment:**
```python
mitre_mapper = getattr(request.app.state, "mitre_mapper", None)
# ...
if mitre_mapper:
    prediction_obj = mitre_mapper.enrich_prediction(prediction_obj)
else:
    prediction_obj["mitre"] = None
```

`getattr(..., None)` is used defensively — if `mitre_mapper` wasn't initialized (e.g., `mitre_mapping.json` is missing), the endpoint still works, it just won't have MITRE data.

---

### `POST /analyze/manual`

Accepts a JSON body matching the `ManualFlowInput` schema and returns a single prediction.

**Why validate before the model?**
```python
try:
    validate_flow_input(flow_dict)
except ValueError as ve:
    raise HTTPException(status_code=400, detail=str(ve))
```

The ML model will accept garbage input and produce garbage output. We validate first to give the user a clear error message rather than a confusing prediction.

---

## 2️⃣ `live.py` — Live Capture & SSE Streaming

This file handles everything related to real-time packet capture: starting/stopping the capture, streaming classified flows to the browser, and managing log files.

### Endpoints

| Method | Path | What it does |
|--------|------|-------------|
| `GET` | `/live/stream` | SSE stream of ML-classified live flows |
| `POST` | `/live/start` | Start capturing on an interface |
| `POST` | `/live/stop` | Stop the running capture |
| `GET` | `/live/status` | Current capture state |
| `GET` | `/live/interfaces` | List available network interfaces |
| `GET` | `/live/logs` | List downloadable log files |
| `GET` | `/live/logs/{filename}` | Download a specific log CSV |

---

### Understanding SSE (Server-Sent Events)

The browser opens a persistent HTTP connection to `/live/stream`. The server keeps that connection open and pushes data as it becomes available — like a one-way WebSocket.

Each message looks like:
```
data: {"id": "live_abc123", "src_ip": "192.168.1.5", "prediction": "Malicious", ...}\n\n
```

The double newline `\n\n` is the SSE message delimiter — the browser's `EventSource` API splits on this.

**Why SSE instead of WebSockets?**
- SSE is simpler: one direction (server → client), built-in reconnect, works over standard HTTP
- WebSockets are bidirectional — overkill for a read-only stream
- SSE works through HTTP/2 multiplexing on the cloud (nginx, ALB)

---

### `_format_result()` — The Frontend Contract

```python
def _format_result(flow: dict, pred: dict) -> dict:
    raw_proto = flow.get("proto", 0)
    proto_str = _PROTO_NAMES.get(int(raw_proto), str(raw_proto))  # 6 → "TCP"

    return {
        "id": f"live_{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now().isoformat(),
        "src_ip": ..., "dst_ip": ...,
        "sport": ..., "dport": ...,
        "protocol": proto_str,
        "duration": round(float(flow.get("dur", 0)), 3),
        "prediction": pred["prediction"],
        "confidence": round(pred["confidence"], 4),
        "severity": pred["severity"],
        "attack_type": pred.get("attack_type"),
    }
```

This function is the **contract** between backend and frontend. The TypeScript `LivePacket` interface on the frontend mirrors this shape exactly. If you add a field here, add it to the TypeScript type too.

**Why `uuid.hex[:12]`?** Full UUIDs are 36 characters. We only need uniqueness within a session — 12 hex chars (48 bits of entropy) is more than enough.

---

### `_classify_live_flow()` — The ML Pipeline for Live Flows

```python
def _classify_live_flow(flow: dict, model_manager, data_standardizer, mitre_mapper=None) -> dict:
    df = data_standardizer.from_live_flow(flow)   # 1. Clean & standardize
    predictions = model_manager.predict(df)        # 2. Run ML
    result = _format_result(flow, predictions[0])  # 3. Shape for frontend
    if mitre_mapper:
        result = mitre_mapper.enrich_prediction(result)  # 4. Add MITRE data
    else:
        result["mitre"] = None
    return result
```

This is called once per completed flow. It's synchronous (runs in the asyncio event loop), which is fine because ML inference is fast (~1ms per flow).

---

### `_stream_from_capture()` — The SSE Generator

```python
async def _stream_from_capture(capture, model_manager, data_standardizer, traffic_logger, mitre_mapper=None):
    while capture.is_running:
        try:
            flow = await asyncio.wait_for(capture.queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            continue  # No flow ready yet, loop again

        if flow is None:
            break  # Sentinel value — capture was stopped

        result = _classify_live_flow(flow, model_manager, data_standardizer, mitre_mapper)
        traffic_logger.log(result)
        yield f"data: {json.dumps(result)}\n\n"
```

**Key design decisions:**

- `asyncio.wait_for(..., timeout=1.0)` — We don't block forever waiting for a flow. Every second, we check if the capture is still running. This allows the generator to exit cleanly when the user stops the capture.
- `flow is None` — The `CaptureManager` pushes `None` onto the queue as a sentinel when it stops. This signals the generator to exit.
- `yield` — This is an async generator. FastAPI's `StreamingResponse` consumes it, sending each yielded string as an SSE message.

---

### `POST /live/start`

```python
@router.post("/live/start")
async def start_capture(request: Request, interface: Optional[str] = None):
    if capture.is_running:
        raise HTTPException(status_code=409, detail="Capture is already running")

    if not check_pcap_available():
        raise HTTPException(status_code=503, detail="pcap library not available...")

    capture.start(interface)
    logger.start_session()
```

**Why 409 Conflict?** Starting a second capture while one is running would be a bug. 409 is the semantically correct HTTP status for "this action conflicts with the current state."

**Why check pcap?** On Linux EC2 (future deployment), you need `libpcap`. On Windows, you need Npcap. If neither is installed, we fail fast with a helpful message instead of a cryptic OS error.

---

### `POST /live/stop`

```python
@router.post("/live/stop")
async def stop_capture(request: Request):
    was_running = capture.is_running
    capture.stop()
    logger.close()
    return {"status": "stopped", "was_running": was_running, ...}
```

**Always returns 200.** Even if no capture was running. The frontend calls this on page unload as a cleanup — it shouldn't error just because the user already stopped it manually.

---

### `GET /live/logs/{filename}` — Secure File Download

```python
@router.get("/live/logs/{filename}")
async def download_log(request: Request, filename: str):
    path = logger.get_log_path(filename)  # Validates path internally
    if not path:
        raise HTTPException(status_code=404, detail="Log file not found")
    return FileResponse(path=str(path), media_type="text/csv", filename=filename)
```

The security check happens inside `TrafficLogger.get_log_path()` — it strips directory traversal attempts (`../../../etc/passwd`). The API layer just checks if the result is `None`.

---

## 3️⃣ `mitre.py` — MITRE ATT&CK Endpoints

This is a small, focused router. It exposes the MITRE knowledge base to the frontend so it can render the MITRE matrix page and look up individual categories.

### Endpoints

| Method | Path | What it does |
|--------|------|-------------|
| `GET` | `/mitre/matrix` | Full MITRE matrix (all 9 attack categories with tactics/techniques) |
| `GET` | `/mitre/lookup/{category}` | Single category lookup (e.g., `/mitre/lookup/DoS`) |

---

### `_get_mapper()` — Dependency Helper

```python
def _get_mapper(request: Request) -> MitreMapper:
    mapper = getattr(request.app.state, "mitre_mapper", None)
    if mapper is None:
        raise HTTPException(status_code=503, detail="MITRE mapper not initialized")
    return mapper
```

This is a private helper used by both endpoints. Rather than repeating the `getattr` + null check in every function, we extract it once. This is the manual equivalent of FastAPI's `Depends()` injection pattern.

**Why 503 Service Unavailable?** If `mitre_mapping.json` is missing, the mapper is `None`. The service exists but a dependency is unavailable — 503 is the correct status.

---

### `GET /mitre/matrix`

```python
@router.get("/matrix")
async def get_matrix(request: Request):
    mapper = _get_mapper(request)
    return mapper.get_matrix()
```

Returns the full matrix payload:
```json
{
  "version": "1.0",
  "framework": "MITRE ATT&CK v14",
  "min_confidence": 0.70,
  "confidence_bands": { ... },
  "entries": [
    {
      "category": "DoS",
      "description": "...",
      "tactics": [ { "id": "TA0040", "name": "Impact", "techniques": [...] } ]
    },
    ...
  ]
}
```

The frontend's `MitrePage.tsx` calls this once on mount and renders the interactive matrix.

---

### `GET /mitre/lookup/{category}`

```python
@router.get("/lookup/{category}")
async def lookup_category(request: Request, category: str):
    result = mapper.lookup(category)
    if result is None:
        raise HTTPException(status_code=404, detail=f"No MITRE mapping found for category: {category}")
    return {"category": category, **result}
```

**Why `**result`?** The raw mapping dict doesn't include the category name (it's the key). We spread it and add `category` so the response is self-describing.

**Example response for `/mitre/lookup/DoS`:**
```json
{
  "category": "DoS",
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
```

---

## 4️⃣ `schemas.py` — Request Validation

```python
class ManualFlowInput(BaseModel):
    proto: Optional[str] = Field("tcp", description="Protocol (e.g., tcp, udp)")
    sport: Optional[int] = Field(0, description="Source Port")
    dsport: Optional[int] = Field(0, description="Destination Port")
    dur: Optional[float] = Field(0.0, description="Duration (seconds)")
    sbytes: Optional[int] = Field(0, description="Source Bytes")
    dbytes: Optional[int] = Field(0, description="Destination Bytes")
    spkts: Optional[int] = Field(0, description="Source Packets")
    dpkts: Optional[int] = Field(0, description="Destination Packets")
    sttl: Optional[int] = Field(0, description="Source TTL")
    dttl: Optional[int] = Field(0, description="Destination TTL")
    srcip: Optional[str] = Field(None, description="Source IP Address")
    dstip: Optional[str] = Field(None, description="Destination IP Address")
```

Pydantic automatically:
- Parses the JSON body into this model
- Validates types (e.g., `sport` must be an integer)
- Applies defaults for missing fields
- Returns a 422 Unprocessable Entity if validation fails

**Why are `srcip` / `dstip` in the schema but not passed to the model?**

The ML model doesn't use IP addresses — it would overfit to specific IPs seen in training data. IPs are only used for display purposes in the response (showing the analyst which machine was involved).

---

## 🔌 How Services Are Accessed

All core services are stored on `app.state` (set in `main.py`'s lifespan handler). Endpoints access them via `request.app.state`:

```python
model_manager = request.app.state.model_manager
data_standardizer = request.app.state.data_standardizer
mitre_mapper = getattr(request.app.state, "mitre_mapper", None)
capture = request.app.state.capture_manager
logger = request.app.state.traffic_logger
```

**Why `getattr(..., None)` for `mitre_mapper`?**

`mitre_mapper` is optional — if `mitre_mapping.json` doesn't exist, it's never set on `app.state`. Using `getattr` with a default prevents an `AttributeError` and lets the endpoint degrade gracefully (MITRE data will be `null` in responses).

**Why not use FastAPI's `Depends()` for this?**

`Depends()` is cleaner for complex dependency graphs, but for simple app-state access it adds boilerplate. The current pattern is explicit and easy to follow for juniors. Refactor to `Depends()` if the codebase grows.

---

## 🗺️ Full API Reference

```
GET  /health                      → { status: "healthy" }

GET  /predictions                 → [ ...prediction objects ]
GET  /analytics                   → { normalCount, maliciousCount, timelineData, ... }
POST /analyze/upload              → { success, total, predictions: [...] }
POST /analyze/manual              → { prediction, confidence, severity, mitre, ... }

POST /live/start?interface=Wi-Fi  → { status, interface, log_file }
POST /live/stop                   → { status, was_running, packets_captured }
GET  /live/status                 → { running, interface, packet_count, log_file }
GET  /live/stream                 → SSE stream of classified flows
GET  /live/interfaces             → [ { name, description, is_physical, ... } ]
GET  /live/logs                   → [ { filename, size_bytes, created } ]
GET  /live/logs/{filename}        → CSV file download

GET  /mitre/matrix                → { version, framework, min_confidence, entries: [...] }
GET  /mitre/lookup/{category}     → { category, description, tactics: [...] }
```

---

## 🛠️ Design Decisions

### Why no authentication?

The current scope is a local analysis tool. When deploying to EC2, add an API key header or JWT middleware in `main.py` before exposing it to the internet.

### Why in-memory predictions store?

Simple, zero-dependency, survives restarts gracefully (fresh start = clean state). The trade-off is that history is lost on restart. For production, swap `predictions_store` for a database write.

### Why not return MITRE data from `/predictions`?

`predictions_store` stores the full enriched prediction dict (including `mitre`). So `/predictions` already returns MITRE data if it was present at prediction time. No extra work needed.

### Why separate routers instead of one big file?

Single Responsibility Principle. `routes.py` handles batch analysis, `live.py` handles real-time capture, `mitre.py` handles threat intelligence. Each can be developed, tested, and reviewed independently.

---

## 📚 Further Reading

- [FastAPI documentation](https://fastapi.tiangolo.com/)
- [Server-Sent Events spec](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)
- [Pydantic v2 docs](https://docs.pydantic.dev/latest/)
- [MITRE ATT&CK framework](https://attack.mitre.org/)

**Questions?** Ask in #engineering-support on Slack.
