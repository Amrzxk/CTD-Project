# Project Context: SOC Cybersecurity Analysis Platform

## Project Overview

A web-based cybersecurity analysis platform that allows SOC analysts to upload network traffic data and receive automated AI-based threat detection and analysis.

The system analyzes network traffic using a machine learning model trained on the **UNSW-NB15 dataset**, detecting malicious behavior and classifying attacks into predefined categories. The goal is to **assist analysts, not replace them**, by automating initial traffic inspection and providing contextual intelligence.

---

## Core Capabilities

1. **Packet Classification** — Benign vs. Malicious
2. **Attack Classification** — 9 attack categories from the UNSW-NB15 dataset
3. **AI-Generated Threat Explanation** — Human-readable narratives for detected threats
4. **Visualization Dashboard** — Traffic statistics, charts, and graphs
5. **MITRE ATT&CK Mapping** — Maps detected attacks to tactics and techniques
6. **Integrated Chatbot** — Analyst Q&A interface for contextual questions

---

## Domain Level

**Application-Level Domain** — self-contained, not global.

- Defined boundaries: upload → analyze → report
- Does not span multiple independent systems or organizations
- All components (ML model, AI chatbot, dashboard, MITRE mapping) serve a single bounded context: SOC traffic analysis
- Global domain would only apply if this were a multi-tenant SaaS product — which is out of scope

---

## Architecture: 3-Tier Structure

```
Presentation (Frontend) → Application (Backend) → Data / Intelligence
```

---

### 1. Frontend — Presentation Tier

**Tech:** React.js (SPA)

| Component | Description |
|---|---|
| Upload Module | Accepts `.pcap`, `.csv`, `.log` files |
| Dashboard | Traffic visualizations (charts, graphs, stats) |
| Threat Report Panel | Per-packet / per-session classification results |
| MITRE ATT&CK Panel | Mapped tactics and techniques |
| Chatbot Widget | Analyst Q&A interface |
| Alert Feed | Real-time or batch malicious event list |

---

### 2. Backend — Application Tier

**Tech:** Python — FastAPI

| Module | Responsibility |
|---|---|
| File Ingestion Service | Validates, parses, and normalizes uploaded files |
| Feature Extraction Engine | Converts raw traffic into UNSW-NB15 feature vectors (47 features: `dur`, `proto`, `service`, `state`, `sbytes`, `dbytes`, etc.) |
| ML Inference Engine | Runs the trained model (binary + multiclass) |
| Explanation Engine | Generates human-readable threat narratives (open source LLM) |
| MITRE Mapper | Maps attack category → ATT&CK Tactic/Technique |
| Chatbot Handler | Manages analyst conversation context |
| Report Aggregator | Compiles session-level summary statistics |

---

### 3. Intelligence Tier

#### ML Layer (local / self-hosted)
- **Binary Classifier:** Benign vs. Malicious
- **Multiclass Classifier:** 9 attack categories:
  - Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms
- **Model Format:** scikit-learn / XGBoost / Random Forest (`.pkl` or ONNX)

#### LLM Layer
- Threat explanation generation
- Chatbot reasoning engine
- MITRE ATT&CK context enrichment

---

### 4. Data Tier

| Component | Details |
|---|---|
| File Storage | Temporary uploaded file buffer (local disk or S3) |
| MITRE ATT&CK Knowledge Base | Static JSON/STIX dataset (MITRE CTI repo) |