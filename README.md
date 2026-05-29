# Hybrid IDS Cybersecurity Platform

A high-performance **Hybrid Intrusion Detection System** combining LightGBM machine learning with Snort signature-based detection.

## 🚀 Quick Links

- **[Project Context](context.md)** — Architectural overview and technical breakdown.
- **[Setup Guide](Docs/SETUP_GUIDE.md)** — Step-by-step installation and deployment instructions.
- **[Backend API](app/)** — FastAPI implementation.
- **[Dashboard](dashboard/)** — React/Vite frontend.

## 🛠 Tech Stack

- **ML Inference**: Python, LightGBM, NFStream.
- **Backend**: FastAPI, Redis (Pub/Sub + Hashes).
- **Frontend**: React, Vite, Tailwind CSS, Framer Motion.
- **Signature Detection**: Snort 3.

## 📈 Data Pipeline

1. **Capture**: NFStream & Snort 3 monitor network interfaces.
2. **Process**: Workers extract features and tail logs to Redis.
3. **Analyze**: ML engine categorizes flows in real-time.
4. **Stream**: Results are pushed to the dashboard via SSE.
