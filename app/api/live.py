import asyncio
import json
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from app.core.capture_manager import CaptureManager, list_interfaces, check_pcap_available

router = APIRouter(prefix="/live", tags=["live"])


_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def _format_result(flow: dict, pred: dict) -> dict:
    """Shape a classified flow into the LivePacket frontend contract."""
    raw_proto = flow.get("proto", 0)
    proto_str = _PROTO_NAMES.get(int(raw_proto), str(raw_proto))

    return {
        "id": f"live_{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now().isoformat(),
        "src_ip": str(flow.get("srcip", "N/A")),
        "dst_ip": str(flow.get("dstip", "N/A")),
        "sport": int(flow.get("sport", 0)),
        "dport": int(flow.get("dsport", 0)),
        "protocol": proto_str,
        "service": str(flow.get("service", "-")),
        "state": str(flow.get("state", "CON")),
        "duration": round(float(flow.get("dur", 0)), 3),
        "sbytes": int(flow.get("sbytes", 0)),
        "dbytes": int(flow.get("dbytes", 0)),
        "spkts": int(flow.get("spkts", 0)),
        "dpkts": int(flow.get("dpkts", 0)),
        "prediction": pred["prediction"],
        "confidence": round(pred["confidence"], 4),
        "severity": pred["severity"],
        "attack_type": pred.get("attack_type"),
    }


def _classify_live_flow(flow: dict, model_manager, data_standardizer) -> dict:
    """Run a single live-captured flow through the ML pipeline."""
    df = data_standardizer.from_live_flow(flow)
    predictions = model_manager.predict(df)
    return _format_result(flow, predictions[0])


# ---------------------------------------------------------------------------
# SSE Stream
# ---------------------------------------------------------------------------

async def _stream_from_capture(
    capture: CaptureManager,
    model_manager,
    data_standardizer,
    traffic_logger,
):
    """Async generator: pull flows from the capture queue, classify, yield SSE."""
    try:
        while capture.is_running:
            try:
                flow = await asyncio.wait_for(capture.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            if flow is None:
                break

            result = _classify_live_flow(flow, model_manager, data_standardizer)
            traffic_logger.log(result)
            yield f"data: {json.dumps(result)}\n\n"
    except asyncio.CancelledError:
        return


@router.get("/stream")
async def live_stream(request: Request):
    """SSE endpoint — streams ML-classified packets from the live capture."""
    capture: Optional[CaptureManager] = getattr(request.app.state, "capture_manager", None)
    mm = request.app.state.model_manager
    ds = request.app.state.data_standardizer
    logger = request.app.state.traffic_logger

    if not capture or not capture.is_running:
        raise HTTPException(status_code=409, detail="Capture is not running. POST /live/start first.")
    if mm is None or ds is None:
        raise HTTPException(status_code=503, detail="ML models not loaded")

    return StreamingResponse(
        _stream_from_capture(capture, mm, ds, logger),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Capture lifecycle
# ---------------------------------------------------------------------------

@router.post("/start")
async def start_capture(request: Request, interface: Optional[str] = None):
    """Start live capture on the given (or auto-detected) interface."""
    capture: CaptureManager = request.app.state.capture_manager
    logger = request.app.state.traffic_logger

    if capture.is_running:
        raise HTTPException(status_code=409, detail="Capture is already running")

    if not check_pcap_available():
        raise HTTPException(status_code=503, detail="pcap library not available. Install Npcap (Windows) or libpcap (Linux).")

    try:
        capture.start(interface)
        logger.start_session()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "status": "started",
        "interface": capture.interface,
        "log_file": logger.current_file,
    }


@router.post("/stop")
async def stop_capture(request: Request):
    """Stop the running capture. Returns OK even if already stopped."""
    capture: CaptureManager = request.app.state.capture_manager
    logger = request.app.state.traffic_logger

    was_running = capture.is_running
    capture.stop()
    logger.close()

    return {
        "status": "stopped",
        "was_running": was_running,
        "packets_captured": capture.packet_count,
    }


@router.get("/status")
async def capture_status(request: Request):
    """Return current capture state."""
    capture: CaptureManager = request.app.state.capture_manager
    logger = request.app.state.traffic_logger

    return {
        "running": capture.is_running,
        "interface": capture.interface,
        "packet_count": capture.packet_count,
        "log_file": logger.current_file,
    }


# ---------------------------------------------------------------------------
# Network interfaces
# ---------------------------------------------------------------------------

@router.get("/interfaces")
async def get_interfaces():
    """List available network interfaces."""
    try:
        return list_interfaces()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Log file management
# ---------------------------------------------------------------------------

@router.get("/logs")
async def get_logs(request: Request):
    """List all available traffic log files."""
    logger = request.app.state.traffic_logger
    return logger.get_log_files()


@router.get("/logs/{filename}")
async def download_log(request: Request, filename: str):
    """Download a specific traffic log CSV."""
    logger = request.app.state.traffic_logger
    path = logger.get_log_path(filename)

    if not path:
        raise HTTPException(status_code=404, detail="Log file not found")

    return FileResponse(
        path=str(path),
        media_type="text/csv",
        filename=filename,
    )
