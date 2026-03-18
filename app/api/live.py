import asyncio
import json
import threading
import uuid
from collections import deque
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from app.core.capture_manager import CaptureManager, list_interfaces, check_pcap_available

router = APIRouter(prefix="/live", tags=["live"])


_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
_PROTO_STR_UPPER = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}


# ---------------------------------------------------------------------------
# CT Feature Window
# ---------------------------------------------------------------------------

class FlowWindow:
    """
    Rolling window of recent completed flows used to compute CT (connection-
    tracking) features for each new flow before ML classification.

    The UNSW-NB15 model was trained with CT features computed over a sliding
    window of flows in the dataset (e.g. ct_src_ltm = how many times this
    source IP appeared in the last N flows). For live capture we cannot
    reproduce the exact training window, but a 200-flow rolling deque gives
    the model meaningful context instead of all-zeros.

    Thread-safe: the capture background thread and the asyncio event loop
    both call enrich_and_add concurrently.
    """

    WINDOW_SIZE = 200

    def __init__(self):
        self._window: deque[dict] = deque(maxlen=self.WINDOW_SIZE)
        self._lock = threading.Lock()

    def enrich_and_add(self, flow: dict) -> dict:
        """
        Compute CT features from the current window, return an enriched copy
        of the flow, then add it to the window for future flows.
        """
        with self._lock:
            w = list(self._window)

            src  = flow.get("srcip")
            dst  = flow.get("dstip")
            svc  = flow.get("service")
            dsp  = flow.get("dsport")
            sp   = flow.get("sport")
            st   = flow.get("state")
            sttl = flow.get("sttl")

            enriched = {
                **flow,
                "ct_src_ltm":       sum(1 for f in w if f.get("srcip") == src),
                "ct_dst_ltm":       sum(1 for f in w if f.get("dstip") == dst),
                "ct_srv_src":       sum(1 for f in w if f.get("srcip") == src  and f.get("service") == svc),
                "ct_srv_dst":       sum(1 for f in w if f.get("dstip") == dst  and f.get("service") == svc),
                "ct_src_dport_ltm": sum(1 for f in w if f.get("srcip") == src  and f.get("dsport")  == dsp),
                "ct_dst_sport_ltm": sum(1 for f in w if f.get("dstip") == dst  and f.get("sport")   == sp),
                "ct_dst_src_ltm":   sum(1 for f in w if f.get("srcip") == src  and f.get("dstip")   == dst),
                "ct_state_ttl":     sum(1 for f in w if f.get("state") == st   and f.get("sttl")    == sttl),
            }

            self._window.append(enriched)
            return enriched

    def reset(self):
        """Clear the window at the start of each capture session."""
        with self._lock:
            self._window.clear()


def _format_result(flow: dict, pred: dict) -> dict:
    """Shape a classified flow into the LivePacket frontend contract."""
    raw_proto = flow.get("proto", 0)
    if isinstance(raw_proto, str):
        proto_str = _PROTO_STR_UPPER.get(raw_proto.lower(), raw_proto.upper())
    else:
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
        # ML features preserved for log re-upload consistency
        "sttl": int(flow.get("sttl", 0)),
        "dttl": int(flow.get("dttl", 0)),
        "sload": round(float(flow.get("sload", 0)), 4),
        "dload": round(float(flow.get("dload", 0)), 4),
        "swin": int(flow.get("swin", 0)),
        "dwin": int(flow.get("dwin", 0)),
        "stcpb": int(flow.get("stcpb", 0)),
        "dtcpb": int(flow.get("dtcpb", 0)),
        "smeansz": round(float(flow.get("smeansz", 0)), 4),
        "dmeansz": round(float(flow.get("dmeansz", 0)), 4),
        "sjit": round(float(flow.get("sjit", 0)), 6),
        "djit": round(float(flow.get("djit", 0)), 6),
        "sintpkt": round(float(flow.get("sintpkt", 0)), 6),
        "dintpkt": round(float(flow.get("dintpkt", 0)), 6),
        "tcprtt": round(float(flow.get("tcprtt", 0)), 6),
        "synack": round(float(flow.get("synack", 0)), 6),
        "ackdat": round(float(flow.get("ackdat", 0)), 6),
        "is_sm_ips_ports": int(flow.get("is_sm_ips_ports", 0)),
        # Classification results
        "prediction": pred["prediction"],
        "confidence": round(pred["confidence"], 4),
        "severity": pred["severity"],
        "attack_type": pred.get("attack_type"),
    }


def _classify_live_flow(
    flow: dict,
    model_manager,
    data_standardizer,
    flow_window: FlowWindow,
    mitre_mapper=None,
) -> dict:
    """
    Run a single live-captured flow through the ML pipeline.

    The flow is first enriched with CT features computed from the rolling
    FlowWindow before being passed to the data standardizer, giving the model
    the same kind of context it had during training.
    """
    enriched = flow_window.enrich_and_add(flow)
    df = data_standardizer.from_live_flow(enriched)
    predictions = model_manager.predict(df)
    result = _format_result(enriched, predictions[0])
    if mitre_mapper:
        result = mitre_mapper.enrich_prediction(result)
    else:
        result["mitre"] = None
    return result


# ---------------------------------------------------------------------------
# SSE Stream
# ---------------------------------------------------------------------------

async def _stream_from_capture(
    capture: CaptureManager,
    model_manager,
    data_standardizer,
    traffic_logger,
    flow_window: FlowWindow,
    mitre_mapper=None,
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

            result = _classify_live_flow(flow, model_manager, data_standardizer, flow_window, mitre_mapper)
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
    flow_window: FlowWindow = request.app.state.flow_window
    mitre = getattr(request.app.state, "mitre_mapper", None)

    if not capture or not capture.is_running:
        raise HTTPException(status_code=409, detail="Capture is not running. POST /live/start first.")
    if mm is None or ds is None:
        raise HTTPException(status_code=503, detail="ML models not loaded")

    return StreamingResponse(
        _stream_from_capture(capture, mm, ds, logger, flow_window, mitre),
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
    flow_window: FlowWindow = request.app.state.flow_window

    if capture.is_running:
        raise HTTPException(status_code=409, detail="Capture is already running")

    if not check_pcap_available():
        raise HTTPException(status_code=503, detail="pcap library not available. Install Npcap (Windows) or libpcap (Linux).")

    try:
        flow_window.reset()
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
