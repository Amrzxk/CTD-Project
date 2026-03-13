<<<<<<< HEAD
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from .core.model_manager import ModelManager
from .core.data_standardizer import DataStandardizer
from .api.routes import router
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize components
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, "models")
    
    print(f"Loading models from: {models_dir}")
    
    mm = ModelManager(
        os.path.join(models_dir, "model_label_best.joblib"),
        os.path.join(models_dir, "model_attack_cat_best.joblib"),
        os.path.join(models_dir, "selected_features.json")
    )
    ds = DataStandardizer(mm.selected_features)
    
    # Store in state to avoid circular imports
    app.state.model_manager = mm
    app.state.data_standardizer = ds
    
    print("Models loaded successfully.")
    
    yield

app = FastAPI(lifespan=lifespan)

# CORS Configuration
=======
import asyncio
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .core.model_manager import ModelManager
from .core.data_standardizer import DataStandardizer
from .core.capture_manager import CaptureManager, check_pcap_available, get_pcap_install_hint
from .core.traffic_logger import TrafficLogger
from .api.routes import router
from .api.live import router as live_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    base_dir = Path(__file__).resolve().parent
    models_dir = base_dir / "models"
    logs_dir = base_dir / "logs"

    # --- ML Models ---
    label_path = models_dir / "model_label_best.joblib"
    attack_path = models_dir / "model_attack_cat_best.joblib"
    features_path = models_dir / "selected_features.json"

    print(f"Loading models from: {models_dir}")

    if not label_path.exists() or not attack_path.exists():
        print("WARNING: Model files not found — API will refuse /live/stream requests.")
        app.state.model_manager = None
        app.state.data_standardizer = None
    else:
        mm = ModelManager(str(label_path), str(attack_path), str(features_path))
        ds = DataStandardizer(mm.selected_features)
        app.state.model_manager = mm
        app.state.data_standardizer = ds
        print("Models loaded successfully.")

    # --- pcap availability ---
    if check_pcap_available():
        print("pcap library detected — live capture available.")
    else:
        print(f"WARNING: {get_pcap_install_hint()}")

    # --- Capture manager & traffic logger ---
    loop = asyncio.get_running_loop()
    app.state.capture_manager = CaptureManager(loop)
    app.state.traffic_logger = TrafficLogger(logs_dir)

    yield

    # Cleanup on shutdown
    if app.state.capture_manager.is_running:
        app.state.capture_manager.stop()
    app.state.traffic_logger.close()


app = FastAPI(lifespan=lifespan)

>>>>>>> 260c5da33751fd3b387bc26d584989d6a0489685
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

<<<<<<< HEAD
# Health Check Endpoint
=======

>>>>>>> 260c5da33751fd3b387bc26d584989d6a0489685
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

<<<<<<< HEAD
app.include_router(router)
=======

app.include_router(router)
app.include_router(live_router)
>>>>>>> 260c5da33751fd3b387bc26d584989d6a0489685
