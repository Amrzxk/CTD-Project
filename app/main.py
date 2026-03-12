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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health Check Endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

app.include_router(router)
