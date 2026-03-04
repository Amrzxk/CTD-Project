from fastapi import FastAPI
from contextlib import asynccontextmanager
from .core.model_manager import ModelManager
from .core.data_standardizer import DataStandardizer
from .api.routes import router
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize components
    # Using your specific selected features and models
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
    
    # Debug: Print registered routes
    print("Registered Routes:")
    for route in app.routes:
        print(f" - {route.path} [{route.name}]")
        
    yield

app = FastAPI(lifespan=lifespan)
app.include_router(router)
