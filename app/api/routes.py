from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from .schemas import ManualFlowInput
from app.utils.validators import validate_flow_input
import shutil
import os
import uuid

router = APIRouter()

@router.post("/analyze/upload")
async def analyze_upload(request: Request, file: UploadFile = File(...)):
    
    # Access initialized services from app state
    if not hasattr(request.app.state, "model_manager") or not hasattr(request.app.state, "data_standardizer"):
        raise HTTPException(status_code=503, detail="Services not initialized")
        
    model_manager = request.app.state.model_manager
    data_standardizer = request.app.state.data_standardizer

    # Validate file extension
    filename = file.filename or "unknown"
    ext = filename.split(".")[-1].lower()
    
    # Create a unique temp file to avoid collisions
    temp_filename = f"temp_{uuid.uuid4()}.{ext}"
    
    try:
        with open(temp_filename, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        if ext == "csv":
            df = data_standardizer.from_csv(temp_filename)
        elif ext in ["xlsx", "xls"]:
            df = data_standardizer.from_excel(temp_filename)
        elif ext in ["pcap", "pcapng"]:
            df = data_standardizer.from_pcap(temp_filename)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported file format: {ext}")

        # Predict
        predictions = model_manager.predict(df)

        return {
            "filename": filename,
            "total_flows": len(predictions) if isinstance(predictions, list) else len(df),
            "results": predictions
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

@router.post("/analyze/manual")
async def analyze_manual(request: Request, flow: ManualFlowInput):
    """
    Accepts manually entered network flow features from the user and returns the prediction results.
    """
    # Access initialized services from app state
    if not hasattr(request.app.state, "model_manager") or not hasattr(request.app.state, "data_standardizer"):
        raise HTTPException(status_code=503, detail="Services not initialized")
        
    model_manager = request.app.state.model_manager
    data_standardizer = request.app.state.data_standardizer

    try:
        # Convert input model to dict (handle Pydantic v1/v2 compatibility)
        if hasattr(flow, "model_dump"):
            flow_dict = flow.model_dump()
        else:
            flow_dict = flow.dict()
            
        # Validate input
        try:
            validate_flow_input(flow_dict)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        
        # Process using DataStandardizer
        # We wrap it in a list because from_records expects a list of dicts
        df = data_standardizer.from_records([flow_dict])
        
        # Predict
        predictions = model_manager.predict(df)
        
        return {
            "total_flows": 1,
            "results": predictions
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
