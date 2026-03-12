from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from .schemas import ManualFlowInput
from app.utils.validators import validate_flow_input
import shutil
import os
import uuid
from datetime import datetime

router = APIRouter()

# In-memory store for predictions
predictions_store = []

@router.get("/predictions")
async def get_predictions():
    """
    Returns all historical predictions stored in memory.
    """
    # Return most recent first
    return list(reversed(predictions_store))

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
        
        # Format for frontend BatchPredictionResult
        formatted_predictions = []
        for i, pred in enumerate(predictions):
            # We use metadata from the prediction result if available (ModelManager now returns it)
            # Otherwise we use defaults.
            prediction_obj = {
                "id": f"batch_{uuid.uuid4()}_{i}",
                "timestamp": datetime.now().isoformat(),
                "sourceIp": pred.get("sourceIp", "N/A"),
                "destinationIp": pred.get("destinationIp", "N/A"),
                "sourcePort": pred.get("sourcePort", 0),
                "destinationPort": pred.get("destinationPort", 0),
                "protocol": pred.get("protocol", "N/A"),
                "packetSize": pred.get("packetSize", 0),
                "duration": pred.get("duration", 0),
                
                "prediction": pred["prediction"],
                "attack_type": pred.get("attack_type"),
                "confidence": pred["confidence"],
                "severity": pred["severity"]
            }
            formatted_predictions.append(prediction_obj)
            
        # Store predictions in memory
        predictions_store.extend(formatted_predictions)

        return {
            "success": True,
            "total": len(formatted_predictions),
            "predictions": formatted_predictions
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
        
        if not predictions:
             raise HTTPException(status_code=500, detail="No prediction returned")
             
        result = predictions[0]
        
        # Construct ThreatPrediction object
        response = {
            "id": f"manual_{uuid.uuid4()}",
            "timestamp": datetime.now().isoformat(),
            "sourceIp": flow_dict.get("srcip") or "N/A",
            "destinationIp": flow_dict.get("dstip") or "N/A",
            "sourcePort": flow_dict.get("sport", 0),
            "destinationPort": flow_dict.get("dsport", 0),
            "protocol": flow_dict.get("proto", "N/A"),
            "packetSize": flow_dict.get("sbytes", 0), # Approximation
            "duration": flow_dict.get("dur", 0),
            
            "prediction": result["prediction"],
            "attack_type": result.get("attack_type"),
            "confidence": result["confidence"],
            "severity": result["severity"]
        }
        
        # Store prediction in memory
        predictions_store.append(response)
        
        return response
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
