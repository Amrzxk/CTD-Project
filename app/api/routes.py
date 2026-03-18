from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from .schemas import ManualFlowInput
from app.utils.validators import validate_flow_input
from datetime import datetime, timedelta
from collections import Counter
import shutil
import os
import uuid

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

@router.get("/analytics")
async def get_analytics(request: Request):
    """
    Aggregates in-memory predictions into analytics statistics.
    """
    normal_count = 0
    malicious_count = 0
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    attack_categories_counter = Counter()
    malicious_ips = Counter()
    protocol_distribution_counter = Counter()

    # Timeline data: progressive prediction events generating wave spikes
    timeline_data = []
    
    for i in range(len(predictions_store)):
        pred = predictions_store[i]
        try:
            # Protocol distribution
            if pred.get("protocol"):
                protocol_dist_key = str(pred["protocol"]).upper()
                protocol_distribution_counter[protocol_dist_key] += 1
            
            is_normal = pred.get("prediction") == "Normal"
            if is_normal:
                normal_count += 1
            else:
                malicious_count += 1
                     
                source_ip = pred.get("sourceIp")
                if source_ip:
                    malicious_ips[source_ip] += 1
                
                # Severity
                sev = pred.get("severity", "").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                    
                # Attack category
                attack_type = pred.get("attack_type")
                if attack_type:
                    attack_categories_counter[attack_type] += 1
        except Exception:
            pass

    # Timeline data
    total_preds = len(predictions_store)
    if total_preds > 0:
        num_bins = 20
        bin_size = max(1, total_preds // num_bins)
        actual_bins = (total_preds + bin_size - 1) // bin_size
        
        for b in range(actual_bins):
            start_idx = b * bin_size
            end_idx = min(total_preds, (b + 1) * bin_size)
            batch = predictions_store[start_idx:end_idx]
            
            batch_normal = sum(1 for p in batch if p.get("prediction") == "Normal")
            batch_suspicious = sum(1 for p in batch if p.get("prediction") == "Malicious")
            
            timeline_data.append({
                "step": b + 1,
                "normal": batch_normal,
                "suspicious": batch_suspicious
            })

    top_malicious_ips = [{"ip": ip, "count": count} for ip, count in malicious_ips.most_common(5)]
    
    colors = ['#ff3366', '#00ccff', '#ffaa00', '#00ff88', '#cc66ff', '#ff6633', '#33ccff', '#33ffaa']
    attack_categories = []
    for i, (name, count) in enumerate(attack_categories_counter.items()):
        attack_categories.append({
            "name": name,
            "value": count,
            "color": colors[i % len(colors)]
        })
        
    proto_colors = {"TCP": "#00ff88", "UDP": "#00ccff", "ICMP": "#ff3366"}
    base_colors = ['#ffaa00', '#cc66ff', '#ff6633', '#33ccff']
    protocol_distribution = []
    for idx, (name, count) in enumerate(protocol_distribution_counter.items()):
        protocol_distribution.append({
            "name": name,
            "count": count,
            "color": proto_colors.get(name, base_colors[idx % len(base_colors)])
        })
        
    features = [
        "sbytes","dbytes","dur","spkts","dpkts",
        "sload","dload","ct_srv_dst","sttl","dttl"
    ]
    
    feature_totals = {f: 0.0 for f in features}
    count_features = 0
    
    for p in predictions_store:
        mf = p.get("mlFeatures")
        if mf:
            count_features += 1
            for f in features:
                feature_totals[f] += float(mf.get(f, 0.0))
                
    feature_importance = []
    if count_features > 0:
        for f in features:
            feature_importance.append({
                "feature": f,
                "importance": feature_totals[f] / count_features
            })
    else:
        feature_importance = [{"feature": f, "importance": 0.0} for f in features]

    return {
        "normalCount": normal_count,
        "maliciousCount": malicious_count,
        "timelineData": timeline_data,
        "topMaliciousIPs": top_malicious_ips,
        "severityCounts": severity_counts,
        "attackCategories": attack_categories,
        "protocolDistribution": protocol_distribution,
        "featureImportance": feature_importance
    }

@router.post("/analyze/upload")
async def analyze_upload(request: Request, file: UploadFile = File(...)):
    if not hasattr(request.app.state, "model_manager") or not hasattr(request.app.state, "data_standardizer"):
        raise HTTPException(status_code=503, detail="Services not initialized")
        
    model_manager = request.app.state.model_manager
    data_standardizer = request.app.state.data_standardizer
    mitre_mapper = getattr(request.app.state, "mitre_mapper", None)

    filename = file.filename or "unknown"
    ext = filename.split(".")[-1].lower()
    
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

        predictions = model_manager.predict(df)
        
        formatted_predictions = []
        for i, pred in enumerate(predictions):
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
                "severity": pred["severity"],
                "mlFeatures": {
                    "sbytes": float(df.iloc[i].get("sbytes", 0) if i < len(df) and "sbytes" in df.columns else 0),
                    "dbytes": float(df.iloc[i].get("dbytes", 0) if i < len(df) and "dbytes" in df.columns else 0),
                    "dur": float(df.iloc[i].get("dur", 0) if i < len(df) and "dur" in df.columns else 0),
                    "spkts": float(df.iloc[i].get("spkts", 0) if i < len(df) and "spkts" in df.columns else 0),
                    "dpkts": float(df.iloc[i].get("dpkts", 0) if i < len(df) and "dpkts" in df.columns else 0),
                    "sload": float(df.iloc[i].get("sload", 0) if i < len(df) and "sload" in df.columns else 0),
                    "dload": float(df.iloc[i].get("dload", 0) if i < len(df) and "dload" in df.columns else 0),
                    "ct_srv_dst": float(df.iloc[i].get("ct_srv_dst", 0) if i < len(df) and "ct_srv_dst" in df.columns else 0),
                    "sttl": float(df.iloc[i].get("sttl", 0) if i < len(df) and "sttl" in df.columns else 0),
                    "dttl": float(df.iloc[i].get("dttl", 0) if i < len(df) and "dttl" in df.columns else 0)
                }
            }
            if mitre_mapper:
                prediction_obj = mitre_mapper.enrich_prediction(prediction_obj)
            else:
                prediction_obj["mitre"] = None
            formatted_predictions.append(prediction_obj)
            
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
    if not hasattr(request.app.state, "model_manager") or not hasattr(request.app.state, "data_standardizer"):
        raise HTTPException(status_code=503, detail="Services not initialized")
        
    model_manager = request.app.state.model_manager
    data_standardizer = request.app.state.data_standardizer
    mitre_mapper = getattr(request.app.state, "mitre_mapper", None)

    try:
        if hasattr(flow, "model_dump"):
            flow_dict = flow.model_dump()
        else:
            flow_dict = flow.dict()
            
        try:
            validate_flow_input(flow_dict)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        
        df = data_standardizer.from_records([flow_dict])
        
        predictions = model_manager.predict(df)
        
        if not predictions:
             raise HTTPException(status_code=500, detail="No prediction returned")
             
        result = predictions[0]
        
        response = {
            "id": f"manual_{uuid.uuid4()}",
            "timestamp": datetime.now().isoformat(),
            "sourceIp": flow_dict.get("srcip") or "N/A",
            "destinationIp": flow_dict.get("dstip") or "N/A",
            "sourcePort": flow_dict.get("sport", 0),
            "destinationPort": flow_dict.get("dsport", 0),
            "protocol": flow_dict.get("proto", "N/A"),
            "packetSize": flow_dict.get("sbytes", 0),
            "duration": flow_dict.get("dur", 0),
            
            "prediction": result["prediction"],
            "attack_type": result.get("attack_type"),
            "confidence": result["confidence"],
            "severity": result["severity"],
            "mlFeatures": {
                "sbytes": float(df.iloc[0].get("sbytes", 0) if "sbytes" in df.columns else 0),
                "dbytes": float(df.iloc[0].get("dbytes", 0) if "dbytes" in df.columns else 0),
                "dur": float(df.iloc[0].get("dur", 0) if "dur" in df.columns else 0),
                "spkts": float(df.iloc[0].get("spkts", 0) if "spkts" in df.columns else 0),
                "dpkts": float(df.iloc[0].get("dpkts", 0) if "dpkts" in df.columns else 0),
                "sload": float(df.iloc[0].get("sload", 0) if "sload" in df.columns else 0),
                "dload": float(df.iloc[0].get("dload", 0) if "dload" in df.columns else 0),
                "ct_srv_dst": float(df.iloc[0].get("ct_srv_dst", 0) if "ct_srv_dst" in df.columns else 0),
                "sttl": float(df.iloc[0].get("sttl", 0) if "sttl" in df.columns else 0),
                "dttl": float(df.iloc[0].get("dttl", 0) if "dttl" in df.columns else 0)
            }
        }
        
        if mitre_mapper:
            response = mitre_mapper.enrich_prediction(response)
        else:
            response["mitre"] = None

        predictions_store.append(response)
        
        return response
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
