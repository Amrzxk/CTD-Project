import joblib
import json
import numpy as np
import pandas as pd

class ModelManager:
    def __init__(self, binary_path, multi_path, features_path):
        self.binary_model = joblib.load(binary_path)
        self.multi_model = joblib.load(multi_path)

        with open(features_path) as f:
            self.selected_features = json.load(f)

    def predict(self, df):
        # Ensure we have the correct columns in the correct order
        X = df[self.selected_features]

        # Predict binary labels (0=Normal, 1=Attack)
        binary_pred = self.binary_model.predict(X)
        binary_proba = self.binary_model.predict_proba(X)

        # Predict multi-class for all rows (batch processing is more efficient)
        multi_pred = self.multi_model.predict(X)
        multi_proba = self.multi_model.predict_proba(X)

        results = []

        for i in range(len(df)):
            is_attack = (binary_pred[i] == 1)
            confidence = float(binary_proba[i].max())
            
            prediction = "Malicious" if is_attack else "Normal"
            
            # Severity logic matching frontend
            severity = None
            if is_attack:
                if confidence > 0.9:
                    severity = "High"
                elif confidence > 0.8:
                    severity = "Medium"
                else:
                    severity = "Low"

            result = {
                "prediction": prediction,
                "confidence": confidence,
                "severity": severity,
                
                # Additional internal details if needed
                "attack_type": str(multi_pred[i]) if is_attack else None,

                # Metadata
                "sourceIp": df.iloc[i].get("srcip", "N/A"),
                "destinationIp": df.iloc[i].get("dstip", "N/A"),
                "sourcePort": int(df.iloc[i].get("sport", 0)),
                "destinationPort": int(df.iloc[i].get("dsport", 0)),
                "protocol": str(df.iloc[i].get("proto", "N/A")),
                "packetSize": int(df.iloc[i].get("sbytes", 0)),
                "duration": float(df.iloc[i].get("dur", 0.0))
            }

            results.append(result)

        return results
