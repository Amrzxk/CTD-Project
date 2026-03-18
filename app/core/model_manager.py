import joblib
import json
import numpy as np
import pandas as pd

ATTACK_THRESHOLD = 0.70


class ModelManager:
    def __init__(self, binary_path, multi_path, features_path):
        self.binary_model = joblib.load(binary_path)
        self.multi_model = joblib.load(multi_path)

        with open(features_path) as f:
            self.selected_features = json.load(f)

        self._attack_idx = list(self.binary_model.classes_).index(1)

    def predict(self, df):
        X = df[self.selected_features]

        binary_proba = self.binary_model.predict_proba(X)
        multi_pred = self.multi_model.predict(X)

        results = []

        for i in range(len(df)):
            attack_prob = float(binary_proba[i][self._attack_idx])
            is_attack = attack_prob >= ATTACK_THRESHOLD
            confidence = attack_prob if is_attack else (1.0 - attack_prob)

            prediction = "Malicious" if is_attack else "Normal"

            severity = None
            if is_attack:
                if attack_prob > 0.9:
                    severity = "High"
                elif attack_prob > 0.8:
                    severity = "Medium"
                else:
                    severity = "Low"

            result = {
                "prediction": prediction,
                "confidence": confidence,
                "severity": severity,
                "attack_type": str(multi_pred[i]) if is_attack else None,
                "sourceIp": df.iloc[i].get("srcip", "N/A"),
                "destinationIp": df.iloc[i].get("dstip", "N/A"),
                "sourcePort": int(df.iloc[i].get("sport", 0)),
                "destinationPort": int(df.iloc[i].get("dsport", 0)),
                "protocol": str(df.iloc[i].get("proto", "N/A")),
                "packetSize": int(df.iloc[i].get("sbytes", 0)),
                "duration": float(df.iloc[i].get("dur", 0.0)),
            }

            results.append(result)

        return results
