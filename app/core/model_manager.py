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
        # CRITICAL: Do NOT use .values here. The pipeline expects a DataFrame with column names.
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
            
            # Use iloc for safe row access if index is not reset
            # But here we are iterating by range(len), so we assume default index or use iloc?
            # binary_pred is numpy array, so [i] works.
            # X is DataFrame, so we don't access it by index here.
            
            result = {
                "flow_id": i,
                "is_attack": bool(is_attack),
                "binary_confidence": float(binary_proba[i].max()),
            }

            if is_attack:
                result["attack_type"] = str(multi_pred[i])
                result["attack_confidence"] = float(multi_proba[i].max())
            else:
                result["attack_type"] = "Normal"
                result["attack_confidence"] = 0.0

            results.append(result)

        return results
