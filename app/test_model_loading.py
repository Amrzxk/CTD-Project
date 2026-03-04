import joblib
import json
import pandas as pd
import numpy as np

# Load selected features
with open("models/selected_features.json") as f:
    selected_features = json.load(f)

print(f"Selected features count: {len(selected_features)}")

# Load models
binary_model = joblib.load("models/model_label_best.joblib")
multi_model = joblib.load("models/model_attack_cat_best.joblib")

print("Binary model loaded successfully")
print("Multi-class model loaded successfully")

# Test dummy inference
# Create a DataFrame with the correct column names
dummy_input = pd.DataFrame(np.zeros((1, len(selected_features))), columns=selected_features)

print("Binary prediction:", binary_model.predict(dummy_input))
print("Multi prediction:", multi_model.predict(dummy_input))
