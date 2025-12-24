"""
Evaluate the saved XGBoost model on the preprocessed test split.

This script reads artifacts from training/processed_dataset/:
  - X_test.npz
  - y_test.npy
  - optimized_xgb_model.json

Run from the repo root:
  python training/evaluate_saved_model.py
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
from scipy import sparse
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

import xgboost as xgb


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    data_dir = repo_root / "training" / "processed_dataset"

    x_path = data_dir / "X_test.npz"
    y_path = data_dir / "y_test.npy"
    model_path = data_dir / "optimized_xgb_model.json"

    if not x_path.exists():
        raise FileNotFoundError(f"Missing: {x_path}")
    if not y_path.exists():
        raise FileNotFoundError(f"Missing: {y_path}")
    if not model_path.exists():
        raise FileNotFoundError(f"Missing: {model_path}")

    X_test = sparse.load_npz(x_path)
    y_test = np.load(y_path)

    model = xgb.XGBClassifier()
    model.load_model(model_path)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    print("=== Saved-model evaluation on processed_dataset/X_test ===")
    print(f"accuracy : {accuracy_score(y_test, y_pred):.6f}")
    print(f"roc_auc  : {roc_auc_score(y_test, y_proba):.6f}")
    print(f"f1       : {f1_score(y_test, y_pred):.6f}")
    print(f"precision: {precision_score(y_test, y_pred):.6f}")
    print(f"recall   : {recall_score(y_test, y_pred):.6f}")

    print("\nconfusion_matrix [[tn fp] [fn tp]]:")
    print(confusion_matrix(y_test, y_pred))

    print("\nclassification_report:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


