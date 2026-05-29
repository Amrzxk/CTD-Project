"""
Model managers — single-model legacy + 3-tier hierarchical.

Two implementations live here, both exposing the same ``predict(df)``
contract so the API layer can swap between them via a single environment
variable (``MODEL_MODE``):

* :class:`ModelManager` — original single LightGBM multiclass model
  (15 classes).  Used when ``MODEL_MODE=legacy`` or when the new
  hierarchical artifacts are not present on disk.
* :class:`HierarchicalModelManager` — 3-tier classifier:
    1. Binary gate (LightGBM, "Benign" vs "Attack")
    2. Attack family (CatBoost, 6 classes)
    3. Per-family sub-attack classifier (XGBoost)
  Used when ``MODEL_MODE=hierarchical`` and the artifacts are present.

Both return a list of dicts with at minimum::

    {
        "prediction":   "Normal" | "Malicious",
        "confidence":   float,        # chained product (kept for backwards-compat)
        "severity":     "High" | "Medium" | "Low" | None,
        "attack_type":  str | None,
        "family":       str | None,
        "stage1_p":     float,
        "stage2_p":     float | None,                 # top family probability
        "stage2_probs": dict[str, float] | None,      # full per-family vector
        "stage3_p":     float | None,                 # top leaf probability in chosen family
        "stage3_probs": dict[str, float] | None,      # full per-leaf vector for chosen family
    }

The legacy ``ModelManager`` keeps the per-stage fields at ``None`` so the
response shape is uniform across both managers.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

# Severity thresholds applied to the *maximum* class probability
_HIGH_THRESHOLD = 0.9
_MEDIUM_THRESHOLD = 0.8

# Label for the benign / normal class
_BENIGN_LABEL = "Benign"


# ---------------------------------------------------------------------------
# Single-model legacy manager (unchanged behavior; new fields default to None)
# ---------------------------------------------------------------------------

class ModelManager:
    """Thin wrapper around a pickled ``LGBMClassifier``.

    Parameters
    ----------
    model_path : str
        Path to the pickled LightGBM model.
    features_path : str
        Path to a JSON file containing the ordered list of feature names.
    labels_path : str
        Path to a JSON file containing the ordered list of class labels.
    scaler_path : str | None
        Optional path to a pickled ``StandardScaler``.
    """

    def __init__(
        self,
        model_path: str,
        features_path: str,
        labels_path: str,
        scaler_path: str | None = None,
    ) -> None:
        self.model = joblib.load(model_path)
        log.info("LightGBM model loaded from %s", model_path)

        with open(features_path, "r", encoding="utf-8") as fh:
            self.selected_features: list[str] = json.load(fh)
        log.info("Feature list loaded: %d features", len(self.selected_features))

        with open(labels_path, "r", encoding="utf-8") as fh:
            self.class_labels: list[str] = json.load(fh)
        log.info("Class labels loaded: %s", self.class_labels)

        self.scaler = None
        if scaler_path and Path(scaler_path).exists():
            self.scaler = joblib.load(scaler_path)
            log.info("StandardScaler loaded from %s", scaler_path)
        else:
            log.info("No scaler found — raw features will be used.")

        self.model_version = "legacy-single"

    def predict(self, df: pd.DataFrame) -> list[dict[str, Any]]:
        X = df[self.selected_features].copy()
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)

        if self.scaler is not None:
            X = pd.DataFrame(
                self.scaler.transform(X),
                columns=self.selected_features,
                index=X.index,
            )

        proba = self.model.predict_proba(X)

        results: list[dict[str, Any]] = []
        for i in range(len(df)):
            row_proba = proba[i]
            predicted_idx = int(np.argmax(row_proba))
            predicted_label = self.class_labels[predicted_idx]
            confidence = float(row_proba[predicted_idx])

            is_attack = predicted_label != _BENIGN_LABEL

            severity = None
            if is_attack:
                if confidence > _HIGH_THRESHOLD:
                    severity = "High"
                elif confidence > _MEDIUM_THRESHOLD:
                    severity = "Medium"
                else:
                    severity = "Low"

            benign_prob = 0.0
            if _BENIGN_LABEL in self.class_labels:
                benign_idx = self.class_labels.index(_BENIGN_LABEL)
                benign_prob = float(row_proba[benign_idx])

            results.append(
                {
                    "prediction": "Malicious" if is_attack else "Normal",
                    "confidence": round(confidence, 4),
                    "severity": severity,
                    "attack_type": predicted_label if is_attack else None,
                    "family": None,
                    "stage1_p": round(1.0 - benign_prob, 4),
                    # Per-stage fields are hierarchical-only; legacy returns None
                    # so the response shape is uniform across both managers.
                    "stage2_p": None,
                    "stage2_probs": None,
                    "stage3_p": None,
                    "stage3_probs": None,
                }
            )

        return results


# ---------------------------------------------------------------------------
# Hierarchical 3-tier manager
# ---------------------------------------------------------------------------

# Subtype layout for stage 3. Must match what training produces.
# Families with a single subtype are handled inline (no stage-3 model).
_FAMILY_SINGLE_LABEL = {
    "DDoS": "DDoS",
    "Probe": "PortScan",
    "WebAttack": "SQL-Injection",
}


class HierarchicalModelManager:
    """3-tier hierarchical IDS classifier.

    Loads stage-1 (binary), stage-2 (family), and per-family stage-3
    (sub-attack) models along with their respective ``StandardScaler``
    instances.  The artifact filenames match what the training notebook
    writes to ``/kaggle/working/artifacts/``.

    Parameters
    ----------
    models_dir : str | Path
        Directory containing all artifacts.

    Raises
    ------
    FileNotFoundError
        If a required artifact is missing.
    """

    REQUIRED_FILES = (
        "stage1_binary.lgb",
        "stage1_threshold.json",
        "stage2_family.cbm",
        "stage2_family_classes.json",
        "scaler_S1.joblib",
        "scaler_S2.joblib",
        "selected_features.json",
        "class_labels.json",
        "manifest.json",
    )

    def __init__(self, models_dir: str | Path) -> None:
        self.models_dir = Path(models_dir)
        for fname in self.REQUIRED_FILES:
            if not (self.models_dir / fname).exists():
                raise FileNotFoundError(
                    f"Hierarchical artifact missing: {self.models_dir / fname}"
                )

        # --- Feature order ---
        with open(self.models_dir / "selected_features.json", "r", encoding="utf-8") as fh:
            self.selected_features: list[str] = json.load(fh)
        log.info("Hierarchical: %d features loaded", len(self.selected_features))

        # --- Leaf labels (for the live event schema) ---
        with open(self.models_dir / "class_labels.json", "r", encoding="utf-8") as fh:
            self.class_labels: list[str] = json.load(fh)

        # --- Stage 1 ---
        import lightgbm as lgb
        self.s1 = lgb.Booster(model_file=str(self.models_dir / "stage1_binary.lgb"))
        with open(self.models_dir / "stage1_threshold.json", "r", encoding="utf-8") as fh:
            self.tau1: float = float(json.load(fh)["tau"])
        self.scaler_S1 = joblib.load(self.models_dir / "scaler_S1.joblib")
        log.info("Hierarchical: stage1 loaded (tau=%.4f)", self.tau1)

        # --- Stage 2 ---
        import catboost as cb
        self.s2 = cb.CatBoostClassifier()
        self.s2.load_model(str(self.models_dir / "stage2_family.cbm"))
        with open(self.models_dir / "stage2_family_classes.json", "r", encoding="utf-8") as fh:
            self.family_classes: list[str] = json.load(fh)
        self.scaler_S2 = joblib.load(self.models_dir / "scaler_S2.joblib")
        log.info("Hierarchical: stage2 loaded (%d families)", len(self.family_classes))

        # --- Stage 3 (one per family with multiple subtypes) ---
        import xgboost as xgb
        self.s3_models: dict[str, Any] = {}
        self.s3_classes: dict[str, list[str]] = {}
        self.scalers_S3: dict[str, Any] = {}
        for fam in self.family_classes:
            model_file = self.models_dir / f"stage3_{fam}.json"
            classes_file = self.models_dir / f"stage3_{fam}_classes.json"
            scaler_file = self.models_dir / f"scaler_S3_{fam}.joblib"
            if not (model_file.exists() and classes_file.exists() and scaler_file.exists()):
                # Single-subtype families (DDoS, Probe, WebAttack) skip stage 3.
                continue
            booster = xgb.XGBClassifier()
            booster.load_model(str(model_file))
            with open(classes_file, "r", encoding="utf-8") as fh:
                self.s3_classes[fam] = json.load(fh)
            self.s3_models[fam] = booster
            self.scalers_S3[fam] = joblib.load(scaler_file)
            log.info("Hierarchical: stage3[%s] loaded (%d subtypes)",
                     fam, len(self.s3_classes[fam]))

        # --- Manifest (version + integrity for /health) ---
        with open(self.models_dir / "manifest.json", "r", encoding="utf-8") as fh:
            self.manifest = json.load(fh)
        # Pick a short version string for the live event payload
        files_hashes = self.manifest.get("files", {})
        s1_hash = files_hashes.get("stage1_binary.lgb", {}).get("sha256", "")
        self.model_version = f"h-{s1_hash[:8]}" if s1_hash else "hierarchical"

    # ------------------------------------------------------------------
    # Public API — identical signature to ``ModelManager.predict``
    # ------------------------------------------------------------------

    def predict(self, df: pd.DataFrame) -> list[dict[str, Any]]:
        if len(df) == 0:
            return []

        X = df[self.selected_features].copy()
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)
        Xv = X.values

        # ---- Stage 1: binary gate ----
        X_s1 = self.scaler_S1.transform(Xv)
        p_atk = np.asarray(self.s1.predict(X_s1)).reshape(-1)
        is_atk = p_atk >= self.tau1

        # Default: everyone is Normal with confidence (1 - p_atk).
        n = len(df)
        results: list[dict[str, Any]] = [
            {
                "prediction": "Normal",
                "confidence": round(float(1.0 - p_atk[i]), 4),
                "severity": None,
                "attack_type": None,
                "family": None,
                "stage1_p": round(float(p_atk[i]), 4),
                "stage2_p": None,
                "stage2_probs": None,
                "stage3_p": None,
                "stage3_probs": None,
            }
            for i in range(n)
        ]

        if not is_atk.any():
            return results

        # ---- Stage 2: family classifier on attack rows ----
        atk_idx = np.where(is_atk)[0]
        X_atk = Xv[atk_idx]
        X_s2 = self.scaler_S2.transform(X_atk)
        fam_proba = self.s2.predict_proba(X_s2)
        fam_pick = np.argmax(fam_proba, axis=1)
        fam_top_p = fam_proba[np.arange(len(atk_idx)), fam_pick]
        fam_names = [self.family_classes[i] for i in fam_pick]

        # ---- Stage 3 per family ----
        # Retain not just the argmax but the full sub-class probability vector
        # so the API can surface why a family was routed to a particular leaf.
        sub_label: list[Any] = [None] * len(atk_idx)
        sub_top_p: list[float] = [1.0] * len(atk_idx)
        sub_probs: list[dict[str, float] | None] = [None] * len(atk_idx)

        for fam, booster in self.s3_models.items():
            sel = np.array([nm == fam for nm in fam_names])
            if not sel.any():
                continue
            X_s3 = self.scalers_S3[fam].transform(X_atk[sel])
            sub_proba = booster.predict_proba(X_s3)
            sub_idx = np.argmax(sub_proba, axis=1)
            sub_p = sub_proba[np.arange(sel.sum()), sub_idx]
            classes = self.s3_classes[fam]
            pos = np.where(sel)[0]
            for row_i, (j, p, k) in enumerate(zip(pos, sub_p, sub_idx)):
                sub_label[j] = classes[k]
                sub_top_p[j] = float(p)
                sub_probs[j] = {
                    classes[c_idx]: round(float(sub_proba[row_i, c_idx]), 4)
                    for c_idx in range(len(classes))
                }

        # Single-subtype families (DDoS / Probe / WebAttack) bypass stage 3.
        for j, fam in enumerate(fam_names):
            if sub_label[j] is None and fam in _FAMILY_SINGLE_LABEL:
                leaf = _FAMILY_SINGLE_LABEL[fam]
                sub_label[j] = leaf
                sub_top_p[j] = 1.0
                sub_probs[j] = {leaf: 1.0}
            elif sub_label[j] is None:
                # Unknown family without a stage-3 model — fall back to family name.
                sub_label[j] = fam
                sub_probs[j] = {fam: 1.0}

        # Build full per-family probability dicts (Stage 2) for all attack rows.
        # Done once outside the merge loop because numpy slicing is cheap.
        fam_prob_dicts: list[dict[str, float]] = [
            {
                self.family_classes[c]: round(float(fam_proba[i, c]), 4)
                for c in range(fam_proba.shape[1])
            }
            for i in range(len(atk_idx))
        ]

        # ---- Merge into the results array ----
        for j, src_idx in enumerate(atk_idx):
            s2_p = float(fam_top_p[j])
            s3_p = float(sub_top_p[j])
            chained = float(p_atk[src_idx]) * s2_p * s3_p

            # New severity rule: key off the downstream signal (stage 3, or
            # stage 2 for single-leaf families which set s3_p=1.0), gated by
            # stage-2 family confidence so a noisy leaf pick can't get promoted.
            # See plan doc for rationale: stage1_p is calibration-shifted by
            # the FPR<=1% threshold and is not a reliable confidence signal.
            if s3_p >= 0.95 and s2_p >= 0.90:
                severity = "High"
            elif s3_p >= 0.80 and s2_p >= 0.70:
                severity = "Medium"
            else:
                severity = "Low"

            results[src_idx] = {
                "prediction": "Malicious",
                "confidence": round(chained, 4),
                "severity": severity,
                "attack_type": sub_label[j],
                "family": fam_names[j],
                "stage1_p": round(float(p_atk[src_idx]), 4),
                "stage2_p": round(s2_p, 4),
                "stage2_probs": fam_prob_dicts[j],
                "stage3_p": round(s3_p, 4),
                "stage3_probs": sub_probs[j],
            }

        return results
