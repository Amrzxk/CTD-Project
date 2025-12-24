"""
UNSW-NB15 preprocessing (binary intrusion detection).

Reads:
  - training/Dataset/UNSW-NB15_1.csv ... UNSW-NB15_4.csv (no header)
  - training/Dataset/NUSW-NB15_features.csv (feature names)

Produces (under --output-dir, default: training/processed_dataset/):
  - X_train.npz / X_test.npz           (scipy sparse matrices)
  - y_train.npy / y_test.npy           (numpy arrays)
  - feature_names.json                 (post-encoding feature names)
  - preprocessor.joblib                (sklearn ColumnTransformer)
  - train.csv / test.csv (optional)    (dense-ish CSV, can be huge)

Why sparse outputs?
  One-hot encoding produces many zero columns; NPZ is far smaller/faster than CSV.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
import pandas as pd
from scipy import sparse as sp
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


DROP_COLS_DEFAULT = ["attack_cat", "srcip", "dstip", "Stime", "Ltime"]
CAT_COLS_DEFAULT = ["proto", "service", "state"]


def _repo_root_from_file() -> Path:
    # training/preprocess.py -> repo root is parent of "training"
    return Path(__file__).resolve().parent.parent


def _iter_parts(dataset_dir: Path) -> Iterable[Path]:
    for i in range(1, 5):
        yield dataset_dir / f"UNSW-NB15_{i}.csv"


def _read_feature_names(features_path: Path) -> list[str]:
    features_df = pd.read_csv(features_path, encoding="cp1252")
    if "Name" not in features_df.columns:
        raise ValueError(f"Expected a 'Name' column in {features_path}")
    return features_df["Name"].astype(str).str.strip().tolist()


def _read_dataset(
    parts: list[Path],
    feature_names: list[str],
    use_cols: list[str],
    max_rows: int | None,
) -> pd.DataFrame:
    dfs: list[pd.DataFrame] = []
    remaining = max_rows

    for file in parts:
        if remaining is not None and remaining <= 0:
            break

        nrows = remaining if remaining is not None else None
        print(f"Loading {file.name} (nrows={nrows})...")

        df_part = pd.read_csv(
            file,
            header=None,
            names=feature_names,
            usecols=use_cols,
            nrows=nrows,
            low_memory=False,
        )
        dfs.append(df_part)

        if remaining is not None:
            remaining -= len(df_part)

    if not dfs:
        raise ValueError("No data loaded. Check dataset paths and --max-rows.")

    df = pd.concat(dfs, axis=0, ignore_index=True)
    return df


def _to_sparse_df(Xm: sp.spmatrix | np.ndarray, columns: np.ndarray, index) -> pd.DataFrame:
    if sp.issparse(Xm):
        return pd.DataFrame.sparse.from_spmatrix(Xm, columns=columns, index=index)
    return pd.DataFrame(Xm, columns=columns, index=index)


def main() -> int:
    parser = argparse.ArgumentParser(description="Preprocess UNSW-NB15 for binary intrusion detection.")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=None,
        help="Directory containing UNSW-NB15_1.csv..UNSW-NB15_4.csv and NUSW-NB15_features.csv. "
        "Defaults to <repo>/training/Dataset.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory. Defaults to <repo>/training/processed_dataset.",
    )
    parser.add_argument(
        "--max-rows",
        type=str,
        default="200000",
        help="Maximum rows to load (across all parts). Use 'all' to load everything.",
    )
    parser.add_argument("--test-size", type=float, default=0.2, help="Test fraction.")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed.")
    parser.add_argument(
        "--scale-numeric",
        action="store_true",
        help="Apply StandardScaler to numeric features (not needed for tree models).",
    )
    parser.add_argument(
        "--save-csv",
        action="store_true",
        help="Also write train.csv/test.csv (can be extremely large for full dataset).",
    )
    parser.add_argument(
        "--drop-cols",
        type=str,
        default=",".join(DROP_COLS_DEFAULT),
        help="Comma-separated columns to drop if present.",
    )
    args = parser.parse_args()

    repo_root = _repo_root_from_file()
    dataset_dir: Path = args.dataset_dir or (repo_root / "training" / "Dataset")
    output_dir: Path = args.output_dir or (repo_root / "training" / "processed_dataset")
    output_dir.mkdir(parents=True, exist_ok=True)

    features_path = dataset_dir / "NUSW-NB15_features.csv"
    parts = [p for p in _iter_parts(dataset_dir)]
    for p in [features_path, *parts]:
        if not p.exists():
            raise FileNotFoundError(f"Missing expected dataset file: {p}")

    max_rows: int | None
    if args.max_rows.strip().lower() in {"all", "none"}:
        max_rows = None
    else:
        max_rows = int(args.max_rows)
        if max_rows <= 0:
            max_rows = None

    feature_names = _read_feature_names(features_path)
    drop_cols = [c.strip() for c in args.drop_cols.split(",") if c.strip()]
    use_cols = [c for c in feature_names if c not in drop_cols]

    df = _read_dataset(parts=parts, feature_names=feature_names, use_cols=use_cols, max_rows=max_rows)
    print(f"Combined dataset shape: {df.shape}")

    # Target column in the raw dataset is "Label" (per features file).
    if "Label" not in df.columns:
        raise ValueError("Expected a 'Label' column in the loaded dataset.")

    X = df.drop(columns=["Label"], errors="ignore")
    y = df["Label"].astype(int).to_numpy()

    # Categorical columns must be strings; everything else coerced to numeric.
    categorical_cols = [c for c in CAT_COLS_DEFAULT if c in X.columns]
    numeric_cols = [c for c in X.columns if c not in categorical_cols]

    for c in categorical_cols:
        X[c] = X[c].astype(str)
    for c in numeric_cols:
        X[c] = pd.to_numeric(X[c], errors="coerce")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )

    numeric_steps = [("imputer", SimpleImputer(strategy="median"))]
    if args.scale_numeric:
        # Note: with sparse data, StandardScaler(with_mean=False) is required.
        numeric_steps.append(("scaler", StandardScaler(with_mean=False)))

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=True), categorical_cols),
            ("num", Pipeline(steps=numeric_steps), numeric_cols),
        ],
        remainder="drop",
        # Prefer sparse output when mixing OHE (sparse) + numeric (dense).
        # This keeps outputs small and ensures we can save as .npz reliably.
        sparse_threshold=1.0,
    )

    print("Fitting preprocessor on train split...")
    X_train_processed = preprocessor.fit_transform(X_train)
    X_test_processed = preprocessor.transform(X_test)

    # Depending on sklearn heuristics/density, ColumnTransformer may still output dense arrays.
    # Normalize to CSR sparse matrices for consistent saving + downstream usage.
    if not sp.issparse(X_train_processed):
        X_train_processed = sp.csr_matrix(X_train_processed)
    if not sp.issparse(X_test_processed):
        X_test_processed = sp.csr_matrix(X_test_processed)

    cat_features = (
        preprocessor.named_transformers_["cat"].get_feature_names_out(categorical_cols)
        if categorical_cols
        else np.array([], dtype=str)
    )
    all_features = np.concatenate([cat_features, np.array(numeric_cols, dtype=str)])

    # Save compact artifacts
    sp.save_npz(output_dir / "X_train.npz", X_train_processed)
    sp.save_npz(output_dir / "X_test.npz", X_test_processed)
    np.save(output_dir / "y_train.npy", y_train)
    np.save(output_dir / "y_test.npy", y_test)
    joblib.dump(preprocessor, output_dir / "preprocessor.joblib")
    (output_dir / "feature_names.json").write_text(json.dumps(all_features.tolist(), indent=2), encoding="utf-8")

    print("Saved:")
    print(f"  {output_dir / 'X_train.npz'}")
    print(f"  {output_dir / 'X_test.npz'}")
    print(f"  {output_dir / 'y_train.npy'}")
    print(f"  {output_dir / 'y_test.npy'}")
    print(f"  {output_dir / 'preprocessor.joblib'}")
    print(f"  {output_dir / 'feature_names.json'}")

    if args.save_csv:
        print("Writing CSVs (this can be very large)...")
        X_train_df = _to_sparse_df(X_train_processed, all_features, X_train.index)
        X_test_df = _to_sparse_df(X_test_processed, all_features, X_test.index)
        train_df = X_train_df.copy()
        train_df["label"] = y_train
        test_df = X_test_df.copy()
        test_df["label"] = y_test
        train_df.to_csv(output_dir / "train.csv", index=False)
        test_df.to_csv(output_dir / "test.csv", index=False)
        print(f"  {output_dir / 'train.csv'}")
        print(f"  {output_dir / 'test.csv'}")

    # Quick sanity stats
    neg = int((y_train == 0).sum())
    pos = int((y_train == 1).sum())
    scale_pos_weight = (neg / pos) if pos else float("inf")
    print(f"Train label distribution: normal={neg}, attack={pos}, scale_pos_weight={scale_pos_weight:.4f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
