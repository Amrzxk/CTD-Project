## Preprocessing UNSW-NB15 (binary)

This project expects the raw dataset under `training/Dataset/`:

- `UNSW-NB15_1.csv` … `UNSW-NB15_4.csv` (no header)
- `NUSW-NB15_features.csv` (feature names)

### Run preprocessing (recommended outputs: NPZ/NPY + preprocessor)

From the repo root:

```bash
python training/preprocess.py
```

By default this loads **200,000 rows** (for speed) and writes to `training/processed_dataset/`:

- `X_train.npz`, `X_test.npz` (sparse, one-hot encoded)
- `y_train.npy`, `y_test.npy`
- `preprocessor.joblib` (sklearn `ColumnTransformer`)
- `feature_names.json`

### Process the full dataset

```bash
python training/preprocess.py --max-rows all
```

### Also export CSVs (can be extremely large)

```bash
python training/preprocess.py --save-csv
```

### What the preprocessing does (simple + correct)

- **Target**: `Label` (0 = normal, 1 = attack)
- **Categoricals**: one-hot encode `proto`, `service`, `state`
- **Numerics**: median impute missing values (after coercing invalid values to NaN)
- **Leakage-safe**: split first, then fit encoder/imputer on the **train** split only
