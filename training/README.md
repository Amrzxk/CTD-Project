# UNSW-NB15 Multi-Task Network Intrusion Detection

This project implements a complete machine learning pipeline for network intrusion detection using the **UNSW-NB15** dataset. It performs two simultaneous classification tasks:
1.  **Binary Classification**: Detecting whether network traffic is normal or an attack.
2.  **Multi-class Classification**: Identifying the specific category of the attack (e.g., DoS, Fuzzers, Exploits).

## 📂 Project Structure

```
training/
├── Dataset/                     # Raw UNSW-NB15 CSV files and feature definitions
├── Processed_Dataset/           # Output folder for cleaned data and models
│   ├── UNSW_NB15_processed.csv  # Cleaned, feature-selected dataset
│   ├── model_label_best.joblib  # Trained Binary Classifier
│   ├── model_attack_cat_best.joblib # Trained Multi-class Classifier
│   └── ... (JSON summaries)
├── UNSW_NB15_MultiTask_Classification.ipynb  # Main Jupyter Notebook
└── requirements.txt             # Python dependencies
```

## 🚀 Pipeline Overview

The pipeline is implemented in `UNSW_NB15_MultiTask_Classification.ipynb` and follows these steps:

### 1. Data Loading & Exploration
*   Loads the 4 raw CSV dataset parts and maps them to the official feature names from `NUSW-NB15_features.csv`.
*   Performs basic EDA to inspect distributions, missing values, and data types.

### 2. Data Cleaning
*   **Missing Values**: Imputes missing values suitable for the data type.
*   **Attack Categories**: 
    *   Fills missing `attack_cat` for normal traffic as "Normal".
    *   Standardizes class names (e.g., merging "Backdoors" into "Backdoor", stripping whitespace).
*   **Duplicates**: Removes duplicate rows (~480k found in the original set).

### 3. Feature Selection
*   **Drop Identifiers**: Removes high-cardinality features like source/destination IP addresses (`srcip`, `dstip`) and timestamps (`stime`, `ltime`) to prevent overfitting and leakage.
*   **Zero Variance**: Removes features that have constant values.
*   **Correlation Filter**: Removes one feature from highly correlated pairs (>0.95 correlation) to reduce redundancy.

### 4. Model Training & Tuning
*   **Binary Task (`label`)**: Trains models (Random Forest, Gradient Boosting) to classify traffic as `0` (Normal) or `1` (Attack).
*   **Multi-class Task (`attack_cat`)**: Trains models to predict the specific attack type.
*   **Hyperparameter Tuning**: Uses `RandomizedSearchCV` to find optimal parameters.
*   **Class Imbalance**: Uses `class_weight='balanced'` (for Random Forest) or sample weights to handle skewed classes.

### 5. Evaluation
*   Evaluates models using **Accuracy**, **Precision**, **Recall**, and **F1-Score**.
*   Generates **Confusion Matrices** to visualize performance across classes.

## 📊 Models

The pipeline saves the best performing models to `training/Processed_Dataset/`:

| Model File | Task | Description |
|------------|------|-------------|
| `model_label_best.joblib` | Binary | Predicts if traffic is **Normal** or **Attack**. |
| `model_attack_cat_best.joblib` | Multi-class | Predicts the specific attack category (e.g., *Exploits, Generic, Fuzzers, Normal*). |

## 🛠️ Usage

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Notebook**:
    Open `UNSW_NB15_MultiTask_Classification.ipynb` in Jupyter Lab or VS Code and run all cells.

    The notebook will:
    *   Process the raw data in `Dataset/`.
    *   Train and evaluate the models.
    *   Save the cleaned dataset and trained models to `Processed_Dataset/`.

## 📈 Dataset Info
The UNSW-NB15 dataset is a comprehensive network intrusion dataset.
*   **Inputs**: 49 features including flow identifiers, packet counts, basic, content, time, and general purpose features.
*   **Targets**: 
    *   `label`: 0 (Normal), 1 (Attack)
    *   `attack_cat`: 9 attack categories + Normal.
