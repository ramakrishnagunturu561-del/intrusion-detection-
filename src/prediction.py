import os
import json
import pickle
import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")


# ============================================================
# LOAD MODELS
# ============================================================

def load_pickle(filename):
    path = os.path.join(MODEL_DIR, filename)

    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "rb") as f:
        return pickle.load(f)


rf_model = load_pickle("rf_model_new.pkl")
quantum_svm = load_pickle("quantum_svm_6.pkl")
quantum_scaler = load_pickle("quantum_scaler_6.pkl")
quantum_kernel = load_pickle("quantum_kernel_6.pkl")


# ============================================================
# LOAD QUANTUM TRAINING DATA
# ============================================================

X6_train_small = np.load(
    os.path.join(MODEL_DIR, "X6_train_small.npy")
)

print("Quantum reference data:", X6_train_small.shape)


# ============================================================
# LOAD SELECTED FEATURES
# ============================================================

with open(
    os.path.join(MODEL_DIR, "selected_features.json"),
    "r"
) as f:
    SELECTED_FEATURES = json.load(f)


# ============================================================
# LABEL MAPPING
# ============================================================

LABEL_MAP = {
    0: "BENIGN",
    1: "ATTACK"
}


# ============================================================
# QUANTUM PREDICTION
# ============================================================

def quantum_predict(input_data):
    """
    Perform Quantum SVM prediction.

    input_data must contain the six selected features.
    """

    if isinstance(input_data, dict):
        df = pd.DataFrame([input_data])

    elif isinstance(input_data, pd.Series):
        df = input_data.to_frame().T

    elif isinstance(input_data, pd.DataFrame):
        df = input_data.copy()

    else:
        raise TypeError(
            "input_data must be dict, pandas Series or pandas DataFrame"
        )

    # Check required features
    missing = [
        feature
        for feature in SELECTED_FEATURES
        if feature not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing quantum features: {missing}"
        )

    # Select six features in correct order
    X6 = df[SELECTED_FEATURES].astype(float).values

    # Scale
    X6_scaled = quantum_scaler.transform(X6)

    # Calculate quantum kernel against training data
    K_test = quantum_kernel.evaluate(
        x_vec=X6_scaled,
        y_vec=X6_train_small
    )

    # Quantum SVM prediction
    prediction = quantum_svm.predict(K_test)

    prediction = int(prediction[0])

    return prediction, LABEL_MAP.get(
        prediction,
        str(prediction)
    )


# ============================================================
# CLASSICAL PREDICTION
# ============================================================

def classical_predict(input_data):
    """
    Perform Random Forest prediction.

    The Random Forest expects the same feature structure
    that was used during its training.
    """

    if isinstance(input_data, dict):
        df = pd.DataFrame([input_data])

    elif isinstance(input_data, pd.Series):
        df = input_data.to_frame().T

    elif isinstance(input_data, pd.DataFrame):
        df = input_data.copy()

    else:
        raise TypeError(
            "input_data must be dict, pandas Series or pandas DataFrame"
        )

    prediction = rf_model.predict(df)

    prediction = int(prediction[0])

    return prediction, LABEL_MAP.get(
        prediction,
        str(prediction)
    )


# ============================================================
# FINAL DETECTION
# ============================================================

def detect_intrusion(input_data):
    """
    Run both Classical and Quantum models
    and produce a final risk assessment.
    """

    classical_raw, classical_label = classical_predict(
        input_data
    )

    quantum_raw, quantum_label = quantum_predict(
        input_data
    )

    # Final decision:
    # If either model detects an attack, mark as ATTACK.
    if classical_raw == 1 or quantum_raw == 1:
        final_label = "ATTACK"
        risk_level = "HIGH"

    else:
        final_label = "BENIGN"
        risk_level = "LOW"

    return {
        "classical_prediction": classical_label,
        "quantum_prediction": quantum_label,
        "final_prediction": final_label,
        "risk_level": risk_level
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("UC029 QUANTUM INTRUSION DETECTION")
    print("=" * 60)

    print("\nModels loaded successfully.")

    print("\nSelected Quantum Features:")
    for feature in SELECTED_FEATURES:
        print(" -", feature)

    print("\nQuantum training shape:")
    print(X6_train_small.shape)

    print("\nReady for prediction.")
