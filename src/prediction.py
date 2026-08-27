import os
import json
import pickle
import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_DIR = os.path.join(
    PROJECT_ROOT,
    "models"
)


# ============================================================
# LAZY MODEL SINGLETON CACHE
# ============================================================

_rf_model = None
_quantum_svm = None
_quantum_scaler = None
_quantum_kernel = None
_X6_train_small = None
_SELECTED_FEATURES = None


def load_pickle(filename):
    """
    Load a saved model/object from the models directory.
    """
    path = os.path.join(
        MODEL_DIR,
        filename
    )
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"File not found: {path}"
        )
    with open(path, "rb") as f:
        return pickle.load(f)


def _init_models():
    global _rf_model, _quantum_svm, _quantum_scaler, _quantum_kernel, _X6_train_small, _SELECTED_FEATURES
    
    if _rf_model is None:
        _rf_model = load_pickle("rf_model_new.pkl")
        _quantum_svm = load_pickle("quantum_svm_6.pkl")
        _quantum_scaler = load_pickle("quantum_scaler_6.pkl")
        _quantum_kernel = load_pickle("quantum_kernel_6.pkl")

        quantum_reference_path = os.path.join(MODEL_DIR, "X6_train_small.npy")
        if not os.path.exists(quantum_reference_path):
            raise FileNotFoundError(f"Quantum reference data not found: {quantum_reference_path}")
        _X6_train_small = np.load(quantum_reference_path)

        selected_features_path = os.path.join(MODEL_DIR, "selected_features.json")
        if not os.path.exists(selected_features_path):
            raise FileNotFoundError(f"Selected features file not found: {selected_features_path}")
        with open(selected_features_path, "r") as f:
            _SELECTED_FEATURES = json.load(f)

    return _rf_model, _quantum_svm, _quantum_scaler, _quantum_kernel, _X6_train_small, _SELECTED_FEATURES


def get_selected_features():
    global _SELECTED_FEATURES
    if _SELECTED_FEATURES is None:
        selected_features_path = os.path.join(MODEL_DIR, "selected_features.json")
        if os.path.exists(selected_features_path):
            with open(selected_features_path, "r") as f:
                _SELECTED_FEATURES = json.load(f)
        else:
            _SELECTED_FEATURES = [
                'Init_Win_bytes_forward',
                'Fwd Packet Length Max',
                'Bwd Packet Length Max',
                'Fwd Packet Length Mean',
                'Avg Bwd Segment Size',
                'Subflow Fwd Bytes'
            ]
    return _SELECTED_FEATURES


SELECTED_FEATURES = get_selected_features()


class _ModelProxy:
    def __getattr__(self, name):
        rf, q_svm, q_scaler, q_kernel, x6_ref, selected = _init_models()
        globals()['rf_model'] = rf
        globals()['quantum_svm'] = q_svm
        globals()['quantum_scaler'] = q_scaler
        globals()['quantum_kernel'] = q_kernel
        globals()['X6_train_small'] = x6_ref
        return getattr(rf, name)


rf_model = _ModelProxy()
quantum_svm = None
quantum_scaler = None
quantum_kernel = None
X6_train_small = None


# ============================================================
# LABEL MAPPING
# ============================================================

LABEL_MAP = {
    0: "BENIGN",
    1: "ATTACK"
}


# ============================================================
# DATAFRAME CONVERSION
# ============================================================

def to_dataframe(input_data):
    """
    Convert supported input types into a pandas DataFrame.
    """
    if isinstance(input_data, dict):
        return pd.DataFrame([input_data])
    elif isinstance(input_data, pd.Series):
        return input_data.to_frame().T
    elif isinstance(input_data, pd.DataFrame):
        return input_data.copy()
    else:
        raise TypeError("input_data must be dict, pandas Series or pandas DataFrame")


# ============================================================
# FEATURE VALIDATION
# ============================================================

def validate_quantum_features(df):
    """
    Verify that all six Quantum ML features exist.
    """
    features = get_selected_features()
    missing = [feature for feature in features if feature not in df.columns]
    if missing:
        raise ValueError(f"Missing quantum features: {missing}")


# ============================================================
# QUANTUM PREDICTION
# ============================================================

def quantum_predict(input_data):
    """
    Perform Quantum SVM prediction.
    """
    rf, q_svm, q_scaler, q_kernel, x6_ref, features = _init_models()

    df = to_dataframe(input_data)
    validate_quantum_features(df)

    X6 = df[features].astype(float)
    X6_scaled = q_scaler.transform(X6)

    K_test = q_kernel.evaluate(
        x_vec=X6_scaled,
        y_vec=x6_ref
    )

    prediction = q_svm.predict(K_test)
    prediction = int(prediction[0])
    label = LABEL_MAP.get(prediction, str(prediction))

    return prediction, label


# ============================================================
# CLASSICAL PREDICTION
# ============================================================

def classical_predict(input_data):
    """
    Perform Random Forest prediction.
    """
    rf, q_svm, q_scaler, q_kernel, x6_ref, features = _init_models()

    df = to_dataframe(input_data)

    if hasattr(rf, "feature_names_in_"):
        required_features = list(rf.feature_names_in_)
        missing = [f for f in required_features if f not in df.columns]
        if missing:
            raise ValueError(f"Missing Random Forest features: {missing}")
        X_classical = df[required_features]
    else:
        X_classical = df

    prediction = rf.predict(X_classical)
    prediction = int(prediction[0])
    label = LABEL_MAP.get(prediction, str(prediction))

    return prediction, label


# ============================================================
# FINAL INTRUSION DETECTION
# ============================================================

def detect_intrusion(input_data):
    """
    Run both Classical and Quantum models.
    """
    classical_raw, classical_label = classical_predict(input_data)
    quantum_raw, quantum_label = quantum_predict(input_data)

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


if __name__ == "__main__":
    print("Testing prediction module...")
    rf, q_svm, q_scaler, q_kernel, x6_ref, features = _init_models()
    print("Models loaded successfully!")
    print("Features:", features)