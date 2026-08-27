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

MODEL_DIR = os.path.join(PROJECT_ROOT, "models")


# ============================================================
# MODEL STORAGE
# ============================================================

_rf_model = None
_quantum_svm = None
_quantum_scaler = None
_quantum_kernel = None
_X6_train_small = None
_SELECTED_FEATURES = None


# ============================================================
# LOAD PICKLE
# ============================================================

def load_pickle(filename):
    path = os.path.join(MODEL_DIR, filename)

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Model file not found: {path}"
        )

    with open(path, "rb") as f:
        return pickle.load(f)


# ============================================================
# LOAD MODELS
# ============================================================

def _init_models():

    global _rf_model
    global _quantum_svm
    global _quantum_scaler
    global _quantum_kernel
    global _X6_train_small
    global _SELECTED_FEATURES

    if _rf_model is not None:
        return

    # --------------------------------------------------------
    # Classical Random Forest
    # --------------------------------------------------------

    _rf_model = load_pickle(
        "rf_model_new.pkl"
    )

    # --------------------------------------------------------
    # Quantum models
    # --------------------------------------------------------

    _quantum_svm = load_pickle(
        "quantum_svm_6.pkl"
    )

    _quantum_scaler = load_pickle(
        "quantum_scaler_6.pkl"
    )

    _quantum_kernel = load_pickle(
        "quantum_kernel_6.pkl"
    )

    # --------------------------------------------------------
    # Quantum reference data
    # --------------------------------------------------------

    quantum_reference_path = os.path.join(
        MODEL_DIR,
        "X6_train_small.npy"
    )

    if not os.path.exists(quantum_reference_path):
        raise FileNotFoundError(
            f"Quantum reference data not found: "
            f"{quantum_reference_path}"
        )

    _X6_train_small = np.load(
        quantum_reference_path
    )

    # --------------------------------------------------------
    # Selected features
    # --------------------------------------------------------

    selected_features_path = os.path.join(
        MODEL_DIR,
        "selected_features.json"
    )

    if not os.path.exists(selected_features_path):
        raise FileNotFoundError(
            f"Selected features file not found: "
            f"{selected_features_path}"
        )

    with open(
        selected_features_path,
        "r"
    ) as f:
        _SELECTED_FEATURES = json.load(f)

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if len(_SELECTED_FEATURES) != 6:
        raise ValueError(
            "Quantum model requires exactly 6 selected features."
        )

    if _X6_train_small.shape != (100, 6):
        raise ValueError(
            "Quantum reference data must have shape (100, 6). "
            f"Found: {_X6_train_small.shape}"
        )


# ============================================================
# INITIALIZE
# ============================================================

_init_models()


# ============================================================
# PUBLIC VARIABLES
# ============================================================

rf_model = _rf_model
quantum_svm = _quantum_svm
quantum_scaler = _quantum_scaler
quantum_kernel = _quantum_kernel
X6_train_small = _X6_train_small
SELECTED_FEATURES = _SELECTED_FEATURES


# ============================================================
# LABEL MAP
# ============================================================

LABEL_MAP = {
    0: "BENIGN",
    1: "ATTACK"
}


# ============================================================
# INPUT CONVERSION
# ============================================================

def _to_dataframe(input_data):

    if isinstance(input_data, dict):

        return pd.DataFrame(
            [input_data]
        )

    elif isinstance(input_data, pd.Series):

        return input_data.to_frame().T

    elif isinstance(input_data, pd.DataFrame):

        return input_data.copy()

    else:

        raise TypeError(
            "input_data must be dict, pandas Series "
            "or pandas DataFrame"
        )


# ============================================================
# QUANTUM PREDICTION
# ============================================================

def quantum_predict(input_data):
    """
    Quantum SVM prediction.

    Uses the six selected quantum features.
    """

    df = _to_dataframe(input_data)

    # --------------------------------------------------------
    # Check features
    # --------------------------------------------------------

    missing = [
        feature
        for feature in SELECTED_FEATURES
        if feature not in df.columns
    ]

    if missing:

        raise ValueError(
            f"Missing quantum features: {missing}"
        )

    # --------------------------------------------------------
    # Select six features
    # --------------------------------------------------------

    X6 = (
        df[SELECTED_FEATURES]
        .astype(float)
        .values
    )

    # --------------------------------------------------------
    # Scale live/input data
    # --------------------------------------------------------

    X6_scaled = quantum_scaler.transform(
        X6
    )

    # --------------------------------------------------------
    # Quantum kernel
    #
    # IMPORTANT:
    # X6_train_small is already stored in the
    # representation expected by the saved kernel.
    # Do NOT scale it again here.
    # --------------------------------------------------------

    K_test = quantum_kernel.evaluate(
        x_vec=X6_scaled,
        y_vec=X6_train_small
    )

    # --------------------------------------------------------
    # Quantum SVM
    # --------------------------------------------------------

    prediction = quantum_svm.predict(
        K_test
    )

    prediction = int(
        prediction[0]
    )

    return (
        prediction,
        LABEL_MAP.get(
            prediction,
            str(prediction)
        )
    )


# ============================================================
# CLASSICAL PREDICTION
# ============================================================

def classical_predict(input_data):
    """
    Random Forest prediction.

    The Random Forest expects the complete
    78-feature network-flow structure.
    """

    df = _to_dataframe(
        input_data
    )

    # --------------------------------------------------------
    # Validate feature count
    # --------------------------------------------------------

    if hasattr(
        rf_model,
        "n_features_in_"
    ):

        expected = rf_model.n_features_in_

        if df.shape[1] != expected:

            raise ValueError(
                f"Random Forest expects "
                f"{expected} features, "
                f"but received {df.shape[1]}."
            )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    prediction = rf_model.predict(
        df
    )

    prediction = int(
        prediction[0]
    )

    return (
        prediction,
        LABEL_MAP.get(
            prediction,
            str(prediction)
        )
    )


# ============================================================
# HYBRID DETECTION
# ============================================================

def detect_intrusion(input_data):
    """
    Run both Classical and Quantum models.

    Decision policy:

    BENIGN + BENIGN
        -> BENIGN / LOW

    ATTACK + ATTACK
        -> ATTACK / HIGH

    BENIGN + ATTACK
        -> SUSPICIOUS / MEDIUM

    ATTACK + BENIGN
        -> SUSPICIOUS / MEDIUM
    """

    # --------------------------------------------------------
    # Classical
    # --------------------------------------------------------

    classical_raw, classical_label = (
        classical_predict(
            input_data
        )
    )

    # --------------------------------------------------------
    # Quantum
    # --------------------------------------------------------

    quantum_raw, quantum_label = (
        quantum_predict(
            input_data
        )
    )

    # --------------------------------------------------------
    # Agreement
    # --------------------------------------------------------

    if (
        classical_raw == 1
        and quantum_raw == 1
    ):

        final_label = "ATTACK"
        risk_level = "HIGH"

    elif (
        classical_raw == 0
        and quantum_raw == 0
    ):

        final_label = "BENIGN"
        risk_level = "LOW"

    else:

        final_label = "SUSPICIOUS"
        risk_level = "MEDIUM"

    # --------------------------------------------------------
    # Return complete result
    # --------------------------------------------------------

    return {

        "classical_prediction":
            classical_label,

        "quantum_prediction":
            quantum_label,

        "final_prediction":
            final_label,

        "risk_level":
            risk_level
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 65)
    print(
        "       UC029 HYBRID QUANTUM-CLASSICAL DETECTION"
    )
    print("=" * 65)

    print(
        "\nModels loaded successfully."
    )

    print(
        "\nClassical model: Random Forest"
    )

    print(
        "Classical features: 78"
    )

    print(
        "\nQuantum model: Fidelity Quantum Kernel + Quantum SVM"
    )

    print(
        "Quantum features: 6"
    )

    print(
        "\nSelected Quantum Features:"
    )

    for feature in SELECTED_FEATURES:

        print(
            " -",
            feature
        )

    print(
        "\nQuantum reference shape:",
        X6_train_small.shape
    )

    print(
        "\nDecision policy:"
    )

    print(
        " RF BENIGN + Quantum BENIGN"
        " -> BENIGN / LOW"
    )

    print(
        " RF ATTACK + Quantum ATTACK"
        " -> ATTACK / HIGH"
    )

    print(
        " Model disagreement"
        " -> SUSPICIOUS / MEDIUM"
    )

    print(
        "\nReady for prediction."
    )

    print("=" * 65)