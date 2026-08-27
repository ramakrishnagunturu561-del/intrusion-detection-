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
# LOAD MODELS
# ============================================================

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


# Classical model
rf_model = load_pickle(
    "rf_model_new.pkl"
)

# Quantum SVM
quantum_svm = load_pickle(
    "quantum_svm_6.pkl"
)

# Quantum feature scaler
quantum_scaler = load_pickle(
    "quantum_scaler_6.pkl"
)

# Quantum kernel
quantum_kernel = load_pickle(
    "quantum_kernel_6.pkl"
)


# ============================================================
# LOAD QUANTUM REFERENCE DATA
# ============================================================

quantum_reference_path = os.path.join(
    MODEL_DIR,
    "X6_train_small.npy"
)

if not os.path.exists(quantum_reference_path):
    raise FileNotFoundError(
        f"Quantum reference data not found: "
        f"{quantum_reference_path}"
    )


X6_train_small = np.load(
    quantum_reference_path
)


print(
    "Quantum reference data:",
    X6_train_small.shape
)


# ============================================================
# LOAD SELECTED QUANTUM FEATURES
# ============================================================

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

    SELECTED_FEATURES = json.load(f)


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

        return pd.DataFrame(
            [input_data]
        )

    elif isinstance(input_data, pd.Series):

        return input_data.to_frame().T

    elif isinstance(input_data, pd.DataFrame):

        return input_data.copy()

    else:

        raise TypeError(
            "input_data must be "
            "dict, pandas Series or pandas DataFrame"
        )


# ============================================================
# FEATURE VALIDATION
# ============================================================

def validate_quantum_features(df):
    """
    Verify that all six Quantum ML features exist.
    """

    missing = [
        feature
        for feature in SELECTED_FEATURES
        if feature not in df.columns
    ]

    if missing:

        raise ValueError(
            f"Missing quantum features: {missing}"
        )


# ============================================================
# QUANTUM PREDICTION
# ============================================================

def quantum_predict(input_data):
    """
    Perform Quantum SVM prediction.

    Pipeline:

    78 input features
            ↓
    Select 6 Quantum features
            ↓
       MinMaxScaler
            ↓
    FidelityQuantumKernel
            ↓
       Quantum SVM
            ↓
       BENIGN / ATTACK
    """

    # Convert input to DataFrame
    df = to_dataframe(
        input_data
    )

    # Check required features
    validate_quantum_features(
        df
    )

    # --------------------------------------------------------
    # Select exactly six features
    # in the same order used during training
    # --------------------------------------------------------

    X6 = df[
        SELECTED_FEATURES
    ].astype(float)

    # --------------------------------------------------------
    # Scale features
    #
    # IMPORTANT:
    # Keep this as a DataFrame so that the feature names
    # remain available to the fitted MinMaxScaler.
    # --------------------------------------------------------

    X6_scaled = quantum_scaler.transform(
        X6
    )

    # --------------------------------------------------------
    # Quantum Kernel
    #
    # One input sample is compared against the
    # 100 reference samples.
    #
    # Expected shape:
    #
    # (1, 100)
    # --------------------------------------------------------

    K_test = quantum_kernel.evaluate(
        x_vec=X6_scaled,
        y_vec=X6_train_small
    )

    # --------------------------------------------------------
    # Quantum SVM prediction
    # --------------------------------------------------------

    prediction = quantum_svm.predict(
        K_test
    )

    prediction = int(
        prediction[0]
    )

    label = LABEL_MAP.get(
        prediction,
        str(prediction)
    )

    return prediction, label


# ============================================================
# CLASSICAL PREDICTION
# ============================================================

def classical_predict(input_data):
    """
    Perform Random Forest prediction.

    The Random Forest uses the original
    78-feature network-flow input.
    """

    # Convert input to DataFrame
    df = to_dataframe(
        input_data
    )

    # --------------------------------------------------------
    # Check that the input contains the expected features
    # --------------------------------------------------------

    if hasattr(
        rf_model,
        "feature_names_in_"
    ):

        required_features = list(
            rf_model.feature_names_in_
        )

        missing = [
            feature
            for feature in required_features
            if feature not in df.columns
        ]

        if missing:

            raise ValueError(
                "Missing Random Forest features: "
                f"{missing}"
            )

        # Preserve exact training feature order
        X_classical = df[
            required_features
        ]

    else:

        # Fallback for models without feature names
        X_classical = df

    # --------------------------------------------------------
    # Random Forest prediction
    # --------------------------------------------------------

    prediction = rf_model.predict(
        X_classical
    )

    prediction = int(
        prediction[0]
    )

    label = LABEL_MAP.get(
        prediction,
        str(prediction)
    )

    return prediction, label


# ============================================================
# FINAL INTRUSION DETECTION
# ============================================================

def detect_intrusion(input_data):
    """
    Run both Classical and Quantum models.

    Final decision:

    If either model detects ATTACK:
        Final = ATTACK
        Risk = HIGH

    If both models detect BENIGN:
        Final = BENIGN
        Risk = LOW
    """

    # --------------------------------------------------------
    # Classical Random Forest
    # --------------------------------------------------------

    classical_raw, classical_label = classical_predict(
        input_data
    )

    # --------------------------------------------------------
    # Quantum SVM
    # --------------------------------------------------------

    quantum_raw, quantum_label = quantum_predict(
        input_data
    )

    # --------------------------------------------------------
    # Final decision
    # --------------------------------------------------------

    if (
        classical_raw == 1
        or
        quantum_raw == 1
    ):

        final_label = "ATTACK"
        risk_level = "HIGH"

    else:

        final_label = "BENIGN"
        risk_level = "LOW"

    # --------------------------------------------------------
    # Return structured result
    # --------------------------------------------------------

    return {
        "classical_prediction": classical_label,
        "quantum_prediction": quantum_label,
        "final_prediction": final_label,
        "risk_level": risk_level
    }


# ============================================================
# SIMPLE TEST
# ============================================================

if __name__ == "__main__":

    print(
        "=" * 65
    )

    print(
        "       UC029 QUANTUM INTRUSION DETECTION"
    )

    print(
        "=" * 65
    )

    print(
        "\nModels loaded successfully."
    )

    # --------------------------------------------------------
    # Classical model
    # --------------------------------------------------------

    print(
        "\nClassical model:"
    )

    print(
        type(rf_model)
    )

    # --------------------------------------------------------
    # Quantum SVM
    # --------------------------------------------------------

    print(
        "\nQuantum SVM:"
    )

    print(
        type(quantum_svm)
    )

    # --------------------------------------------------------
    # Quantum Kernel
    # --------------------------------------------------------

    print(
        "\nQuantum Kernel:"
    )

    print(
        type(quantum_kernel)
    )

    # --------------------------------------------------------
    # Selected features
    # --------------------------------------------------------

    print(
        "\nSelected Quantum Features:"
    )

    for feature in SELECTED_FEATURES:

        print(
            " -",
            feature
        )

    # --------------------------------------------------------
    # Reference data
    # --------------------------------------------------------

    print(
        "\nQuantum reference data shape:"
    )

    print(
        X6_train_small.shape
    )

    # --------------------------------------------------------
    # Ready
    # --------------------------------------------------------

    print(
        "\nPrediction pipeline ready."
    )

    print(
        "=" * 65
    )