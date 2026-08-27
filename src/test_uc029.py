import json
import pandas as pd

from prediction import (
    classical_predict,
    quantum_predict,
    SELECTED_FEATURES,
    quantum_scaler,
    quantum_kernel,
    X6_train_small
)


print("=" * 65)
print("          UC-029 FINAL MODEL TEST")
print("=" * 65)


# ============================================================
# LOAD REAL UC-029 DATA
# ============================================================

with open(
    "data/UC029_test_row.json",
    "r"
) as f:
    uc029 = json.load(f)


df = pd.DataFrame([uc029])


print(
    f"\nOriginal UC-029 features: {len(df.columns)}"
)

assert len(df.columns) == 78, (
    "UC-029 must have exactly 78 features"
)


# ============================================================
# QUANTUM REFERENCE DATA
# ============================================================

print(
    f"\nQuantum reference data shape: "
    f"{X6_train_small.shape}"
)

assert X6_train_small.shape == (100, 6), (
    "Quantum reference data must be (100, 6)"
)


# ============================================================
# SELECTED QUANTUM FEATURES
# ============================================================

print(
    f"\nSelected Quantum features: "
    f"{len(SELECTED_FEATURES)}"
)

assert len(SELECTED_FEATURES) == 6, (
    "Must have exactly 6 quantum features"
)


print("\nQuantum features:")

for feature in SELECTED_FEATURES:
    print(" -", feature)


# ============================================================
# VERIFY ALL QUANTUM FEATURES EXIST
# ============================================================

missing = [
    feature
    for feature in SELECTED_FEATURES
    if feature not in df.columns
]

assert not missing, (
    f"Missing Quantum features: {missing}"
)


# ============================================================
# QUANTUM FEATURE PREPARATION
# ============================================================

# IMPORTANT:
# Keep this as a pandas DataFrame.
# Do NOT use .values here.
#
# This preserves the feature names expected by
# the fitted MinMaxScaler.

X6 = df[
    SELECTED_FEATURES
].astype(float)


print("\nQuantum input:")

print(X6)


# ============================================================
# QUANTUM SCALING
# ============================================================

X6_scaled = quantum_scaler.transform(
    X6
)


print("\nQuantum scaled input:")

print(X6_scaled)


# ============================================================
# QUANTUM KERNEL
# ============================================================

print(
    "\nCalculating Quantum Kernel..."
)

K_test = quantum_kernel.evaluate(
    x_vec=X6_scaled,
    y_vec=X6_train_small
)


print(
    f"Quantum kernel for one sample shape: "
    f"{K_test.shape}"
)


assert K_test.shape == (1, 100), (
    "Quantum kernel shape must be (1, 100)"
)


# ============================================================
# CLASSICAL RANDOM FOREST
# ============================================================

print(
    "\n[1] Classical Random Forest prediction..."
)


classical_raw, classical_label = classical_predict(
    df
)


print(
    "Classical raw prediction :",
    classical_raw
)

print(
    "Classical result         :",
    classical_label
)


assert classical_raw in [0, 1], (
    "Classical prediction must be 0 or 1"
)


# ============================================================
# QUANTUM SVM
# ============================================================

print(
    "\n[2] Quantum SVM prediction..."
)


quantum_raw, quantum_label = quantum_predict(
    df
)


print(
    "Quantum raw prediction   :",
    quantum_raw
)

print(
    "Quantum result           :",
    quantum_label
)


assert quantum_raw in [0, 1], (
    "Quantum prediction must be 0 or 1"
)


# ============================================================
# FINAL DECISION
# ============================================================

if (
    classical_raw == 1
    or
    quantum_raw == 1
):

    final_result = "ATTACK"
    risk_level = "HIGH"

else:

    final_result = "BENIGN"
    risk_level = "LOW"


# ============================================================
# FINAL UC-029 RESULT
# ============================================================

print(
    "\n" + "=" * 65
)

print(
    "             FINAL UC-029 DETECTION"
)

print(
    "=" * 65
)

print(
    "Classical :",
    classical_label
)

print(
    "Quantum   :",
    quantum_label
)

print(
    "Final     :",
    final_result
)

print(
    "Risk      :",
    risk_level
)

print(
    "=" * 65
)


# ============================================================
# SUCCESS MESSAGE
# ============================================================

print(
    "\nUC-029 test completed successfully."
)

print(
    "Classical ML + Quantum ML pipeline is working."
)