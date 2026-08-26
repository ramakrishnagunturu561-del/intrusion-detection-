import json
import pandas as pd

from prediction import (
    classical_predict,
    quantum_predict,
    SELECTED_FEATURES
)


print("=" * 65)
print("          UC-029 FINAL MODEL TEST")
print("=" * 65)


# ============================================================
# LOAD REAL UC-029 DATA
# ============================================================

with open("data/UC029_test_row.json", "r") as f:
    uc029 = json.load(f)

df = pd.DataFrame([uc029])

print("\nOriginal UC-029 features:", len(df.columns))


# ============================================================
# CLASSICAL RANDOM FOREST
# ============================================================

print("\n[1] Classical Random Forest prediction...")

classical_raw, classical_label = classical_predict(df)

print("Classical raw prediction :", classical_raw)
print("Classical result         :", classical_label)


# ============================================================
# QUANTUM SVM
# ============================================================

print("\n[2] Quantum SVM prediction...")

quantum_raw, quantum_label = quantum_predict(df)

print("Quantum raw prediction   :", quantum_raw)
print("Quantum result           :", quantum_label)


# ============================================================
# FINAL DECISION
# ============================================================

if classical_raw == 1 or quantum_raw == 1:
    final_result = "ATTACK"
    risk_level = "HIGH"
else:
    final_result = "BENIGN"
    risk_level = "LOW"


# ============================================================
# FINAL UC-029 RESULT
# ============================================================

print("\n" + "=" * 65)
print("             FINAL UC-029 DETECTION")
print("=" * 65)

print("Classical :", classical_label)
print("Quantum   :", quantum_label)
print("Final     :", final_result)
print("Risk      :", risk_level)

print("=" * 65)
