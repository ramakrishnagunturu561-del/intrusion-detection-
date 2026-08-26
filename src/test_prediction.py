from prediction import (
    rf_model,
    quantum_svm,
    quantum_scaler,
    quantum_kernel,
    X6_train_small,
    SELECTED_FEATURES,
    LABEL_MAP
)

import numpy as np


print("=" * 65)
print("        UC029 SAVED MODEL TEST")
print("=" * 65)


# ============================================================
# CHECK LOADED FILES
# ============================================================

print("\n[1] Checking loaded models...")

print("Random Forest :", type(rf_model))
print("Quantum SVM   :", type(quantum_svm))
print("Quantum Scaler:", type(quantum_scaler))
print("Quantum Kernel:", type(quantum_kernel))

print("\nSelected features:")
for feature in SELECTED_FEATURES:
    print(" -", feature)

print("\nQuantum training data shape:")
print(X6_train_small.shape)


# ============================================================
# CHECK QUANTUM MODEL
# ============================================================

print("\n[2] Checking Quantum SVM...")

print("Quantum SVM parameters:")
print(quantum_svm)


# ============================================================
# TEST WITH A SAMPLE
# ============================================================
#
# IMPORTANT:
# This is only a technical test sample.
# We use six numeric values matching the six selected features.
#

sample = np.array([[
    0.0,       # Init_Win_bytes_forward
    0.0,       # Fwd Packet Length Max
    0.0,       # Bwd Packet Length Max
    0.0,       # Avg Fwd Segment Size
    0.0,       # Avg Bwd Segment Size
    0.0        # Total Length of Fwd Packets
]])


# ============================================================
# SCALE SAMPLE
# ============================================================

print("\n[3] Scaling test sample...")

sample_scaled = quantum_scaler.transform(sample)

print("Scaled sample:")
print(sample_scaled)


# ============================================================
# QUANTUM KERNEL
# ============================================================

print("\n[4] Calculating quantum kernel...")

K_sample = quantum_kernel.evaluate(
    x_vec=sample_scaled,
    y_vec=X6_train_small
)

print("Quantum kernel shape:")
print(K_sample.shape)


# ============================================================
# QUANTUM PREDICTION
# ============================================================

print("\n[5] Quantum prediction...")

quantum_raw = quantum_svm.predict(K_sample)

quantum_label = LABEL_MAP.get(
    int(quantum_raw[0]),
    str(quantum_raw[0])
)

print("Quantum raw prediction:", quantum_raw[0])
print("Quantum label:", quantum_label)


# ============================================================
# FINAL RESULT
# ============================================================

print("\n" + "=" * 65)
print("              TEST COMPLETED")
print("=" * 65)

print("Quantum Prediction:", quantum_label)

print("\nIf you see the prediction above without an error,")
print("the saved Quantum model is working correctly.")

print("=" * 65)
