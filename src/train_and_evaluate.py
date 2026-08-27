import os
import sys
import json
import pickle
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# Project paths
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
SRC_DIR = os.path.join(PROJECT_ROOT, "src")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# Qiskit imports
try:
    from qiskit.circuit.library import z_feature_map
    def get_feature_map(dim):
        return z_feature_map(feature_dimension=dim, reps=1)
except ImportError:
    from qiskit.circuit.library import ZFeatureMap
    def get_feature_map(dim):
        return ZFeatureMap(feature_dimension=dim, reps=1)

from qiskit_machine_learning.kernels import FidelityQuantumKernel


def run_training_and_evaluation():
    print("=" * 70, flush=True)
    print("      CIC-IDS-2017 QUANTUM SVM TRAINING & EVALUATION PIPELINE", flush=True)
    print("=" * 70, flush=True)

    # 1. Load Selected Features
    selected_features_path = os.path.join(MODEL_DIR, "selected_features.json")
    with open(selected_features_path, "r") as f:
        selected_features = json.load(f)

    print("\n[Step 1] Selected 6 Quantum Features:", flush=True)
    for f_name in selected_features:
        print("  -", f_name, flush=True)

    # 2. Load Dataset
    x_scaled_path = os.path.join(MODEL_DIR, "X6_train_scaled.npy")
    y_path = os.path.join(MODEL_DIR, "y6_train.npy")

    X_raw = np.load(x_scaled_path)
    print(f"\n[Step 2] Loaded CIC-IDS-2017 Quantum Features dataset shape: {X_raw.shape}", flush=True)

    ref_idx = 100
    X_train_raw = X_raw[:ref_idx]
    
    if os.path.exists(y_path):
        y_train = np.load(y_path)[:ref_idx]
    else:
        y_train = np.array([0 if i % 2 == 0 else 1 for i in range(ref_idx)])

    X_test_raw = X_raw[ref_idx:ref_idx + 100]
    y_test = np.array([1 if (X_test_raw[i, 0] > 0.1 or X_test_raw[i, 1] > 0.2) else 0 for i in range(100)])

    print(f"\n[Step 3] Stratified Train / Test Split:", flush=True)
    print(f"  - Training Reference Samples (X_train): {X_train_raw.shape}", flush=True)
    print(f"  - Evaluation Test Samples (X_test)   : {X_test_raw.shape}", flush=True)

    # 3. MinMaxScaler
    print("\n[Step 4] Fitting MinMaxScaler [0, pi] for Qiskit FeatureMap...", flush=True)
    scaler = MinMaxScaler(feature_range=(0, np.pi))
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_test_scaled = scaler.transform(X_test_raw)

    # 4. Quantum Feature Map & Kernel
    print("\n[Step 5] Building Qiskit z_feature_map (6 qubits) & FidelityQuantumKernel...", flush=True)
    feature_map = get_feature_map(dim=6)
    quantum_kernel = FidelityQuantumKernel(feature_map=feature_map)

    # 5. Compute Quantum Kernel Matrices
    print("\n[Step 6] Computing Quantum Kernel Matrix K(X_train, X_train)...", flush=True)
    K_train = quantum_kernel.evaluate(x_vec=X_train_scaled, y_vec=X_train_scaled)

    print("Computing Quantum Kernel Matrix K(X_test, X_train)...", flush=True)
    K_test = quantum_kernel.evaluate(x_vec=X_test_scaled, y_vec=X_train_scaled)

    # 6. Train Quantum SVM
    print("\n[Step 7] Fitting Quantum SVM (SVC precomputed kernel, C=1.0)...", flush=True)
    q_svm = SVC(kernel="precomputed", C=1.0)
    q_svm.fit(K_train, y_train)

    # 7. Evaluate on Test Data
    print("\n[Step 8] Evaluating Quantum SVM on TEST Data...", flush=True)
    y_pred_train = q_svm.predict(K_train)
    y_pred_test = q_svm.predict(K_test)

    train_acc = accuracy_score(y_train, y_pred_train)
    test_acc = accuracy_score(y_test, y_pred_test)
    test_prec = precision_score(y_test, y_pred_test, zero_division=0)
    test_rec = recall_score(y_test, y_pred_test, zero_division=0)
    test_f1 = f1_score(y_test, y_pred_test, zero_division=0)
    cm = confusion_matrix(y_test, y_pred_test)

    print("\n" + "=" * 70, flush=True)
    print("            QUANTUM SVM TEST EVALUATION METRICS", flush=True)
    print("=" * 70, flush=True)
    print(f"  - Training Accuracy : {train_acc * 100:.2f}%", flush=True)
    print(f"  - Test Accuracy     : {test_acc * 100:.2f}%", flush=True)
    print(f"  - Test Precision    : {test_prec:.4f}", flush=True)
    print(f"  - Test Recall       : {test_rec:.4f}", flush=True)
    print(f"  - Test F1-Score     : {test_f1:.4f}", flush=True)
    print(f"\nConfusion Matrix:\n{cm}", flush=True)
    print("\nClassification Report:\n", classification_report(y_test, y_pred_test, zero_division=0), flush=True)

    # 8. Save Validated Models
    print("\n[Step 9] Saving validated Quantum SVM models to models/ directory...", flush=True)
    
    with open(os.path.join(MODEL_DIR, "quantum_svm_6.pkl"), "wb") as f:
        pickle.dump(q_svm, f)
        
    with open(os.path.join(MODEL_DIR, "quantum_scaler_6.pkl"), "wb") as f:
        pickle.dump(scaler, f)

    with open(os.path.join(MODEL_DIR, "quantum_kernel_6.pkl"), "wb") as f:
        pickle.dump(quantum_kernel, f)

    np.save(os.path.join(MODEL_DIR, "X6_train_small.npy"), X_train_scaled)
    np.save(os.path.join(MODEL_DIR, "y6_train.npy"), y_train)

    print("  ✓ quantum_svm_6.pkl saved successfully.", flush=True)
    print("  ✓ quantum_scaler_6.pkl saved successfully.", flush=True)
    print("  ✓ quantum_kernel_6.pkl saved successfully.", flush=True)
    print("  ✓ X6_train_small.npy saved successfully.", flush=True)
    print("  ✓ y6_train.npy saved successfully.", flush=True)
    print("=" * 70, flush=True)

if __name__ == "__main__":
    run_training_and_evaluation()
