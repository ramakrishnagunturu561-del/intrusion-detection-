import os
import json
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

# Add project root to path
import sys
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.prediction import classical_predict, quantum_predict, detect_intrusion

def evaluate_models():
    """
    Evaluates Random Forest and Quantum SVM models on the training dataset.
    Normally we would use a dedicated test set, but since we only have
    access to a small sample of data locally, we'll evaluate on the loaded samples
    (and some generated attacks for testing).
    """
    print("=" * 60)
    print("MODEL EVALUATION & COMPARISON")
    print("=" * 60)

    # 1. Load Benign Sample (UC029)
    with open(os.path.join(PROJECT_ROOT, "data", "UC029_test_row.json"), "r") as f:
        uc029 = json.load(f)
    
    # 2. Create a Mock Attack Sample for Evaluation
    # (By slightly modifying some features to trigger the attack thresholds)
    attack_row = uc029.copy()
    attack_row["Init_Win_bytes_forward"] = 30000.0
    attack_row["Total Length of Fwd Packets"] = 10000.0
    
    # 3. Create evaluation dataset
    X_test_data = [uc029, attack_row]
    y_true = [0, 1]  # 0: BENIGN, 1: ATTACK

    df = pd.DataFrame(X_test_data)
    
    c_preds = []
    q_preds = []
    
    print("\nRunning predictions on test set...")
    
    for i, row in df.iterrows():
        c_raw, _ = classical_predict(row)
        q_raw, _ = quantum_predict(row)
        
        c_preds.append(c_raw)
        q_preds.append(q_raw)
        
    print("\n[1] Classical Random Forest Results")
    print_metrics(y_true, c_preds)
    
    print("\n[2] Quantum SVM Results")
    print_metrics(y_true, q_preds)
    
def print_metrics(y_true, y_pred):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    try:
        roc_auc = roc_auc_score(y_true, y_pred)
    except ValueError:
        roc_auc = 0.0
        
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    
    # TN, FP, FN, TP
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0

    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print(f"ROC-AUC  : {roc_auc:.4f}")
    print(f"FPR      : {fpr:.4f}")
    print(f"FNR      : {fnr:.4f}")
    print(f"Confusion Matrix:\n{cm}")

if __name__ == "__main__":
    evaluate_models()
