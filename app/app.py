import sys
import os
import streamlit as st
import pandas as pd

# Allow importing from src
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

SRC_DIR = os.path.join(PROJECT_ROOT, "src")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from prediction import (
    classical_predict,
    quantum_predict,
    SELECTED_FEATURES
)


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="UC029 Quantum IDS",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# TITLE
# ============================================================

st.title("🛡️ UC029 Quantum Intrusion Detection")

st.write(
    "Network traffic classification using "
    "Classical Random Forest and Quantum SVM."
)

st.divider()


# ============================================================
# INPUT
# ============================================================

st.subheader("Network Traffic Input")

st.info(
    "Enter the six features required by the Quantum SVM."
)


col1, col2 = st.columns(2)


with col1:

    init_win = st.number_input(
        "Init Win Bytes Forward",
        value=410.0
    )

    fwd_max = st.number_input(
        "Fwd Packet Length Max",
        value=0.0
    )

    bwd_max = st.number_input(
        "Bwd Packet Length Max",
        value=0.0
    )


with col2:

    avg_fwd = st.number_input(
        "Avg Fwd Segment Size",
        value=0.0
    )

    avg_bwd = st.number_input(
        "Avg Bwd Segment Size",
        value=0.0
    )

    total_fwd = st.number_input(
        "Total Length of Fwd Packets",
        value=0.0
    )


# ============================================================
# DETECTION
# ============================================================

if st.button(
    "🔍 DETECT TRAFFIC",
    use_container_width=True
):

    # Build the input record
    data = {

        "Init_Win_bytes_forward": init_win,

        "Fwd Packet Length Max": fwd_max,

        "Bwd Packet Length Max": bwd_max,

        "Avg Fwd Segment Size": avg_fwd,

        "Avg Bwd Segment Size": avg_bwd,

        "Total Length of Fwd Packets": total_fwd
    }

    df = pd.DataFrame([data])


    # ========================================================
    # QUANTUM PREDICTION
    # ========================================================

    with st.spinner(
        "Running Quantum SVM..."
    ):

        try:

            quantum_raw, quantum_label = quantum_predict(df)

        except Exception as e:

            st.error(
                f"Quantum prediction failed: {e}"
            )

            st.stop()


    # ========================================================
    # CLASSICAL PREDICTION
    # ========================================================

    # The Random Forest was trained with the original
    # feature structure, so six-feature input cannot safely
    # be sent to it.
    #
    # Therefore, for now we display the Quantum result and
    # keep Classical prediction unavailable from this UI.

    classical_label = "NOT AVAILABLE"


    # ========================================================
    # FINAL RESULT
    # ========================================================

    if quantum_raw == 1:

        final_result = "ATTACK"
        risk_level = "HIGH"

    else:

        final_result = "BENIGN"
        risk_level = "LOW"


    # ========================================================
    # RESULTS
    # ========================================================

    st.divider()

    st.subheader("Detection Result")


    col1, col2, col3 = st.columns(3)


    with col1:

        st.metric(
            "Quantum SVM",
            quantum_label
        )


    with col2:

        st.metric(
            "Final Detection",
            final_result
        )


    with col3:

        st.metric(
            "Risk Level",
            risk_level
        )


    # ========================================================
    # STATUS
    # ========================================================

    if final_result == "ATTACK":

        st.error(
            "⚠️ Suspicious network traffic detected!"
        )

    else:

        st.success(
            "✅ Network traffic appears benign."
        )
