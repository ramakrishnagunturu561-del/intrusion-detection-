import sys
import os
import json
import io

from typing import Dict, Any

import pandas as pd

from fastapi import (
    FastAPI,
    HTTPException,
    UploadFile,
    File
)

from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

SRC_DIR = os.path.join(
    PROJECT_ROOT,
    "src"
)


if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


# ============================================================
# IMPORT REAL PREDICTION PIPELINE
# ============================================================

from prediction import (
    detect_intrusion,
    SELECTED_FEATURES
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="UC029 Quantum Intrusion Detection API",
    description=(
        "Hybrid Quantum-Classical Network "
        "Intrusion Detection System using "
        "Random Forest and Quantum SVM."
    ),
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"]
)


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health_check():

    return {
        "system": "UC029 Quantum Intrusion Detection API",

        "status": "ONLINE",

        "classical_model": "Random Forest",

        "quantum_model": "Fidelity Quantum Kernel + Quantum SVM",

        "quantum_features": SELECTED_FEATURES,

        "quantum_feature_count": len(
            SELECTED_FEATURES
        )
    }


# ============================================================
# JSON PREDICTION
# ============================================================

@app.post("/predict")
def predict_traffic(
    traffic: Dict[str, Any]
):

    try:

        # ----------------------------------------------------
        # Check input
        # ----------------------------------------------------

        if not traffic:

            raise HTTPException(
                status_code=400,
                detail="Empty traffic data provided."
            )


        # ----------------------------------------------------
        # Run REAL Hybrid ML pipeline
        # ----------------------------------------------------

        result = detect_intrusion(
            traffic
        )


        # ----------------------------------------------------
        # Return prediction
        # ----------------------------------------------------

        return {
            "success": True,

            "classical_prediction":
                result[
                    "classical_prediction"
                ],

            "quantum_prediction":
                result[
                    "quantum_prediction"
                ],

            "final_prediction":
                result[
                    "final_prediction"
                ],

            "risk_level":
                result[
                    "risk_level"
                ]
        }


    except HTTPException:

        raise


    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# FILE PREDICTION
# ============================================================

@app.post("/predict-file")
async def predict_file(
    file: UploadFile = File(...)
):

    try:

        # ----------------------------------------------------
        # Validate filename
        # ----------------------------------------------------

        if not file.filename:

            raise HTTPException(
                status_code=400,
                detail="Filename is missing."
            )


        filename = file.filename.lower()


        if not (
            filename.endswith(".json")
            or
            filename.endswith(".csv")
        ):

            raise HTTPException(
                status_code=400,
                detail=(
                    "Only JSON and CSV files "
                    "are supported."
                )
            )


        # ----------------------------------------------------
        # Read file
        # ----------------------------------------------------

        contents = await file.read()


        if not contents:

            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty."
            )


        # ====================================================
        # JSON
        # ====================================================

        if filename.endswith(".json"):

            try:

                data = json.loads(
                    contents.decode("utf-8")
                )

            except json.JSONDecodeError:

                raise HTTPException(
                    status_code=400,
                    detail="Invalid JSON file."
                )


            # -----------------------------------------------
            # Single JSON object
            # -----------------------------------------------

            if isinstance(
                data,
                dict
            ):

                record = data


            # -----------------------------------------------
            # JSON list
            # -----------------------------------------------

            elif isinstance(
                data,
                list
            ):

                if len(data) == 0:

                    raise HTTPException(
                        status_code=400,
                        detail="JSON list is empty."
                    )


                record = data[0]


            else:

                raise HTTPException(
                    status_code=400,
                    detail=(
                        "JSON must contain "
                        "an object or list."
                    )
                )


        # ====================================================
        # CSV
        # ====================================================

        else:

            try:

                df = pd.read_csv(
                    io.StringIO(
                        contents.decode("utf-8")
                    )
                )

            except Exception as e:

                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Unable to read CSV: {str(e)}"
                    )
                )


            if df.empty:

                raise HTTPException(
                    status_code=400,
                    detail="CSV file is empty."
                )


            # Use first network-flow row
            record = df.iloc[0].to_dict()


        # ====================================================
        # RUN HYBRID PREDICTION
        # ====================================================

        result = detect_intrusion(
            record
        )


        # ====================================================
        # RETURN RESULT
        # ====================================================

        return {

            "success": True,

            "filename": file.filename,

            "classical_prediction":
                result[
                    "classical_prediction"
                ],

            "quantum_prediction":
                result[
                    "quantum_prediction"
                ],

            "final_prediction":
                result[
                    "final_prediction"
                ],

            "risk_level":
                result[
                    "risk_level"
                ]
        }


    except HTTPException:

        raise


    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {

        "project":
            "UC029 Quantum Intrusion Detection",

        "status":
            "ONLINE",

        "architecture":
            "Hybrid Quantum-Classical ML",

        "classical_model":
            "Random Forest",

        "quantum_model":
            "Fidelity Quantum Kernel + Quantum SVM",

        "endpoints": {

            "health":
                "/health",

            "predict":
                "/predict",

            "predict_file":
                "/predict-file",

            "documentation":
                "/docs"
        }
    }


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )