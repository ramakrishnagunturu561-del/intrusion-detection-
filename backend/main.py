import sys
import os
import json
import io
import time
import shutil
import tempfile
import subprocess
import warnings

from typing import Dict, Any, Optional

import pandas as pd

from pydantic import BaseModel

from fastapi import (
    FastAPI,
    HTTPException,
    UploadFile,
    File
)

from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# WARNINGS
# ============================================================

warnings.filterwarnings(
    "ignore"
)


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


if PROJECT_ROOT not in sys.path:

    sys.path.insert(
        0,
        PROJECT_ROOT
    )


if SRC_DIR not in sys.path:

    sys.path.insert(
        0,
        SRC_DIR
    )


# ============================================================
# IMPORT ML PIPELINE
# ============================================================

from prediction import (
    detect_intrusion,
    SELECTED_FEATURES
)

from flow_extractor import (
    extract_flows_from_pcap,
    FEATURE_NAMES
)


# ============================================================
# TSHARK PATH
# ============================================================

def get_tshark_path() -> Optional[str]:

    t_path = shutil.which(
        "tshark"
    )

    if t_path:

        return t_path

    win_path = (
        r"C:\Program Files\Wireshark\tshark.exe"
    )

    if os.path.exists(win_path):

        return win_path

    return None


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(

    title=(
        "UC029 Quantum Intrusion Detection API"
    ),

    description=(
        "Hybrid Quantum-Classical Network "
        "Intrusion Detection System using "
        "Random Forest and Quantum SVM "
        "with Live TShark PCAP Capture."
    ),

    version="1.1.0"
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
# HEALTH
# ============================================================

@app.get("/health")
def health_check():

    tshark_path = (
        get_tshark_path()
    )

    return {

        "system":
            "UC029 Quantum Intrusion Detection API",

        "status":
            "ONLINE",

        "tshark_installed":
            tshark_path is not None,

        "tshark_path":
            tshark_path,

        "classical_model":
            "Random Forest (78 features)",

        "quantum_model":
            "Fidelity Quantum Kernel + Quantum SVM (6 features)",

        "quantum_features":
            SELECTED_FEATURES,

        "quantum_feature_count":
            len(SELECTED_FEATURES),

        "decision_policy": {

            "both_benign":
                "BENIGN / LOW",

            "both_attack":
                "ATTACK / HIGH",

            "model_disagreement":
                "SUSPICIOUS / MEDIUM"
        }
    }


# ============================================================
# INTERFACES
# ============================================================

@app.get("/interfaces")
def list_interfaces():

    tshark_path = (
        get_tshark_path()
    )

    if not tshark_path:

        return {

            "success": False,

            "error":
                "TShark executable not found.",

            "interfaces": []
        }

    try:

        cmd_str = (
            f'"{tshark_path}" -D'
        )

        res = subprocess.run(

            cmd_str,

            capture_output=True,

            text=True,

            timeout=10,

            shell=True
        )

        output_text = (
            res.stdout
            if res.stdout
            else res.stderr
        )

        lines = (
            output_text.strip().splitlines()
            if output_text
            else []
        )

        interfaces = []

        for line in lines:

            line = line.strip()

            if not line:

                continue

            parts = line.split(
                ". ",
                1
            )

            idx = (
                parts[0]
                if len(parts) > 1
                else ""
            )

            rest = (
                parts[1]
                if len(parts) > 1
                else line
            )

            friendly_name = rest

            device_id = rest

            if (
                "(" in rest
                and rest.endswith(")")
            ):

                friendly_name = (
                    rest[
                        rest.rfind("(") + 1:
                        -1
                    ]
                )

                device_id = (
                    rest[
                        :rest.rfind("(")
                    ].strip()
                )

            interfaces.append({

                "id":
                    idx,

                "name":
                    friendly_name,

                "device":
                    device_id,

                "raw":
                    line
            })

        return {

            "success":
                True,

            "interfaces":
                interfaces
        }

    except Exception as e:

        return {

            "success":
                False,

            "error":
                str(e),

            "interfaces":
                []
        }


# ============================================================
# LIVE CAPTURE REQUEST
# ============================================================

class LiveCaptureRequest(BaseModel):

    interface: str = "4"

    duration: int = 5

    packet_count: Optional[int] = None


# ============================================================
# HELPER:
# CAPTURE OVERALL DECISION
# ============================================================

def calculate_overall_decision(
    processed_flows
):

    attack_count = 0

    suspicious_count = 0

    benign_count = 0

    for flow in processed_flows:

        result = flow[
            "final_prediction"
        ]

        if result == "ATTACK":

            attack_count += 1

        elif result == "SUSPICIOUS":

            suspicious_count += 1

        else:

            benign_count += 1

    # --------------------------------------------------------
    # Overall policy
    # --------------------------------------------------------

    if attack_count > 0:

        overall_prediction = (
            "ATTACK"
        )

        overall_risk = (
            "HIGH"
        )

    elif suspicious_count > 0:

        overall_prediction = (
            "SUSPICIOUS"
        )

        overall_risk = (
            "MEDIUM"
        )

    else:

        overall_prediction = (
            "BENIGN"
        )

        overall_risk = (
            "LOW"
        )

    return (
        attack_count,
        suspicious_count,
        benign_count,
        overall_prediction,
        overall_risk
    )


# ============================================================
# LIVE CAPTURE
# ============================================================

@app.post("/capture-live")
def capture_live(
    req: LiveCaptureRequest
):

    tshark_path = (
        get_tshark_path()
    )

    if not tshark_path:

        raise HTTPException(

            status_code=500,

            detail=(
                "TShark not found on host system. "
                "Please install Wireshark."
            )
        )

    # --------------------------------------------------------
    # Duration safety
    # --------------------------------------------------------

    duration = max(
        1,
        min(req.duration, 30)
    )

    # --------------------------------------------------------
    # Temporary PCAP
    # --------------------------------------------------------

    temp_dir = (
        tempfile.gettempdir()
    )

    pcap_filename = (
        f"capture_{int(time.time())}.pcap"
    )

    pcap_path = os.path.join(
        temp_dir,
        pcap_filename
    )

    # --------------------------------------------------------
    # TShark command
    # --------------------------------------------------------

    cmd_str = (
        f'"{tshark_path}" '
        f'-i {req.interface} '
        f'-a duration:{duration} '
        f'-w "{pcap_path}"'
    )

    if (
        req.packet_count
        and req.packet_count > 0
    ):

        cmd_str += (
            f" -c {req.packet_count}"
        )

    try:

        proc_start = time.time()

        res = subprocess.run(

            cmd_str,

            capture_output=True,

            text=True,

            timeout=duration + 15,

            shell=True
        )

        capture_time = round(
            time.time() - proc_start,
            2
        )

        # ----------------------------------------------------
        # Verify PCAP
        # ----------------------------------------------------

        if not os.path.exists(
            pcap_path
        ):

            raise RuntimeError(
                "TShark did not create a PCAP file."
            )

        # ----------------------------------------------------
        # Extract flows
        # ----------------------------------------------------

        extracted_flows = (
            extract_flows_from_pcap(
                pcap_path
            )
        )

        # ----------------------------------------------------
        # Cleanup
        # ----------------------------------------------------

        if os.path.exists(
            pcap_path
        ):

            try:

                os.remove(
                    pcap_path
                )

            except Exception:

                pass

        # ----------------------------------------------------
        # Process flows
        # ----------------------------------------------------

        processed_flows = []

        for item in extracted_flows:

            meta = item[
                "flow_meta"
            ]

            feats = item[
                "features"
            ]

            # ------------------------------------------------
            # Hybrid ML
            # ------------------------------------------------

            ml_res = detect_intrusion(
                feats
            )

            # ------------------------------------------------
            # Quantum features
            # ------------------------------------------------

            q_features_extracted = {

                k:
                    feats.get(
                        k,
                        0.0
                    )

                for k in SELECTED_FEATURES
            }

            # ------------------------------------------------
            # Flow result
            # ------------------------------------------------

            processed_flows.append({

                "flow_id":
                    f"FLOW-{len(processed_flows)+1:03d}",

                "src_ip":
                    meta["src_ip"],

                "src_port":
                    meta["src_port"],

                "dst_ip":
                    meta["dst_ip"],

                "dst_port":
                    meta["dst_port"],

                "protocol":
                    meta["protocol"],

                "packets_count":
                    meta["packets_count"],

                "duration_ms":
                    meta["duration_ms"],

                "classical_prediction":
                    ml_res[
                        "classical_prediction"
                    ],

                "quantum_prediction":
                    ml_res[
                        "quantum_prediction"
                    ],

                "final_prediction":
                    ml_res[
                        "final_prediction"
                    ],

                "risk_level":
                    ml_res[
                        "risk_level"
                    ],

                "quantum_features":
                    q_features_extracted,

                "all_features":
                    feats
            })

        # ----------------------------------------------------
        # Overall result
        # ----------------------------------------------------

        (
            attack_count,
            suspicious_count,
            benign_count,
            overall_prediction,
            overall_risk
        ) = calculate_overall_decision(
            processed_flows
        )

        # ----------------------------------------------------
        # Response
        # ----------------------------------------------------

        return {

            "success":
                True,

            "interface_used":
                req.interface,

            "duration_requested":
                duration,

            "actual_capture_time_sec":
                capture_time,

            "total_flows_analyzed":
                len(processed_flows),

            "attack_flows_detected":
                attack_count,

            "suspicious_flows_detected":
                suspicious_count,

            "benign_flows_detected":
                benign_count,

            "overall_prediction":
                overall_prediction,

            "overall_risk_level":
                overall_risk,

            "flows":
                processed_flows
        }

    except subprocess.TimeoutExpired:

        raise HTTPException(

            status_code=504,

            detail=(
                "TShark capture timed out."
            )
        )

    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=(
                f"Live capture error: {str(e)}"
            )
        )


# ============================================================
# JSON PREDICTION
# ============================================================

@app.post("/predict")
def predict_traffic(
    traffic: Dict[str, Any]
):

    try:

        if not traffic:

            raise HTTPException(

                status_code=400,

                detail=(
                    "Empty traffic data provided."
                )
            )

        result = detect_intrusion(
            traffic
        )

        return {

            "success":
                True,

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

        if not file.filename:

            raise HTTPException(

                status_code=400,

                detail="Filename is missing."
            )

        filename = (
            file.filename.lower()
        )

        contents = await file.read()

        if not contents:

            raise HTTPException(

                status_code=400,

                detail="Uploaded file is empty."
            )

        # ====================================================
        # PCAP / PCAPNG
        # ====================================================

        if (
            filename.endswith(".pcap")
            or filename.endswith(".pcapng")
        ):

            temp_dir = (
                tempfile.gettempdir()
            )

            pcap_path = os.path.join(

                temp_dir,

                f"upload_"
                f"{int(time.time())}_"
                f"{file.filename}"
            )

            with open(
                pcap_path,
                "wb"
            ) as f:

                f.write(
                    contents
                )

            try:

                extracted_flows = (
                    extract_flows_from_pcap(
                        pcap_path
                    )
                )

            finally:

                if os.path.exists(
                    pcap_path
                ):

                    try:

                        os.remove(
                            pcap_path
                        )

                    except Exception:

                        pass

            processed_flows = []

            for item in extracted_flows:

                meta = item[
                    "flow_meta"
                ]

                feats = item[
                    "features"
                ]

                ml_res = detect_intrusion(
                    feats
                )

                q_features_extracted = {

                    k:
                        feats.get(
                            k,
                            0.0
                        )

                    for k in SELECTED_FEATURES
                }

                processed_flows.append({

                    "flow_id":
                        f"FLOW-{len(processed_flows)+1:03d}",

                    "src_ip":
                        meta["src_ip"],

                    "src_port":
                        meta["src_port"],

                    "dst_ip":
                        meta["dst_ip"],

                    "dst_port":
                        meta["dst_port"],

                    "protocol":
                        meta["protocol"],

                    "packets_count":
                        meta["packets_count"],

                    "duration_ms":
                        meta["duration_ms"],

                    "classical_prediction":
                        ml_res[
                            "classical_prediction"
                        ],

                    "quantum_prediction":
                        ml_res[
                            "quantum_prediction"
                        ],

                    "final_prediction":
                        ml_res[
                            "final_prediction"
                        ],

                    "risk_level":
                        ml_res[
                            "risk_level"
                        ],

                    "quantum_features":
                        q_features_extracted
                })

            (
                attack_count,
                suspicious_count,
                benign_count,
                overall_prediction,
                overall_risk
            ) = calculate_overall_decision(
                processed_flows
            )

            return {

                "success":
                    True,

                "filename":
                    file.filename,

                "file_type":
                    "PCAP Network Capture",

                "total_flows_analyzed":
                    len(processed_flows),

                "attack_flows_detected":
                    attack_count,

                "suspicious_flows_detected":
                    suspicious_count,

                "benign_flows_detected":
                    benign_count,

                "overall_prediction":
                    overall_prediction,

                "risk_level":
                    overall_risk,

                "flows":
                    processed_flows
            }

        # ====================================================
        # JSON
        # ====================================================

        elif filename.endswith(".json"):

            try:

                data = json.loads(
                    contents.decode(
                        "utf-8"
                    )
                )

            except json.JSONDecodeError:

                raise HTTPException(

                    status_code=400,

                    detail="Invalid JSON file."
                )

            if isinstance(
                data,
                dict
            ):

                record = data

            elif (
                isinstance(data, list)
                and len(data) > 0
            ):

                record = data[0]

            else:

                raise HTTPException(

                    status_code=400,

                    detail=(
                        "JSON must contain "
                        "a non-empty object "
                        "or list."
                    )
                )

            result = detect_intrusion(
                record
            )

            return {

                "success":
                    True,

                "filename":
                    file.filename,

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

        # ====================================================
        # CSV
        # ====================================================

        elif filename.endswith(".csv"):

            try:

                df = pd.read_csv(
                    io.StringIO(
                        contents.decode(
                            "utf-8"
                        )
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

            record = (
                df.iloc[0].to_dict()
            )

            result = detect_intrusion(
                record
            )

            return {

                "success":
                    True,

                "filename":
                    file.filename,

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

        else:

            raise HTTPException(

                status_code=400,

                detail=(
                    "Only JSON, CSV, PCAP, "
                    "and PCAPNG files are supported."
                )
            )

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
            "UC029 Quantum Intrusion Detection System",

        "status":
            "ONLINE",

        "architecture":
            "Hybrid Quantum-Classical ML "
            "(Random Forest + Quantum SVM)",

        "tshark_status":
            (
                "AVAILABLE"
                if get_tshark_path()
                else
                "NOT FOUND"
            ),

        "decision_policy": {

            "BENIGN_BENIGN":
                "BENIGN / LOW",

            "ATTACK_ATTACK":
                "ATTACK / HIGH",

            "MODEL_DISAGREEMENT":
                "SUSPICIOUS / MEDIUM"
        },

        "endpoints": {

            "health":
                "/health",

            "interfaces":
                "/interfaces",

            "capture_live":
                "/capture-live",

            "predict":
                "/predict",

            "predict_file":
                "/predict-file",

            "documentation":
                "/docs"
        }
    }


# ============================================================
# DIRECT RUN
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(

        "backend.main:app",

        host="127.0.0.1",

        port=8000
    )