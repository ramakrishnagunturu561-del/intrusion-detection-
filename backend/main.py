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

warnings.filterwarnings("ignore")


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
    sys.path.insert(0, PROJECT_ROOT)

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


# ============================================================
# IMPORT PREDICTION & FLOW EXTRACTION PIPELINE
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
# TSHARK PATH DETECTOR
# ============================================================

def get_tshark_path() -> Optional[str]:
    t_path = shutil.which("tshark")
    if t_path:
        return t_path
    
    win_path = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(win_path):
        return win_path
    
    return None


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="UC029 Quantum Intrusion Detection API",
    description=(
        "Hybrid Quantum-Classical Network "
        "Intrusion Detection System using "
        "Random Forest and Quantum SVM with Live TShark PCAP Capture."
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
    tshark_path = get_tshark_path()
    return {
        "system": "UC029 Quantum Intrusion Detection API",
        "status": "ONLINE",
        "tshark_installed": tshark_path is not None,
        "tshark_path": tshark_path,
        "classical_model": "Random Forest (78 features)",
        "quantum_model": "Fidelity Quantum Kernel + Quantum SVM (6 features)",
        "quantum_features": SELECTED_FEATURES,
        "quantum_feature_count": len(SELECTED_FEATURES)
    }


# ============================================================
# TSHARK INTERFACES LIST
# ============================================================

@app.get("/interfaces")
def list_interfaces():
    tshark_path = get_tshark_path()
    if not tshark_path:
        return {
            "success": False,
            "error": "TShark executable not found on host system.",
            "interfaces": []
        }

    try:
        cmd_str = f'"{tshark_path}" -D'
        res = subprocess.run(cmd_str, capture_output=True, text=True, timeout=10, shell=True)
        
        output_text = res.stdout if res.stdout else res.stderr
        lines = output_text.strip().splitlines() if output_text else []
        
        interfaces = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parts = line.split(". ", 1)
            idx = parts[0] if len(parts) > 1 else ""
            rest = parts[1] if len(parts) > 1 else line
            
            friendly_name = rest
            device_id = rest
            if "(" in rest and rest.endswith(")"):
                friendly_name = rest[rest.rfind("(")+1:-1]
                device_id = rest[:rest.rfind("(")].strip()

            interfaces.append({
                "id": idx,
                "name": friendly_name,
                "device": device_id,
                "raw": line
            })

        return {
            "success": True,
            "interfaces": interfaces
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "interfaces": []
        }



# ============================================================
# LIVE CAPTURE REQUEST MODEL
# ============================================================

class LiveCaptureRequest(BaseModel):
    interface: str = "4"
    duration: int = 5
    packet_count: Optional[int] = None


# ============================================================
# LIVE CAPTURE & INFERENCE ENDPOINT
# ============================================================

@app.post("/capture-live")
def capture_live(req: LiveCaptureRequest):
    tshark_path = get_tshark_path()
    if not tshark_path:
        raise HTTPException(
            status_code=500,
            detail="TShark not found on host system. Please install Wireshark."
        )

    duration = max(1, min(req.duration, 30))
    temp_dir = tempfile.gettempdir()
    pcap_filename = f"capture_{int(time.time())}.pcap"
    pcap_path = os.path.join(temp_dir, pcap_filename)

    cmd_str = f'"{tshark_path}" -i {req.interface} -a duration:{duration} -w "{pcap_path}"'
    if req.packet_count and req.packet_count > 0:
        cmd_str += f' -c {req.packet_count}'

    try:
        proc_start = time.time()
        res = subprocess.run(cmd_str, capture_output=True, text=True, timeout=duration + 10, shell=True)
        capture_time = round(time.time() - proc_start, 2)


        # Process PCAP file with flow extractor
        extracted_flows = extract_flows_from_pcap(pcap_path)
        
        # Cleanup temp file
        if os.path.exists(pcap_path):
            try:
                os.remove(pcap_path)
            except Exception:
                pass

        processed_flows = []
        attack_count = 0
        benign_count = 0

        for item in extracted_flows:
            meta = item["flow_meta"]
            feats = item["features"]

            # Run Hybrid ML Pipeline (RF + Quantum SVM)
            ml_res = detect_intrusion(feats)

            if ml_res["final_prediction"] == "ATTACK":
                attack_count += 1
            else:
                benign_count += 1

            # Extract key 6 quantum features for visibility
            q_features_extracted = {k: feats.get(k, 0.0) for k in SELECTED_FEATURES}

            processed_flows.append({
                "flow_id": f"FLOW-{len(processed_flows)+1:03d}",
                "src_ip": meta["src_ip"],
                "src_port": meta["src_port"],
                "dst_ip": meta["dst_ip"],
                "dst_port": meta["dst_port"],
                "protocol": meta["protocol"],
                "packets_count": meta["packets_count"],
                "duration_ms": meta["duration_ms"],
                "classical_prediction": ml_res["classical_prediction"],
                "quantum_prediction": ml_res["quantum_prediction"],
                "final_prediction": ml_res["final_prediction"],
                "risk_level": ml_res["risk_level"],
                "quantum_features": q_features_extracted,
                "all_features": feats
            })

        overall_prediction = "ATTACK" if attack_count > 0 else "BENIGN"
        overall_risk = "HIGH" if attack_count > 0 else "LOW"

        return {
            "success": True,
            "interface_used": req.interface,
            "duration_requested": duration,
            "actual_capture_time_sec": capture_time,
            "total_flows_analyzed": len(processed_flows),
            "attack_flows_detected": attack_count,
            "benign_flows_detected": benign_count,
            "overall_prediction": overall_prediction,
            "overall_risk_level": overall_risk,
            "flows": processed_flows
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="TShark capture timed out."
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Live capture error: {str(e)}"
        )


# ============================================================
# JSON PREDICTION
# ============================================================

@app.post("/predict")
def predict_traffic(traffic: Dict[str, Any]):
    try:
        if not traffic:
            raise HTTPException(
                status_code=400,
                detail="Empty traffic data provided."
            )

        result = detect_intrusion(traffic)

        return {
            "success": True,
            "classical_prediction": result["classical_prediction"],
            "quantum_prediction": result["quantum_prediction"],
            "final_prediction": result["final_prediction"],
            "risk_level": result["risk_level"]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# PCAP / JSON / CSV FILE PREDICTION
# ============================================================

@app.post("/predict-file")
async def predict_file(file: UploadFile = File(...)):
    try:
        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail="Filename is missing."
            )

        filename = file.filename.lower()
        contents = await file.read()

        if not contents:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty."
            )

        # ----------------------------------------------------
        # PCAP / PCAPNG FILE
        # ----------------------------------------------------
        if filename.endswith(".pcap") or filename.endswith(".pcapng"):
            temp_dir = tempfile.gettempdir()
            pcap_path = os.path.join(temp_dir, f"upload_{int(time.time())}_{file.filename}")
            
            with open(pcap_path, "wb") as f:
                f.write(contents)

            try:
                extracted_flows = extract_flows_from_pcap(pcap_path)
            finally:
                if os.path.exists(pcap_path):
                    try:
                        os.remove(pcap_path)
                    except Exception:
                        pass

            processed_flows = []
            attack_count = 0

            for item in extracted_flows:
                meta = item["flow_meta"]
                feats = item["features"]

                ml_res = detect_intrusion(feats)
                if ml_res["final_prediction"] == "ATTACK":
                    attack_count += 1

                q_features_extracted = {k: feats.get(k, 0.0) for k in SELECTED_FEATURES}

                processed_flows.append({
                    "flow_id": f"FLOW-{len(processed_flows)+1:03d}",
                    "src_ip": meta["src_ip"],
                    "src_port": meta["src_port"],
                    "dst_ip": meta["dst_ip"],
                    "dst_port": meta["dst_port"],
                    "protocol": meta["protocol"],
                    "packets_count": meta["packets_count"],
                    "duration_ms": meta["duration_ms"],
                    "classical_prediction": ml_res["classical_prediction"],
                    "quantum_prediction": ml_res["quantum_prediction"],
                    "final_prediction": ml_res["final_prediction"],
                    "risk_level": ml_res["risk_level"],
                    "quantum_features": q_features_extracted
                })

            overall_pred = "ATTACK" if attack_count > 0 else "BENIGN"
            overall_risk = "HIGH" if attack_count > 0 else "LOW"

            first_flow = processed_flows[0] if processed_flows else {}

            return {
                "success": True,
                "filename": file.filename,
                "file_type": "PCAP Network Capture",
                "total_flows_analyzed": len(processed_flows),
                "attack_flows_detected": attack_count,
                "classical_prediction": first_flow.get("classical_prediction", overall_pred),
                "quantum_prediction": first_flow.get("quantum_prediction", overall_pred),
                "final_prediction": overall_pred,
                "risk_level": overall_risk,
                "flows": processed_flows
            }

        # ----------------------------------------------------
        # JSON FILE
        # ----------------------------------------------------
        elif filename.endswith(".json"):
            try:
                data = json.loads(contents.decode("utf-8"))
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid JSON file."
                )

            if isinstance(data, dict):
                record = data
            elif isinstance(data, list) and len(data) > 0:
                record = data[0]
            else:
                raise HTTPException(
                    status_code=400,
                    detail="JSON must contain a non-empty object or list."
                )

            result = detect_intrusion(record)

            return {
                "success": True,
                "filename": file.filename,
                "classical_prediction": result["classical_prediction"],
                "quantum_prediction": result["quantum_prediction"],
                "final_prediction": result["final_prediction"],
                "risk_level": result["risk_level"]
            }

        # ----------------------------------------------------
        # CSV FILE
        # ----------------------------------------------------
        elif filename.endswith(".csv"):
            try:
                df = pd.read_csv(io.StringIO(contents.decode("utf-8")))
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unable to read CSV: {str(e)}"
                )

            if df.empty:
                raise HTTPException(
                    status_code=400,
                    detail="CSV file is empty."
                )

            record = df.iloc[0].to_dict()
            result = detect_intrusion(record)

            return {
                "success": True,
                "filename": file.filename,
                "classical_prediction": result["classical_prediction"],
                "quantum_prediction": result["quantum_prediction"],
                "final_prediction": result["final_prediction"],
                "risk_level": result["risk_level"]
            }

        else:
            raise HTTPException(
                status_code=400,
                detail="Only JSON, CSV, PCAP, and PCAPNG files are supported."
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():
    return {
        "project": "UC029 Quantum Intrusion Detection System",
        "status": "ONLINE",
        "architecture": "Hybrid Quantum-Classical ML (Random Forest + Quantum SVM)",
        "tshark_status": "AVAILABLE" if get_tshark_path() else "NOT FOUND",
        "endpoints": {
            "health": "/health",
            "interfaces": "/interfaces",
            "capture_live": "/capture-live",
            "predict": "/predict",
            "predict_file": "/predict-file",
            "documentation": "/docs"
        }
    }


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000)