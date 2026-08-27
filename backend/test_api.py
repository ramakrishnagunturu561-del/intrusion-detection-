import os
import sys
import json
from fastapi.testclient import TestClient

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.main import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert "selected_features" in data
    assert len(data["selected_features"]) == 6

def test_predict_json():
    # Load test row
    with open(os.path.join(PROJECT_ROOT, "data", "UC029_test_row.json"), "r") as f:
        traffic_data = json.load(f)
    
    response = client.post("/predict", json=traffic_data)
    assert response.status_code == 200
    data = response.json()
    
    assert "classical_prediction" in data
    assert "quantum_prediction" in data
    assert "final_prediction" in data
    assert "risk_level" in data
    
    assert data["classical_prediction"] in ["BENIGN", "ATTACK"]
    assert data["quantum_prediction"] in ["BENIGN", "ATTACK"]

def test_predict_file_endpoint():
    file_path = os.path.join(PROJECT_ROOT, "data", "UC029_test_row.json")
    with open(file_path, "rb") as f:
        # FastAPI test client file upload
        response = client.post("/predict-file", files={"file": ("UC029_test_row.json", f, "application/json")})
    
    assert response.status_code == 200
    data = response.json()
    assert data["final_prediction"] in ["BENIGN", "ATTACK"]
