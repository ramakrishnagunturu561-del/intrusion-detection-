import sys
import os
import traceback

print("[1] Starting run_server.py...", flush=True)

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
SRC_DIR = os.path.join(PROJECT_ROOT, "src")

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

print("[2] Importing backend.main...", flush=True)
import backend.main
print("[3] backend.main imported successfully!", flush=True)

import uvicorn

if __name__ == "__main__":
    print("[4] Starting uvicorn.run on http://127.0.0.1:8080 ...", flush=True)
    uvicorn.run(backend.main.app, host="127.0.0.1", port=8080)
