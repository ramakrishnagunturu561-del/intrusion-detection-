# UC029 Quantum Intrusion Detection System - Chrome & Edge Extension

This folder contains the Manifest V3 browser extension for the **UC029 Hybrid Quantum-Classical Intrusion Detection System**. It provides a real-time cybersecurity monitoring dashboard directly within Google Chrome and Microsoft Edge.

---

## 🎯 Security & Architectural Design

> [!IMPORTANT]
> **Monitoring Interface Framing:**
> The browser extension is a **monitoring and visualization interface**. It detects the current active browser domain using official extension APIs and triggers live network packet capture (`TShark`) through the local FastAPI backend. The underlying network traffic is processed into 78 network-flow features and analyzed using **Random Forest (78 features)** and **Qiskit Fidelity Quantum Kernel + Quantum SVM (6 selected features)**.
>
> The extension does **not** claim to block attacks, decrypt HTTPS, or parse private app payloads inside the browser. It communicates exclusively with the local FastAPI backend over HTTP (`http://127.0.0.1:8080`).

---

## 📁 File Structure

```
extension/
├── manifest.json       # Manifest V3 extension configuration & permission definitions
├── background.js       # Background service worker for badge updates & polling
├── popup.html          # Cyber-themed extension dashboard UI
├── popup.css           # Vanilla CSS dark cybersecurity design (zero CDN dependencies)
└── popup.js            # Dashboard logic, active domain detection, and API integration
```

---

## 🔒 Permission Disclosures

The extension requests minimal permissions in `manifest.json`:

1. **`activeTab` and `tabs`**: Used strictly to detect the active browser domain (e.g. `youtube.com`, `github.com`) to display active context in the header.
2. **`host_permissions` (`http://127.0.0.1:8080/*`, `http://localhost:8080/*`)**: Required for fetch requests between the browser popup and the local FastAPI backend endpoints (`/health`, `/capture-live`).

---

## ⚙️ Installation Instructions

### 1. Google Chrome Installation
1. Open Google Chrome.
2. Navigate to `chrome://extensions/` in the address bar.
3. Enable **Developer mode** using the toggle in the top-right corner.
4. Click **Load unpacked** in the top-left menu.
5. Select the `extension/` folder located inside the project repository (`c:\Users\bapi0\Downloads\intrusion-detection-\extension`).

### 2. Microsoft Edge Installation
1. Open Microsoft Edge.
2. Navigate to `edge://extensions/` in the address bar.
3. Enable **Developer mode** toggle in the left sidebar menu.
4. Click **Load unpacked**.
5. Select the `extension/` folder inside the project repository (`c:\Users\bapi0\Downloads\intrusion-detection-\extension`).

---

## 🧪 Testing Instructions

### Step 1: Start the FastAPI Backend

Open a terminal in the root project directory and start the FastAPI backend on port `8080`:

```bash
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8080
```

### Step 2: Verify Backend Connection

In your terminal or command prompt, verify the backend health endpoint returns `ONLINE`:

```powershell
curl.exe -s http://127.0.0.1:8080/health
```

Expected output:
```json
{
  "system": "UC029 Quantum Intrusion Detection API",
  "status": "ONLINE",
  "tshark_installed": true,
  "tshark_path": "C:\\Program Files\\Wireshark\\tshark.exe",
  "classical_model": "Random Forest (78 features)",
  "quantum_model": "Fidelity Quantum Kernel + Quantum SVM (6 features)",
  "quantum_features": [
    "Init_Win_bytes_forward",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Avg Bwd Segment Size",
    "Subflow Fwd Bytes"
  ]
}
```

### Step 3: Test the Browser Extension

1. Open your browser (Chrome or Edge).
2. Visit a website (e.g. `https://www.youtube.com` or `https://github.com`).
3. Click the **UC029 Quantum Intrusion Detection** extension icon in your browser toolbar.
4. Verify the active tab domain is identified (`youtube.com` or `github.com`) and the status displays **Backend Online**.
5. Click **Start Monitoring**.
6. The extension will call `POST http://127.0.0.1:8080/capture-live` for 5 seconds, parse the extracted flow features, run the Classical Random Forest and Quantum SVM models, and render the overall risk level along with the flow breakdown table.
7. Optionally toggle **Auto Monitor** to perform automated network checks every 15 seconds.

---

## 🛠 Troubleshooting

- **Backend Offline alert in extension:** Ensure FastAPI is running on `127.0.0.1:8080`. Check `http://127.0.0.1:8080/health` in your browser.
- **TShark executable not found:** Ensure Wireshark is installed at `C:\Program Files\Wireshark\tshark.exe` or available in system `PATH`.
- **Port changes:** If your backend runs on a port other than `8080`, update the `API_BASE_URL` constant at the top of `popup.js` and `background.js`, and adjust `host_permissions` in `manifest.json`.
