import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

const PRESETS = {
  uc029: {
    name: "UC-029 Benign Benchmark",
    tag: "Verified Sample",
    data: {
      init_win: 410,
      fwd_max: 0,
      bwd_max: 0,
      avg_fwd: 0,
      avg_bwd: 0,
      total_fwd: 0,
    },
  },
  portScan: {
    name: "Port Scan Attack Pattern",
    tag: "High Reconnaissance",
    data: {
      init_win: 29200,
      fwd_max: 1460,
      bwd_max: 1460,
      avg_fwd: 480,
      avg_bwd: 620,
      total_fwd: 2920,
    },
  },
  ddos: {
    name: "DDoS Volumetric Burst",
    tag: "Critical Threat",
    data: {
      init_win: 65535,
      fwd_max: 2500,
      bwd_max: 0,
      avg_fwd: 1250,
      avg_bwd: 0,
      total_fwd: 50000,
    },
  },
  normalWeb: {
    name: "Standard HTTPS Traffic",
    tag: "Benign Session",
    data: {
      init_win: 8192,
      fwd_max: 517,
      bwd_max: 1420,
      avg_fwd: 180,
      avg_bwd: 840,
      total_fwd: 1540,
    },
  },
};

function App() {
  const [formData, setFormData] = useState(PRESETS.uc029.data);
  const [selectedPreset, setSelectedPreset] = useState("uc029");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState([]);
  const [backendOnline, setBackendOnline] = useState(null);

  // Check backend health
  useEffect(() => {
    const checkBackend = async () => {
      try {
        await axios.get("http://127.0.0.1:8000/", { timeout: 1200 });
        setBackendOnline(true);
      } catch {
        setBackendOnline(false);
      }
    };
    checkBackend();
    const interval = setInterval(checkBackend, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleChange = (e) => {
    setSelectedPreset("");
    setFormData({
      ...formData,
      [e.target.name]: parseFloat(e.target.value) || 0,
    });
  };

  const loadPreset = (key) => {
    setSelectedPreset(key);
    setFormData(PRESETS[key].data);
    setError("");
  };

  const detectTraffic = async () => {
    setLoading(true);
    setError("");
    const startTime = performance.now();

    try {
      let data;
      if (backendOnline) {
        const response = await axios.post("http://127.0.0.1:8000/predict", formData);
        data = response.data;
      } else {
        // High fidelity frontend preview simulation if FastAPI backend isn't started yet
        await new Promise((r) => setTimeout(r, 650));
        const isSuspicious =
          formData.init_win > 20000 ||
          formData.total_fwd > 10000 ||
          (formData.fwd_max > 1200 && formData.bwd_max === 0);

        data = {
          classical: isSuspicious ? "ATTACK" : "BENIGN",
          quantum: isSuspicious ? "ATTACK" : "BENIGN",
          final: isSuspicious ? "ATTACK" : "BENIGN",
          risk: isSuspicious ? (formData.total_fwd > 20000 ? "CRITICAL" : "HIGH") : "LOW",
          simulated: true,
        };
      }

      const elapsed = Math.round(performance.now() - startTime);
      const enrichedResult = {
        ...data,
        elapsed,
        timestamp: new Date().toLocaleTimeString(),
        vector: { ...formData },
      };

      setResult(enrichedResult);
      setHistory((prev) => [enrichedResult, ...prev.slice(0, 7)]);
    } catch (err) {
      console.error(err);
      setError("Inference request failed. Please check FastAPI backend connection.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-container">
      {/* Dynamic Background Glows */}
      <div className="bg-glow bg-glow-1"></div>
      <div className="bg-glow bg-glow-2"></div>

      {/* Top Navbar */}
      <header className="navbar">
        <div className="brand-group">
          <div className="logo-badge">
            <span className="quantum-icon">⚛️</span>
          </div>
          <div>
            <div className="brand-title">
              <span className="gradient-text">UC-029</span> QUANTUM INTRUSION DETECTION
            </div>
            <div className="brand-subtitle">
              Dual-Engine Quantum Kernel SVM & Classical Ensemble Architecture
            </div>
          </div>
        </div>

        <div className="header-status-panel">
          <div className="backend-indicator">
            <span className={`pulse-dot ${backendOnline ? "online" : "standby"}`}></span>
            <span>
              {backendOnline === null
                ? "Connecting..."
                : backendOnline
                ? "FastAPI Live"
                : "Engine Simulator (Standby)"}
            </span>
          </div>
          <div className="badge-qml">
            <span>6-Qubit State Vector</span>
          </div>
        </div>
      </header>

      <main className="main-content">
        {/* Top Feature Presets */}
        <section className="presets-bar">
          <span className="preset-label">⚡ Quick Presets:</span>
          <div className="preset-buttons">
            {Object.entries(PRESETS).map(([key, item]) => (
              <button
                key={key}
                className={`preset-btn ${selectedPreset === key ? "active" : ""}`}
                onClick={() => loadPreset(key)}
              >
                <span className="preset-name">{item.name}</span>
                <span className="preset-tag">{item.tag}</span>
              </button>
            ))}
          </div>
        </section>

        <div className="dashboard-grid">
          {/* LEFT PANEL: Feature Vector Input */}
          <section className="glass-panel input-panel">
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">📊</span>
                <h3>Quantum Feature Vector</h3>
              </div>
              <span className="feature-count-badge">6 Selected Dimensions</span>
            </div>
            <p className="panel-desc">
              Selected via mutual information & quantum kernel feature mapping from the 78-feature CIC-IDS space.
            </p>

            <div className="feature-grid">
              <div className="input-group">
                <div className="input-label-row">
                  <label>Init Win Bytes Forward</label>
                  <span className="code-tag">Init_Win_bytes_forward</span>
                </div>
                <input
                  type="number"
                  step="any"
                  name="init_win"
                  value={formData.init_win}
                  onChange={handleChange}
                />
              </div>

              <div className="input-group">
                <div className="input-label-row">
                  <label>Fwd Packet Length Max</label>
                  <span className="code-tag">Fwd_Pkt_Len_Max</span>
                </div>
                <input
                  type="number"
                  step="any"
                  name="fwd_max"
                  value={formData.fwd_max}
                  onChange={handleChange}
                />
              </div>

              <div className="input-group">
                <div className="input-label-row">
                  <label>Bwd Packet Length Max</label>
                  <span className="code-tag">Bwd_Pkt_Len_Max</span>
                </div>
                <input
                  type="number"
                  step="any"
                  name="bwd_max"
                  value={formData.bwd_max}
                  onChange={handleChange}
                />
              </div>

              <div className="input-group">
                <div className="input-label-row">
                  <label>Avg Fwd Segment Size</label>
                  <span className="code-tag">Avg_Fwd_Seg_Size</span>
                </div>
                <input
                  type="number"
                  step="any"
                  name="avg_fwd"
                  value={formData.avg_fwd}
                  onChange={handleChange}
                />
              </div>

              <div className="input-group">
                <div className="input-label-row">
                  <label>Avg Bwd Segment Size</label>
                  <span className="code-tag">Avg_Bwd_Seg_Size</span>
                </div>
                <input
                  type="number"
                  step="any"
                  name="avg_bwd"
                  value={formData.avg_bwd}
                  onChange={handleChange}
                />
              </div>

              <div className="input-group">
                <div className="input-label-row">
                  <label>Total Length Fwd Packets</label>
                  <span className="code-tag">Tot_Len_Fwd_Pkts</span>
                </div>
                <input
                  type="number"
                  step="any"
                  name="total_fwd"
                  value={formData.total_fwd}
                  onChange={handleChange}
                />
              </div>
            </div>

            <button
              className={`quantum-action-btn ${loading ? "loading" : ""}`}
              onClick={detectTraffic}
              disabled={loading}
            >
              {loading ? (
                <div className="btn-loader">
                  <span className="spinner"></span>
                  <span>Evaluating Quantum Kernel...</span>
                </div>
              ) : (
                <div className="btn-content">
                  <span>⚡</span>
                  <span>EVALUATE NETWORK FLOW</span>
                </div>
              )}
            </button>

            {error && <div className="cyber-alert error-alert">⚠️ {error}</div>}
          </section>

          {/* RIGHT PANEL: Decision & Intelligence */}
          <section className="glass-panel result-panel">
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">🛡️</span>
                <h3>Intelligence & Consensus</h3>
              </div>
              {result && (
                <span className="latency-badge">
                  ⏱️ {result.elapsed} ms {result.simulated ? "(simulated)" : ""}
                </span>
              )}
            </div>

            {result ? (
              <div className="result-content-wrapper">
                {/* Main Threat Status Banner */}
                <div
                  className={`status-hero-card ${
                    result.final === "ATTACK" ? "status-attack" : "status-benign"
                  }`}
                >
                  <div className="status-hero-icon">
                    {result.final === "ATTACK" ? "🚨" : "🛡️"}
                  </div>
                  <div className="status-hero-info">
                    <div className="status-tagline">CONSENSUS VERDICT</div>
                    <div className="status-main-label">{result.final} TRAFFIC</div>
                    <div className="status-desc">
                      {result.final === "ATTACK"
                        ? "Anomalous flow signature identified by Quantum-Classical fusion gate."
                        : "Verified nominal flow behavior with high fidelity confidence."}
                    </div>
                  </div>
                  <div className="risk-level-badge">
                    <span className="risk-title">THREAT LEVEL</span>
                    <span className="risk-value">{result.risk}</span>
                  </div>
                </div>

                {/* Dual Engine Comparison */}
                <div className="engine-grid">
                  <div className="engine-card classical-engine">
                    <div className="engine-header">
                      <span className="engine-icon">🌲</span>
                      <div>
                        <div className="engine-name">Classical Random Forest</div>
                        <div className="engine-spec">Ensemble Decision Trees</div>
                      </div>
                    </div>
                    <div
                      className={`engine-result ${
                        result.classical === "ATTACK" ? "res-attack" : "res-benign"
                      }`}
                    >
                      {result.classical}
                    </div>
                  </div>

                  <div className="engine-card quantum-engine">
                    <div className="engine-header">
                      <span className="engine-icon">⚛️</span>
                      <div>
                        <div className="engine-name">Quantum SVM</div>
                        <div className="engine-spec">Fidelity Quantum Kernel (100×6)</div>
                      </div>
                    </div>
                    <div
                      className={`engine-result ${
                        result.quantum === "ATTACK" ? "res-attack" : "res-benign"
                      }`}
                    >
                      {result.quantum}
                    </div>
                  </div>
                </div>

                {/* Quantum Metric Telemetry */}
                <div className="telemetry-box">
                  <div className="telemetry-title">⚡ Quantum Pipeline Telemetry</div>
                  <div className="telemetry-items">
                    <div className="telemetry-item">
                      <span className="t-label">Feature Scaler</span>
                      <span className="t-val">MinMaxScaler [0, 1]</span>
                    </div>
                    <div className="telemetry-item">
                      <span className="t-label">Quantum Hilbert Space</span>
                      <span className="t-val">2^6 = 64 Dimensions</span>
                    </div>
                    <div className="telemetry-item">
                      <span className="t-label">Kernel Reference Set</span>
                      <span className="t-val">100 Reference Flows</span>
                    </div>
                    <div className="telemetry-item">
                      <span className="t-label">Decision Policy</span>
                      <span className="t-val">Disjunctive Attack Guard</span>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="empty-state">
                <div className="empty-quantum-orb">⚛️</div>
                <h4>Awaiting Flow Ingestion</h4>
                <p>
                  Select a traffic preset above or input custom flow parameters, then click{" "}
                  <strong>Evaluate Network Flow</strong> to execute classification.
                </p>
              </div>
            )}
          </section>
        </div>

        {/* RECENT INSPECTION LOG */}
        {history.length > 0 && (
          <section className="glass-panel log-section">
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">📜</span>
                <h3>Recent Inference Telemetry</h3>
              </div>
              <button className="clear-btn" onClick={() => setHistory([])}>
                Clear History
              </button>
            </div>

            <div className="table-responsive">
              <table className="telemetry-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Init Win</th>
                    <th>Fwd Max</th>
                    <th>Tot Fwd Pkts</th>
                    <th>Classical</th>
                    <th>Quantum SVM</th>
                    <th>Consensus</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((item, idx) => (
                    <tr key={idx} className={item.final === "ATTACK" ? "row-attack" : "row-benign"}>
                      <td className="mono">{item.timestamp}</td>
                      <td className="mono">{item.vector.init_win}</td>
                      <td className="mono">{item.vector.fwd_max}</td>
                      <td className="mono">{item.vector.total_fwd}</td>
                      <td>
                        <span className={`mini-pill ${item.classical === "ATTACK" ? "pill-attack" : "pill-benign"}`}>
                          {item.classical}
                        </span>
                      </td>
                      <td>
                        <span className={`mini-pill ${item.quantum === "ATTACK" ? "pill-attack" : "pill-benign"}`}>
                          {item.quantum}
                        </span>
                      </td>
                      <td>
                        <strong className={item.final === "ATTACK" ? "text-attack" : "text-benign"}>
                          {item.final}
                        </strong>
                      </td>
                      <td>
                        <span className={`risk-tag ${item.risk.toLowerCase()}`}>{item.risk}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </main>

      <footer className="footer">
        <div>
          🛡️ <strong>UC029 Quantum Intrusion Detection System</strong> • Quantum Computing & Machine Learning Fusion
        </div>
        <div className="footer-sub">
          Qiskit Machine Learning • Fidelity Quantum Kernel • Scikit-Learn • React 19
        </div>
      </footer>
    </div>
  );
}

export default App;
