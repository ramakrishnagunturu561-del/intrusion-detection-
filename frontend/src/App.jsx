import { useState } from "react";
import axios from "axios";
import "./App.css";

function App() {
  const [formData, setFormData] = useState({
    init_win: 410,
    fwd_max: 0,
    bwd_max: 0,
    avg_fwd: 0,
    avg_bwd: 0,
    total_fwd: 0,
  });

  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: Number(e.target.value),
    });
  };

  const detectTraffic = async () => {
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await axios.post(
        "http://127.0.0.1:8000/predict",
        formData
      );

      setResult(response.data);
    } catch (err) {
      console.error(err);
      setError(
        "Backend connection failed. Make sure FastAPI is running."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">

      <header className="header">
        <div>
          <h1>🛡️ UC029 Quantum IDS</h1>
          <p>
            Quantum-assisted Network Intrusion Detection System
          </p>
        </div>

        <div className="status">
          <span className="status-dot"></span>
          System Ready
        </div>
      </header>

      <main className="container">

        <section className="hero">
          <h2>Network Traffic Analysis</h2>
          <p>
            Enter network-flow features to detect potential
            intrusion using Classical and Quantum Machine Learning.
          </p>
        </section>

        <section className="card">

          <h3>Traffic Features</h3>

          <div className="grid">

            <div className="field">
              <label>Init Win Bytes Forward</label>
              <input
                type="number"
                name="init_win"
                value={formData.init_win}
                onChange={handleChange}
              />
            </div>

            <div className="field">
              <label>Fwd Packet Length Max</label>
              <input
                type="number"
                name="fwd_max"
                value={formData.fwd_max}
                onChange={handleChange}
              />
            </div>

            <div className="field">
              <label>Bwd Packet Length Max</label>
              <input
                type="number"
                name="bwd_max"
                value={formData.bwd_max}
                onChange={handleChange}
              />
            </div>

            <div className="field">
              <label>Avg Fwd Segment Size</label>
              <input
                type="number"
                name="avg_fwd"
                value={formData.avg_fwd}
                onChange={handleChange}
              />
            </div>

            <div className="field">
              <label>Avg Bwd Segment Size</label>
              <input
                type="number"
                name="avg_bwd"
                value={formData.avg_bwd}
                onChange={handleChange}
              />
            </div>

            <div className="field">
              <label>Total Length Fwd Packets</label>
              <input
                type="number"
                name="total_fwd"
                value={formData.total_fwd}
                onChange={handleChange}
              />
            </div>

          </div>

          <button
            className="detect-button"
            onClick={detectTraffic}
            disabled={loading}
          >
            {loading ? "Analyzing..." : "🔍 Analyze Traffic"}
          </button>

        </section>

        {error && (
          <div className="error">
            ⚠️ {error}
          </div>
        )}

        {result && (
          <section className="results">

            <h2>Detection Results</h2>

            <div className="result-grid">

              <div className="result-card">
                <span>Classical Model</span>
                <strong>{result.classical}</strong>
              </div>

              <div className="result-card">
                <span>Quantum SVM</span>
                <strong>{result.quantum}</strong>
              </div>

              <div className="result-card">
                <span>Final Detection</span>
                <strong>{result.final}</strong>
              </div>

              <div className="result-card">
                <span>Risk Level</span>
                <strong>{result.risk}</strong>
              </div>

            </div>

            <div
              className={
                result.final === "ATTACK"
                  ? "alert attack"
                  : "alert benign"
              }
            >
              {result.final === "ATTACK"
                ? "🚨 Suspicious network traffic detected."
                : "✅ Network traffic appears benign."}
            </div>

          </section>
        )}

      </main>

      <footer>
        UC029 Quantum Intrusion Detection • Random Forest + Quantum SVM
      </footer>

    </div>
  );
}

export default App;
