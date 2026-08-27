import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import './index.css';

const API_BASE_URL = 'http://127.0.0.1:8080';

function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [status, setStatus] = useState('Checking...');
  const fileInputRef = useRef(null);

  // Check API status on load
  useEffect(() => {
    axios.get(`${API_BASE_URL}/health`)
      .then(res => setStatus(res.data.status))
      .catch(() => setStatus('OFFLINE'));
  }, []);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setResult(null);
      setError(null);
    }
  };

  const triggerFileInput = () => {
    fileInputRef.current.click();
  };

  const runDemo = async () => {
    setLoading(true);
    setError(null);
    setFile(null);
    try {
      alert('For the demo, please click "Upload Network Flow" and select data/UC029_test_row.json');
      setLoading(false);
    } catch (err) {
      setError(err.message || 'Error running demo');
      setLoading(false);
    }
  };

  const analyzeTraffic = async () => {
    if (!file) {
      setError("Please upload a file first.");
      return;
    }

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post(`${API_BASE_URL}/predict-file`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'An error occurred during analysis');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-container">
      <header className="header">
        <h1 className="title">UC029 Quantum Intrusion Detection</h1>
        <p className="subtitle">Hybrid Quantum-Classical Machine Learning System</p>
        <div className="status-badge">
          <div className="status-dot"></div>
          System Status: {status}
        </div>
      </header>

      <div className="dashboard-grid">
        
        {/* Left Column: Input Controls */}
        <div className="input-section">
          <div className="glass-panel">
            <h2 className="panel-title">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
              Data Input
            </h2>
            
            <div className="file-upload-area" onClick={triggerFileInput}>
              <input 
                type="file" 
                ref={fileInputRef} 
                onChange={handleFileChange} 
                className="file-input"
                accept=".json,.csv"
              />
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--accent-color)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{marginBottom: '1rem'}}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="12" y1="18" x2="12" y2="12"></line><line x1="9" y1="15" x2="15" y2="15"></line></svg>
              <p>{file ? file.name : "Upload JSON/CSV Network Flow"}</p>
            </div>
            
            <div style={{display: 'flex', gap: '1rem', marginBottom: '1rem'}}>
              <button 
                className="btn btn-secondary" 
                onClick={runDemo}
                disabled={loading}
              >
                UC-029 Demo
              </button>
            </div>

            <button 
              className="btn btn-primary" 
              onClick={analyzeTraffic}
              disabled={loading || !file}
            >
              {loading ? <span className="loading-spinner"></span> : "ANALYZE TRAFFIC"}
            </button>

            {error && (
              <div className="error-message" style={{marginTop: '1rem'}}>
                <strong>Error:</strong> {error}
              </div>
            )}
          </div>

          <div className="glass-panel" style={{marginTop: '2rem'}}>
            <h2 className="panel-title">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
              Architecture
            </h2>
            <p style={{fontSize: '0.875rem', color: 'var(--text-secondary)'}}>
              This system uses a Hybrid Quantum-Classical pipeline.
            </p>
            <div className="quantum-info">
              <strong>Classical:</strong> Random Forest (78 Features)<br/><br/>
              <strong>Quantum:</strong> Qiskit Fidelity Quantum Kernel + SVM (6 Selected Features)
            </div>
          </div>
        </div>

        {/* Right Column: Results */}
        <div className="results-section">
          <div className="glass-panel" style={{height: '100%'}}>
            <h2 className="panel-title">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
              Analysis Results
            </h2>

            {result ? (
              <div className="results-container">
                <div className="results-grid">
                  <div className="result-card">
                    <h3>Classical Model</h3>
                    <div className={`prediction-value ${result.classical_prediction === 'ATTACK' ? 'value-attack' : 'value-benign'}`}>
                      {result.classical_prediction}
                    </div>
                    <div style={{fontSize: '0.75rem', marginTop: '0.5rem', color: 'var(--text-secondary)'}}>
                      Random Forest
                    </div>
                  </div>
                  
                  <div className="result-card">
                    <h3>Quantum SVM</h3>
                    <div className={`prediction-value ${result.quantum_prediction === 'ATTACK' ? 'value-attack' : 'value-benign'}`}>
                      {result.quantum_prediction}
                    </div>
                    <div style={{fontSize: '0.75rem', marginTop: '0.5rem', color: 'var(--text-secondary)'}}>
                      Fidelity Quantum Kernel
                    </div>
                  </div>
                </div>

                <div className="final-result">
                  <div>
                    <div className="final-result-title">Final Detection</div>
                    <div className={`prediction-value ${result.final_prediction === 'ATTACK' ? 'value-attack' : 'value-benign'}`} style={{fontSize: '2rem'}}>
                      {result.final_prediction}
                    </div>
                  </div>
                  
                  <div style={{textAlign: 'right'}}>
                    <div className="final-result-title">Risk Level</div>
                    <div className={`risk-level-badge ${result.risk_level === 'HIGH' ? 'risk-high' : 'risk-low'}`}>
                      {result.risk_level}
                    </div>
                  </div>
                </div>

                <div className="quantum-info">
                  <strong>Decision Logic:</strong> If either model detects an anomaly, the final risk is elevated to HIGH/ATTACK to ensure maximum security coverage.
                </div>
              </div>
            ) : (
              <div style={{display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '300px', color: 'var(--text-secondary)', opacity: 0.5}}>
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" style={{marginBottom: '1rem'}}><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
                <p>Upload a network flow record to begin analysis</p>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}

export default App;
