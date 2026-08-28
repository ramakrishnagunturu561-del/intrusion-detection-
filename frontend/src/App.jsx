import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import './index.css';

// Default API base URL configuration (prioritizing 8080, fallback 8000)
const PRIMARY_API_URL = 'http://127.0.0.1:8000';
const FALLBACK_API_URL = 'http://127.0.0.1:8080';

const QUANTUM_FEATURES = [
  'Init_Win_bytes_forward',
  'Fwd Packet Length Max',
  'Bwd Packet Length Max',
  'Fwd Packet Length Mean',
  'Avg Bwd Segment Size',
  'Subflow Fwd Bytes'
];

function App() {
  const [apiBaseUrl, setApiBaseUrl] = useState(PRIMARY_API_URL);
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [status, setStatus] = useState('Checking...');
  const [tsharkPath, setTsharkPath] = useState(null);
  const [activeTab, setActiveTab] = useState('live'); // 'live' or 'analysis'
  
  // Interface selection & capture parameters
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('4');
  const [captureDuration, setCaptureDuration] = useState(5);
  
  // Pipeline Step Tracking (0: Idle, 1: TShark Capture, 2: PCAP Gen, 3: Flow Extraction, 4: 78-Feature Vector, 5: Quantum/RF ML, 6: UI Display)
  const [pipelineStep, setPipelineStep] = useState(0);

  // Flow details modal state
  const [selectedFlowDetails, setSelectedFlowDetails] = useState(null);

  // Live capture results
  const [captureSummary, setCaptureSummary] = useState(null);
  const [capturedFlows, setCapturedFlows] = useState([]);

  // Historical Log
  const [history, setHistory] = useState([
    { id: 1, time: '10:24:15', source: 'Wi-Fi (TShark Live)', classical: 'BENIGN', quantum: 'BENIGN', result: 'BENIGN', risk: 'LOW' },
    { id: 2, time: '10:25:02', source: 'UC029_test_row.json', classical: 'BENIGN', quantum: 'BENIGN', result: 'BENIGN', risk: 'LOW' },
    { id: 3, time: '10:26:41', source: 'pcap_capture_syn_flood.pcap', classical: 'ATTACK', quantum: 'ATTACK', result: 'ATTACK DETECTED', risk: 'HIGH' }
  ]);

  const fileInputRef = useRef(null);

  // Check Health & Available Network Interfaces on load
  useEffect(() => {
    initBackendConnection();
  }, []);

  const initBackendConnection = async () => {
    // Try primary port 8080 first
    try {
      const res = await axios.get(`${PRIMARY_API_URL}/health`, { timeout: 3000 });
      setApiBaseUrl(PRIMARY_API_URL);
      setStatus(res.data.status);
      setTsharkPath(res.data.tshark_path);
      fetchInterfaces(PRIMARY_API_URL);
      return;
    } catch (_) {}

    // Try fallback port 8000
    try {
      const res = await axios.get(`${FALLBACK_API_URL}/health`, { timeout: 3000 });
      setApiBaseUrl(FALLBACK_API_URL);
      setStatus(res.data.status);
      setTsharkPath(res.data.tshark_path);
      fetchInterfaces(FALLBACK_API_URL);
      return;
    } catch (_) {}

    setStatus('OFFLINE');
  };

  const fetchInterfaces = (baseUrl) => {
    const targetUrl = baseUrl || apiBaseUrl;
    axios.get(`${targetUrl}/interfaces`)
      .then(res => {
        if (res.data.success && res.data.interfaces.length > 0) {
          setInterfaces(res.data.interfaces);
          const wifi = res.data.interfaces.find(i => i.name.toLowerCase().includes('wi-fi') || i.id === '4');
          if (wifi) {
            setSelectedInterface(wifi.id);
          } else {
            setSelectedInterface(res.data.interfaces[0].id);
          }
        }
      })
      .catch(err => console.log('Unable to fetch interfaces:', err));
  };

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

  // ============================================================
  // TRIGGER REAL TSHARK LIVE NETWORK CAPTURE
  // ============================================================
  const runLiveNetworkCapture = async () => {
    setLoading(true);
    setError(null);
    setCapturedFlows([]);
    setCaptureSummary(null);

    // Step 1: User clicks Live Network Capture -> TShark starting
    setPipelineStep(1);

    try {
      // Simulate pipeline UI progress while backend TShark captures
      const stepTimer1 = setTimeout(() => setPipelineStep(2), captureDuration * 500);
      const stepTimer2 = setTimeout(() => setPipelineStep(3), captureDuration * 800);
      const stepTimer3 = setTimeout(() => setPipelineStep(4), captureDuration * 1000);
      const stepTimer4 = setTimeout(() => setPipelineStep(5), captureDuration * 1000 + 400);

      const response = await axios.post(`${apiBaseUrl}/capture-live`, {
        interface: selectedInterface,
        duration: captureDuration
      });

      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      clearTimeout(stepTimer3);
      clearTimeout(stepTimer4);

      setPipelineStep(6); // Result ready

      const resData = response.data;
      setCaptureSummary(resData);
      setCapturedFlows(resData.flows || []);

      // Add record to history
      const now = new Date().toTimeString().split(' ')[0];
      const newHistoryItem = {
        id: Date.now(),
        time: now,
        source: `Live Capture (If: ${selectedInterface}, ${resData.total_flows_analyzed} flows)`,
        classical: resData.overall_prediction,
        quantum: resData.overall_prediction,
        result: resData.overall_prediction === 'ATTACK' ? 'ATTACK DETECTED' : 'BENIGN',
        risk: resData.overall_risk_level
      };
      setHistory(prev => [newHistoryItem, ...prev]);

    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Error executing TShark live capture.');
      setPipelineStep(0);
    } finally {
      setLoading(false);
    }
  };

  // Analyze uploaded File (JSON / CSV / PCAP)
  const analyzeTraffic = async () => {
    if (!file) {
      setError("Please select or upload a network flow file (JSON/CSV/PCAP) first.");
      return;
    }

    setLoading(true);
    setError(null);
    setPipelineStep(3); // Extracted flows

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post(`${apiBaseUrl}/predict-file`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      
      const resData = response.data;
      setResult(resData);
      if (resData.flows) {
        setCapturedFlows(resData.flows);
      }
      setPipelineStep(6);

      const now = new Date().toTimeString().split(' ')[0];
      const newEntry = {
        id: Date.now(),
        time: now,
        source: file.name,
        classical: resData.classical_prediction,
        quantum: resData.quantum_prediction,
        result: resData.final_prediction === 'ATTACK' ? 'ATTACK DETECTED' : 'BENIGN',
        risk: resData.risk_level
      };
      setHistory(prev => [newEntry, ...prev]);

    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'An error occurred during file analysis');
      setPipelineStep(0);
    } finally {
      setLoading(false);
    }
  };

  const runDemo = async () => {
    setLoading(true);
    setError(null);
    setPipelineStep(1);
    
    setTimeout(async () => {
      try {
        const response = await axios.get(`${apiBaseUrl}/health`);
        setPipelineStep(5);
        
        // Use demo sample
        const demoResult = {
          success: true,
          filename: 'UC029_test_sample.json',
          classical_prediction: 'BENIGN',
          quantum_prediction: 'BENIGN',
          final_prediction: 'BENIGN',
          risk_level: 'LOW'
        };
        setResult(demoResult);
        setPipelineStep(6);
      } catch (err) {
        setError("Backend API unavailable for demo");
      } finally {
        setLoading(false);
      }
    }, 1200);
  };

  return (
    <div className="app-container">
      {/* Header Banner */}
      <header className="header">
        <div className="header-badge-row">
          <span className="quantum-tag">🛡 UC029 QUANTUM INTRUSION DETECTION</span>
          <div className="status-badge">
            <div className={`status-dot ${status === 'ONLINE' ? 'online-pulse' : 'offline-dot'}`}></div>
            FastAPI Backend: {status}
          </div>
        </div>
        <h1 className="title">Hybrid Quantum-Classical Security Monitor</h1>
        <p className="subtitle">Real-Time TShark Packet Capture, 78-Feature CICIDS Flow Extraction & Qiskit Quantum SVM Inference</p>
      </header>

      {/* PIPELINE ARCHITECTURE VISUALIZER */}
      <section className="pipeline-container glass-panel">
        <div className="pipeline-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
          Live Quantum-Classical Detection Pipeline Execution
        </div>
        
        <div className="pipeline-steps">
          <div className={`step-box ${pipelineStep >= 1 ? 'step-active' : ''}`}>
            <div className="step-num">1</div>
            <div className="step-label">Live Capture Clicked</div>
            <div className="step-sub">User trigger</div>
          </div>

          <div className="step-arrow">➔</div>

          <div className={`step-box ${pipelineStep >= 2 ? 'step-active' : ''}`}>
            <div className="step-num">2</div>
            <div className="step-label">TShark Engine</div>
            <div className="step-sub">PCAP capture</div>
          </div>

          <div className="step-arrow">➔</div>

          <div className={`step-box ${pipelineStep >= 3 ? 'step-active' : ''}`}>
            <div className="step-num">3</div>
            <div className="step-label">PCAP Generated</div>
            <div className="step-sub">Raw packet file</div>
          </div>

          <div className="step-arrow">➔</div>

          <div className={`step-box ${pipelineStep >= 4 ? 'step-active' : ''}`}>
            <div className="step-num">4</div>
            <div className="step-label">78-Feature Extraction</div>
            <div className="step-sub">CICIDS 5-tuples</div>
          </div>

          <div className="step-arrow">➔</div>

          <div className={`step-box ${pipelineStep >= 5 ? 'step-active' : ''}`}>
            <div className="step-num">5</div>
            <div className="step-label">Random Forest + Q-SVM</div>
            <div className="step-sub">Kernel evaluation</div>
          </div>

          <div className="step-arrow">➔</div>

          <div className={`step-box ${pipelineStep >= 6 ? 'step-active' : ''}`}>
            <div className="step-num">6</div>
            <div className="step-label">UI Verdict & Risk</div>
            <div className="step-sub">BENIGN / ATTACK</div>
          </div>
        </div>
      </section>

      {/* DASHBOARD STATISTICS CARDS */}
      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon icon-network">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 11a9 9 0 0 1 9 9"></path><path d="M4 4a16 16 0 0 1 16 16"></path><circle cx="5" cy="19" r="1"></circle></svg>
          </div>
          <div className="stat-info">
            <div className="stat-value">78</div>
            <div className="stat-label">CICIDS Flow Features</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon icon-quantum">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"></circle><path d="M12 21a9 9 0 0 0 9-9 9 9 0 0 0-9-9 9 9 0 0 0-9 9 9 9 0 0 0 9 9z"></path><path d="M12 3v3M12 18v3M3 12h3M18 12h3"></path></svg>
          </div>
          <div className="stat-info">
            <div className="stat-value">6</div>
            <div className="stat-label">Selected Quantum Features</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon icon-engine">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
          </div>
          <div className="stat-info">
            <div className="stat-value">2</div>
            <div className="stat-label">Ensemble Engines (RF+QSVM)</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon icon-ref">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path></svg>
          </div>
          <div className="stat-info">
            <div className="stat-value">100</div>
            <div className="stat-label">Quantum Ref States</div>
          </div>
        </div>
      </section>

      {/* Top Navigation Tabs */}
      <div className="tab-navigation">
        <button 
          className={`tab-btn ${activeTab === 'live' ? 'active' : ''}`}
          onClick={() => setActiveTab('live')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg>
          Live Network Capture (TShark Engine)
        </button>
        <button 
          className={`tab-btn ${activeTab === 'analysis' ? 'active' : ''}`}
          onClick={() => setActiveTab('analysis')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
          PCAP / JSON / CSV File Upload
        </button>
      </div>

      {activeTab === 'live' ? (
        /* LIVE TSHARK CAPTURE TAB */
        <div className="live-monitoring-container">
          <div className="glass-panel">
            <div className="live-header">
              <div>
                <h2 className="panel-title" style={{border: 'none', padding: 0, margin: 0}}>
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><path d="M12 8v4l3 3"></path></svg>
                  TShark Live Network Interface Capture
                </h2>
                <p className="subtitle" style={{textAlign: 'left', marginTop: '0.25rem'}}>
                  Captures real hardware network traffic, generates PCAP, extracts 78 flow features & evaluates Quantum SVM
                </p>
              </div>
            </div>

            {/* Interface & Duration Controls */}
            <div className="capture-controls-bar">
              <div className="control-group">
                <label className="control-label">Capture Network Interface:</label>
                <select 
                  className="interface-select"
                  value={selectedInterface} 
                  onChange={(e) => setSelectedInterface(e.target.value)}
                  disabled={loading}
                >
                  {interfaces.length > 0 ? (
                    interfaces.map((iface) => (
                      <option key={iface.id} value={iface.id}>
                        {iface.id}. {iface.name} ({iface.device.substring(0, 25)}...)
                      </option>
                    ))
                  ) : (
                    <>
                      <option value="4">4. Wi-Fi Adapter</option>
                      <option value="1">1. Local Area Connection</option>
                      <option value="7">7. Loopback Capture</option>
                    </>
                  )}
                </select>
              </div>

              <div className="control-group">
                <label className="control-label">Duration (Seconds):</label>
                <select 
                  className="interface-select"
                  value={captureDuration} 
                  onChange={(e) => setCaptureDuration(Number(e.target.value))}
                  disabled={loading}
                >
                  <option value={3}>3 Seconds</option>
                  <option value={5}>5 Seconds (Recommended)</option>
                  <option value={10}>10 Seconds</option>
                  <option value={15}>15 Seconds</option>
                </select>
              </div>

              <button 
                className="btn btn-primary btn-live-capture"
                onClick={runLiveNetworkCapture}
                disabled={loading}
              >
                {loading ? (
                  <>
                    <span className="loading-spinner"></span>
                    Capturing Packets via TShark...
                  </>
                ) : (
                  <>
                    <span style={{marginRight: '6px'}}>⚡</span>
                    START LIVE NETWORK CAPTURE
                  </>
                )}
              </button>
            </div>

            {tsharkPath && (
              <div className="tshark-path-banner">
                <span className="badge-online">TSHARK ENGINE READY</span>
                <code>{tsharkPath}</code>
              </div>
            )}

            {error && (
              <div className="error-message" style={{marginTop: '1rem'}}>
                <strong>Capture Error:</strong> {error}
              </div>
            )}

            {/* CAPTURE SUMMARY HIGHLIGHT */}
            {captureSummary && (
              <div className={`final-result-banner ${captureSummary.overall_prediction === 'ATTACK' ? 'banner-attack' : 'banner-benign'}`} style={{marginTop: '1.5rem'}}>
                <div className="result-main-group">
                  <div className="banner-title">TSHARK CAPTURE OVERALL VERDICT</div>
                  <div className="banner-status">
                    {captureSummary.overall_prediction === 'ATTACK' ? '🔴 ATTACK DETECTED IN FLOWS' : '🟢 ALL FLOWS BENIGN'}
                  </div>
                  <div style={{fontSize: '0.85rem', opacity: 0.9, marginTop: '4px'}}>
                    Analyzed {captureSummary.total_flows_analyzed} network flows ({captureSummary.attack_flows_detected} Attacks, {captureSummary.benign_flows_detected} Benign)
                  </div>
                </div>

                <div className="result-risk-group">
                  <div className="banner-title">RISK LEVEL</div>
                  <div className={`risk-badge ${captureSummary.overall_risk_level === 'HIGH' ? 'risk-high-glow' : 'risk-low-glow'}`}>
                    {captureSummary.overall_risk_level === 'HIGH' ? 'HIGH RISK' : 'LOW RISK'}
                  </div>
                </div>
              </div>
            )}

            {/* FLOWS TABLE */}
            <div className="table-responsive" style={{marginTop: '1.5rem'}}>
              <table className="history-table live-table">
                <thead>
                  <tr>
                    <th>Flow ID</th>
                    <th>Source IP:Port</th>
                    <th>Destination IP:Port</th>
                    <th>Proto</th>
                    <th>Packets</th>
                    <th>Classical RF</th>
                    <th>Quantum SVM</th>
                    <th>Final Verdict</th>
                    <th>Risk</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {capturedFlows.length > 0 ? (
                    capturedFlows.map((flow) => (
                      <tr key={flow.flow_id} className={flow.final_prediction === 'ATTACK' ? 'row-attack' : ''}>
                        <td className="packet-id">{flow.flow_id}</td>
                        <td>{flow.src_ip}:{flow.src_port}</td>
                        <td>{flow.dst_ip}:{flow.dst_port}</td>
                        <td><span className="proto-badge">{flow.protocol}</span></td>
                        <td>{flow.packets_count}</td>
                        <td>
                          <span className={flow.classical_prediction === 'ATTACK' ? 'text-attack' : 'text-benign'}>
                            {flow.classical_prediction}
                          </span>
                        </td>
                        <td>
                          <span className={flow.quantum_prediction === 'ATTACK' ? 'text-attack' : 'text-benign'}>
                            {flow.quantum_prediction}
                          </span>
                        </td>
                        <td>
                          {flow.final_prediction === 'ATTACK' ? (
                            <span className="badge-result-attack">🔴 ATTACK</span>
                          ) : (
                            <span className="badge-result-benign">🟢 BENIGN</span>
                          )}
                        </td>
                        <td>
                          <span className={`risk-tag ${flow.risk_level === 'HIGH' ? 'risk-tag-high' : 'risk-tag-low'}`}>
                            {flow.risk_level}
                          </span>
                        </td>
                        <td>
                          <button 
                            className="btn-inspect"
                            onClick={() => setSelectedFlowDetails(flow)}
                          >
                            Inspect 78 Features
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="10" style={{textAlign: 'center', padding: '2rem', color: '#94a3b8'}}>
                        Click <strong>"START LIVE NETWORK CAPTURE"</strong> above to capture live packets via TShark and extract features.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

          </div>
        </div>
      ) : (
        /* FILE ANALYSIS TAB (PCAP / JSON / CSV) */
        <div className="dashboard-grid">
          {/* Left Column: Upload & Controls */}
          <div className="input-section">
            <div className="glass-panel">
              <h2 className="panel-title">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
                Upload Traffic File (.pcap, .json, .csv)
              </h2>
              
              <div className="file-upload-area" onClick={triggerFileInput}>
                <input 
                  type="file" 
                  ref={fileInputRef} 
                  onChange={handleFileChange} 
                  className="file-input"
                  accept=".pcap,.pcapng,.json,.csv"
                />
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent-color)" strokeWidth="2" style={{marginBottom: '0.75rem'}}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="12" y1="18" x2="12" y2="12"></line><line x1="9" y1="15" x2="15" y2="15"></line></svg>
                <div className="upload-title">Drop PCAP / JSON / CSV here</div>
                <div className="upload-subtitle">or click to browse files from system</div>
                {file && <div className="selected-filename">📄 {file.name}</div>}
              </div>
              
              <div className="action-buttons">
                <button 
                  className="btn btn-primary" 
                  onClick={analyzeTraffic}
                  disabled={loading || !file}
                >
                  {loading ? <span className="loading-spinner"></span> : "ANALYZE FILE"}
                </button>
                <button 
                  className="btn btn-secondary" 
                  onClick={runDemo}
                  disabled={loading}
                >
                  Run Sample Demo
                </button>
              </div>

              {error && (
                <div className="error-message">
                  <strong>Alert:</strong> {error}
                </div>
              )}
            </div>

            {/* QUANTUM FEATURES LIST */}
            <div className="glass-panel" style={{marginTop: '1.5rem'}}>
              <h2 className="panel-title">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
                Selected 6 Quantum ML Features
              </h2>
              <ul className="feature-list">
                {QUANTUM_FEATURES.map((feat, idx) => (
                  <li key={idx}>
                    <span className="bullet-glow">•</span> {feat}
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Right Column: Analysis Results & Detection History */}
          <div className="results-section">
            <div className="glass-panel">
              <h2 className="panel-title">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                Detection Results
              </h2>

              {result ? (
                <div className="results-container">
                  <div className="results-grid">
                    <div className="result-card">
                      <div className="card-label">CLASSICAL ML</div>
                      <div className="card-sub">Random Forest (78 Features)</div>
                      <div className={`prediction-value ${result.classical_prediction === 'ATTACK' ? 'value-attack' : 'value-benign'}`}>
                        {result.classical_prediction === 'ATTACK' ? '🔴 ATTACK' : '🟢 BENIGN'}
                      </div>
                    </div>
                    
                    <div className="result-card">
                      <div className="card-label">QUANTUM ML</div>
                      <div className="card-sub">Quantum SVM (6 Features)</div>
                      <div className={`prediction-value ${result.quantum_prediction === 'ATTACK' ? 'value-attack' : 'value-benign'}`}>
                        {result.quantum_prediction === 'ATTACK' ? '🔴 ATTACK' : '🟢 BENIGN'}
                      </div>
                    </div>
                  </div>

                  {/* FINAL RESULT HIGHLIGHT */}
                  <div className={`final-result-banner ${result.final_prediction === 'ATTACK' ? 'banner-attack' : 'banner-benign'}`}>
                    <div className="result-main-group">
                      <div className="banner-title">FINAL ENSEMBLE RESULT</div>
                      <div className="banner-status">
                        {result.final_prediction === 'ATTACK' ? '🔴 ATTACK DETECTED' : '🟢 BENIGN'}
                      </div>
                    </div>

                    <div className="result-risk-group">
                      <div className="banner-title">RISK EVALUATION</div>
                      <div className={`risk-badge ${result.risk_level === 'HIGH' ? 'risk-high-glow' : 'risk-low-glow'}`}>
                        {result.risk_level === 'HIGH' ? 'HIGH RISK' : 'LOW RISK'}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <p>Upload a PCAP / JSON / CSV flow or click "Run Sample Demo" to evaluate classical and quantum ML inference.</p>
              )}
            </div>

            {/* DETECTION HISTORY TABLE */}
            <div className="glass-panel" style={{marginTop: '1.5rem'}}>
              <h2 className="panel-title">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                Detection History Log
              </h2>

              <div className="table-responsive">
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Source</th>
                      <th>Classical</th>
                      <th>Quantum</th>
                      <th>Result</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((item) => (
                      <tr key={item.id} className={item.risk === 'HIGH' ? 'row-attack' : ''}>
                        <td className="time-col">{item.time}</td>
                        <td className="file-col">{item.source}</td>
                        <td>
                          <span className={item.classical === 'ATTACK' ? 'text-attack' : 'text-benign'}>
                            {item.classical}
                          </span>
                        </td>
                        <td>
                          <span className={item.quantum === 'ATTACK' ? 'text-attack' : 'text-benign'}>
                            {item.quantum}
                          </span>
                        </td>
                        <td className="result-col">
                          {item.result === 'ATTACK DETECTED' ? (
                            <span className="badge-result-attack">🔴 ATTACK</span>
                          ) : (
                            <span className="badge-result-benign">🟢 BENIGN</span>
                          )}
                        </td>
                        <td>
                          <span className={`risk-tag ${item.risk === 'HIGH' ? 'risk-tag-high' : 'risk-tag-low'}`}>
                            {item.risk}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 78-FEATURE INSPECTION MODAL */}
      {selectedFlowDetails && (
        <div className="modal-overlay" onClick={() => setSelectedFlowDetails(null)}>
          <div className="modal-content glass-panel" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Extracted 78-Feature Vector - {selectedFlowDetails.flow_id}</h3>
              <button className="btn-close" onClick={() => setSelectedFlowDetails(null)}>✕</button>
            </div>
            
            <div className="modal-meta-grid">
              <div><strong>5-Tuple:</strong> {selectedFlowDetails.src_ip}:{selectedFlowDetails.src_port} ➔ {selectedFlowDetails.dst_ip}:{selectedFlowDetails.dst_port}</div>
              <div><strong>Protocol:</strong> {selectedFlowDetails.protocol} | <strong>Packets:</strong> {selectedFlowDetails.packets_count}</div>
              <div><strong>Verdict:</strong> {selectedFlowDetails.final_prediction} ({selectedFlowDetails.risk_level} RISK)</div>
            </div>

            <h4 style={{marginTop: '1rem', color: 'var(--accent-color)'}}>Selected Quantum Features (6):</h4>
            <div className="quantum-features-preview">
              {Object.entries(selectedFlowDetails.quantum_features || {}).map(([k, v]) => (
                <div key={k} className="q-feat-chip">
                  <span className="q-key">{k}:</span> <span className="q-val">{v}</span>
                </div>
              ))}
            </div>

            <h4 style={{marginTop: '1.25rem', color: '#94a3b8'}}>All 78 Extracted CICIDS Features:</h4>
            <div className="features-scroll-table">
              <table>
                <thead>
                  <tr>
                    <th>Feature Name</th>
                    <th>Extracted Value</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(selectedFlowDetails.all_features || {}).map(([k, v]) => (
                    <tr key={k}>
                      <td className="feat-name">{k}</td>
                      <td className="feat-val">{typeof v === 'number' ? v.toFixed(4) : String(v)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

export default App;
