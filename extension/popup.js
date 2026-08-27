/**
 * UC029 Quantum Intrusion Detection System
 * Extension Popup Script
 *
 * CONFIGURATION:
 * - API_BASE_URL: Central endpoint for FastAPI backend
 * - DASHBOARD_URL: URL for React frontend UI
 * - AUTO_MONITOR_INTERVAL_MS: Interval for auto capture (minimum 10000ms per spec)
 */

// ============================================================
// CONFIGURABLE CONSTANTS
// ============================================================
const API_BASE_URL = 'http://127.0.0.1:8080';
const DASHBOARD_URL = 'http://localhost:5173';
const AUTO_MONITOR_INTERVAL_MS = 15000;

// ============================================================
// APP STATE & LOCKS
// ============================================================
let isCapturing = false;
let autoMonitorTimer = null;
let activeDomain = 'Unknown Domain';

// ============================================================
// DOM ELEMENTS
// ============================================================
document.addEventListener('DOMContentLoaded', async () => {
  // DOM References
  const backendPill = document.getElementById('backend-status-pill');
  const backendText = document.getElementById('backend-status-text');
  const domainDisplay = document.getElementById('active-domain-display');
  const startBtn = document.getElementById('start-capture-btn');
  const refreshBtn = document.getElementById('refresh-btn');
  const dashboardBtn = document.getElementById('open-dashboard-btn');
  const autoToggle = document.getElementById('auto-monitor-toggle');
  const autoPulse = document.getElementById('auto-monitor-indicator');
  const alertBox = document.getElementById('error-alert-box');
  const alertMsg = document.getElementById('error-alert-message');

  // Stats Elements
  const totalFlowsEl = document.getElementById('stat-total-flows');
  const benignFlowsEl = document.getElementById('stat-benign-flows');
  const suspiciousFlowsEl = document.getElementById('stat-suspicious-flows');
  const attackFlowsEl = document.getElementById('stat-attack-flows');

  // Risk Elements
  const riskCard = document.getElementById('risk-summary-card');
  const riskBadge = document.getElementById('risk-level-badge');
  const riskPredText = document.getElementById('risk-prediction-text');
  const captureInfoText = document.getElementById('capture-info-text');

  // Flow Table Elements
  const flowTableBody = document.getElementById('flow-table-body');
  const flowCountTag = document.getElementById('flow-count-tag');

  // ============================================================
  // 1. ACTIVE BROWSER TAB DOMAIN DETECTION
  // ============================================================
  async function detectActiveTabDomain() {
    try {
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs && tabs.length > 0 && tabs[0].url) {
          const urlObj = new URL(tabs[0].url);
          if (urlObj.protocol.startsWith('http')) {
            activeDomain = urlObj.hostname;
          } else {
            activeDomain = `Browser Page (${urlObj.protocol.replace(':', '')})`;
          }
        } else {
          activeDomain = 'Active Browser Tab';
        }
      } else {
        activeDomain = 'Browser Tab';
      }
    } catch (err) {
      console.warn('[UC029 Extension] Tab query error:', err);
      activeDomain = 'Local Browser Session';
    }
    domainDisplay.textContent = activeDomain;
  }

  // ============================================================
  // 2. BACKEND HEALTH CHECK
  // ============================================================
  async function checkBackendHealth() {
    backendPill.className = 'status-pill status-checking';
    backendText.textContent = 'Checking API...';

    try {
      const response = await fetch(`${API_BASE_URL}/health`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      
      backendPill.className = 'status-pill status-online';
      backendText.textContent = 'Backend Online';

      if (!data.tshark_installed) {
        showError('TShark not detected on host system. Please install Wireshark.');
      } else {
        hideError();
      }

      return true;
    } catch (err) {
      backendPill.className = 'status-pill status-offline';
      backendText.textContent = 'Backend Offline';
      showError(`Backend unavailable at ${API_BASE_URL}. Start FastAPI server first.`);
      return false;
    }
  }

  // ============================================================
  // 3. START NETWORK CAPTURE & INFERENCE
  // ============================================================
  async function startMonitoringCapture() {
    if (isCapturing) {
      console.log('[UC029 Extension] Capture already in progress. Skipping duplicate execution.');
      return;
    }

    isCapturing = true;
    startBtn.disabled = true;
    startBtn.innerHTML = '<span class="btn-icon">⏳</span> Capturing (5s)...';
    hideError();

    try {
      // First verify backend health
      const isHealthy = await checkBackendHealth();
      if (!isHealthy) {
        throw new Error(`Cannot reach FastAPI backend at ${API_BASE_URL}`);
      }

      const payload = {
        interface: '4',
        duration: 5,
        packet_count: null
      };

      console.log('[UC029 Extension] Triggering /capture-live with payload:', payload);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 25000); // 25s safety timeout

      const response = await fetch(`${API_BASE_URL}/capture-live`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let errDetail = `HTTP ${response.status}`;
        try {
          const errData = await response.json();
          if (errData.detail) errDetail = errData.detail;
        } catch (_) {}
        throw new Error(errDetail);
      }

      const result = await response.json();
      console.log('[UC029 Extension] Live Capture Result:', result);

      if (result.success) {
        renderCaptureResults(result);
      } else {
        throw new Error(result.error || 'Live capture failed.');
      }
    } catch (err) {
      console.error('[UC029 Extension] Capture error:', err);
      let msg = err.message || 'Unknown network capture error';
      if (err.name === 'AbortError') {
        msg = 'Capture timed out after 25 seconds.';
      }
      showError(msg);
    } finally {
      isCapturing = false;
      startBtn.disabled = false;
      startBtn.innerHTML = '<span class="btn-icon">▶</span> Start Monitoring';
    }
  }

  // ============================================================
  // 4. RENDER RESULTS TO DOM
  // ============================================================
  function renderCaptureResults(data) {
    const totalFlows = data.total_flows_analyzed || 0;
    const benignFlows = data.benign_flows_detected || 0;
    const suspiciousFlows = data.suspicious_flows_detected || 0;
    const attackFlows = data.attack_flows_detected || 0;

    const overallPred = data.overall_prediction || 'BENIGN';
    const overallRisk = data.overall_risk_level || 'LOW';

    // Update Counters
    totalFlowsEl.textContent = totalFlows;
    benignFlowsEl.textContent = benignFlows;
    suspiciousFlowsEl.textContent = suspiciousFlows;
    attackFlowsEl.textContent = attackFlows;

    // Update Risk Card
    riskCard.className = 'risk-card';
    riskBadge.className = 'risk-badge';

    if (overallPred === 'ATTACK' || overallRisk === 'HIGH') {
      riskCard.classList.add('risk-attack');
      riskBadge.classList.add('badge-high');
      riskBadge.textContent = 'HIGH RISK';
      riskPredText.textContent = '⚠️ THREAT DETECTED';
    } else if (overallPred === 'SUSPICIOUS' || overallRisk === 'MEDIUM') {
      riskCard.classList.add('risk-suspicious');
      riskBadge.classList.add('badge-medium');
      riskBadge.textContent = 'MEDIUM RISK';
      riskPredText.textContent = '⚡ SUSPICIOUS ACTIVITY';
    } else {
      riskCard.classList.add('risk-benign');
      riskBadge.classList.add('badge-low');
      riskBadge.textContent = 'LOW RISK';
      riskPredText.textContent = '✅ NETWORK BENIGN';
    }

    captureInfoText.textContent = `Interface: ${data.interface_used || '4'} | Capture: ${data.actual_capture_time_sec || 5}s | Domain: ${activeDomain}`;

    // Render Table
    flowCountTag.textContent = `${totalFlows} Flow${totalFlows !== 1 ? 's' : ''}`;
    const flows = data.flows || [];

    if (flows.length === 0) {
      flowTableBody.innerHTML = `
        <tr>
          <td colspan="8" class="table-placeholder">
            No network flows recorded during the 5s capture period.
          </td>
        </tr>
      `;
      return;
    }

    let rowsHtml = '';
    flows.forEach((flow) => {
      const flowId = flow.flow_id || 'FLOW-000';
      const srcIp = flow.src_ip || '0.0.0.0';
      const dstIp = flow.dst_ip || '0.0.0.0';
      const proto = flow.protocol || 'TCP';
      const classPred = flow.classical_prediction || 'BENIGN';
      const quantPred = flow.quantum_prediction || 'BENIGN';
      const finalPred = flow.final_prediction || 'BENIGN';
      const riskLvl = flow.risk_level || 'LOW';

      let finalBadgeClass = 'tbl-benign';
      if (finalPred === 'ATTACK') finalBadgeClass = 'tbl-attack';
      else if (finalPred === 'SUSPICIOUS') finalBadgeClass = 'tbl-suspicious';

      rowsHtml += `
        <tr>
          <td><strong>${escapeHtml(flowId)}</strong></td>
          <td>${escapeHtml(srcIp)}</td>
          <td>${escapeHtml(dstIp)}</td>
          <td>${escapeHtml(proto)}</td>
          <td>${escapeHtml(classPred)}</td>
          <td>${escapeHtml(quantPred)}</td>
          <td><span class="tbl-badge ${finalBadgeClass}">${escapeHtml(finalPred)}</span></td>
          <td><strong>${escapeHtml(riskLvl)}</strong></td>
        </tr>
      `;
    });

    flowTableBody.innerHTML = rowsHtml;
  }

  // ============================================================
  // 5. HELPER UTILITIES
  // ============================================================
  function showError(message) {
    alertMsg.textContent = message;
    alertBox.classList.remove('hidden');
  }

  function hideError() {
    alertBox.classList.add('hidden');
  }

  function escapeHtml(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/[&<>"']/g, function(m) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
    });
  }

  // ============================================================
  // 6. EVENT LISTENERS
  // ============================================================
  startBtn.addEventListener('click', startMonitoringCapture);

  refreshBtn.addEventListener('click', async () => {
    await detectActiveTabDomain();
    await checkBackendHealth();
  });

  dashboardBtn.addEventListener('click', () => {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: DASHBOARD_URL });
    } else {
      window.open(DASHBOARD_URL, '_blank');
    }
  });

  autoToggle.addEventListener('change', (e) => {
    if (e.target.checked) {
      autoPulse.classList.remove('hidden');
      console.log(`[UC029 Extension] Auto Monitor enabled (every ${AUTO_MONITOR_INTERVAL_MS}ms)`);
      
      // Trigger initial capture immediately
      startMonitoringCapture();

      // Schedule periodic captures
      autoMonitorTimer = setInterval(() => {
        if (!isCapturing) {
          startMonitoringCapture();
        }
      }, AUTO_MONITOR_INTERVAL_MS);
    } else {
      autoPulse.classList.add('hidden');
      console.log('[UC029 Extension] Auto Monitor disabled');
      if (autoMonitorTimer) {
        clearInterval(autoMonitorTimer);
        autoMonitorTimer = null;
      }
    }
  });

  // ============================================================
  // INITIALIZATION ON LOAD
  // ============================================================
  await detectActiveTabDomain();
  await checkBackendHealth();
});
