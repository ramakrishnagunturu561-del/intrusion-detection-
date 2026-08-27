/**
 * UC029 Quantum Intrusion Detection System
 * Background Service Worker (Manifest V3)
 *
 * PERMISSION JUSTIFICATIONS:
 * - 'activeTab' and 'tabs': Required to read active browser domain for display in security dashboard.
 * - 'host_permissions' (http://127.0.0.1:8080/*, http://localhost:8080/*): Required to communicate with local FastAPI backend.
 *
 * ARCHITECTURAL SECURITY NOTE:
 * The background worker and extension UI act solely as a local monitoring interface.
 * All PCAP capture, flow processing, and Quantum-Classical ML inference are handled
 * securely by the local FastAPI backend and TShark engine.
 */

// Central API Base URL Configuration
const API_BASE_URL = 'http://127.0.0.1:8080';

// Service Worker Lifecycle Initialization
chrome.runtime.onInstalled.addListener(() => {
  console.log('[UC029 Extension] Service Worker installed successfully.');
  updateExtensionBadge('READY', '#00f0ff');
});

// Helper function to update action badge state
function updateExtensionBadge(text, color) {
  try {
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color });
  } catch (err) {
    console.error('[UC029 Extension] Error updating badge:', err);
  }
}

// Handle messages from popup script if background processing is required
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CHECK_HEALTH') {
    fetch(`${API_BASE_URL}/health`)
      .then((res) => res.json())
      .then((data) => {
        updateExtensionBadge('OK', '#10b981');
        sendResponse({ status: 'online', data });
      })
      .catch((err) => {
        updateExtensionBadge('OFF', '#ef4444');
        sendResponse({ status: 'offline', error: err.message });
      });
    return true; // Keep message channel open for async response
  }

  if (message.type === 'UPDATE_BADGE') {
    updateExtensionBadge(message.text, message.color);
    sendResponse({ success: true });
  }
});
