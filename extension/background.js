/**
 * Smart Link Interceptor — Service Worker (Background Script)
 * 
 * Handles messages from the content script, queries the backend API,
 * and manages scan history in chrome.storage.local.
 */

// ─── Configuration ───────────────────────────────────────────────
const API_ENDPOINT = 'http://localhost:3001/api/verify';
// Change this to your deployed server URL in production:
// const API_ENDPOINT = 'https://your-cloudflare-worker.workers.dev/api/verify';
// or
// const API_ENDPOINT = 'https://your-backend.onrender.com/api/verify';

const REQUEST_TIMEOUT_MS = 15000;

// ─── Message Handler ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'check_link') {
    handleLinkCheck(request.url)
      .then(sendResponse)
      .catch(() => sendResponse({
        isSafe: false,
        reason: 'Unable to reach verification server. Blocked as a precaution.'
      }));
    return true; // Keep the message channel open for async response
  }

  if (request.action === 'save_scan') {
    saveScanToHistory(request.data);
    return false;
  }

  if (request.action === 'get_stats') {
    getStats().then(sendResponse);
    return true;
  }

  if (request.action === 'get_history') {
    getHistory().then(sendResponse);
    return true;
  }

  if (request.action === 'clear_history') {
    chrome.storage.local.set({ scanHistory: [], stats: { total: 0, safe: 0, blocked: 0 } });
    sendResponse({ success: true });
    return false;
  }
});

// ─── Link Check Logic ────────────────────────────────────────────
async function handleLinkCheck(url) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }

    const data = await response.json();
    return {
      isSafe: Boolean(data.isSafe),
      reason: data.reason || 'No details provided',
      confidence: data.confidence || null,
      cached: data.cached || false
    };
  } catch (error) {
    clearTimeout(timeoutId);

    if (error.name === 'AbortError') {
      return {
        isSafe: false,
        reason: 'Verification timed out. Blocked as a precaution.'
      };
    }

    return {
      isSafe: false,
      reason: `Server unreachable: ${error.message}. Blocked as a precaution.`
    };
  }
}

// ─── Scan History Management ─────────────────────────────────────
async function saveScanToHistory(scanData) {
  try {
    const result = await chrome.storage.local.get(['scanHistory', 'stats']);
    const history = result.scanHistory || [];
    const stats = result.stats || { total: 0, safe: 0, blocked: 0 };

    // Prepend new scan (most recent first)
    history.unshift(scanData);

    // Keep only the last 200 scans
    if (history.length > 200) history.length = 200;

    // Update stats
    stats.total++;
    if (scanData.isSafe) {
      stats.safe++;
    } else {
      stats.blocked++;
    }

    await chrome.storage.local.set({ scanHistory: history, stats });
  } catch (e) {
    console.error('[SLI] Failed to save scan:', e);
  }
}

async function getStats() {
  const result = await chrome.storage.local.get('stats');
  return result.stats || { total: 0, safe: 0, blocked: 0 };
}

async function getHistory() {
  const result = await chrome.storage.local.get('scanHistory');
  return result.scanHistory || [];
}

// ─── Extension Install Handler ───────────────────────────────────
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.storage.local.set({
      scanHistory: [],
      stats: { total: 0, safe: 0, blocked: 0 }
    });
    console.log('[Smart Link Interceptor] Extension installed successfully');
  }
});
