/**
 * Smart Link Interceptor — Popup Script (v2.0)
 * 
 * Loads stats and scan history from chrome.storage via the service worker.
 * Shows multi-source intelligence badges (VT, GSB, Gemini) in scan results.
 */

document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadHistory();

  document.getElementById('btn-clear').addEventListener('click', clearHistory);
});

function loadStats() {
  chrome.runtime.sendMessage({ action: 'get_stats' }, (stats) => {
    if (chrome.runtime.lastError || !stats) return;
    document.getElementById('stat-total').textContent = formatNumber(stats.total);
    document.getElementById('stat-safe').textContent = formatNumber(stats.safe);
    document.getElementById('stat-blocked').textContent = formatNumber(stats.blocked);
  });
}

function loadHistory() {
  chrome.runtime.sendMessage({ action: 'get_history' }, (history) => {
    if (chrome.runtime.lastError || !history) return;

    const listEl = document.getElementById('history-list');

    if (!history.length) {
      listEl.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">📋</div>
          <p>No links scanned yet</p>
          <p class="empty-hint">Click a link on Gmail or WhatsApp Web to start</p>
        </div>
      `;
      return;
    }

    listEl.innerHTML = history.slice(0, 50).map((scan) => {
      const icon = scan.isSafe ? '✅' : '🚨';
      const cls = scan.isSafe ? 'safe' : 'unsafe';
      const time = formatTime(scan.timestamp);
      const shortUrl = truncateUrl(scan.url, 36);

      // Build source badges
      let badges = '';
      if (scan.sources) {
        const s = scan.sources;
        if (s.virusTotal && s.virusTotal.available) {
          const vtClass = s.virusTotal.malicious > 0 ? 'badge-danger' : 'badge-safe';
          badges += `<span class="source-badge ${vtClass}" title="VirusTotal: ${s.virusTotal.malicious}/${s.virusTotal.totalEngines} detections">VT:${s.virusTotal.malicious}/${s.virusTotal.totalEngines}</span>`;
        }
        if (s.safeBrowsing && s.safeBrowsing.available) {
          const gsbClass = s.safeBrowsing.isThreat ? 'badge-danger' : 'badge-safe';
          const gsbText = s.safeBrowsing.isThreat ? '⚠️' : '✓';
          badges += `<span class="source-badge ${gsbClass}" title="Google Safe Browsing: ${s.safeBrowsing.isThreat ? s.safeBrowsing.threatTypes.join(', ') : 'Clean'}">GSB:${gsbText}</span>`;
        }
      }

      // Timing info
      let timingInfo = '';
      if (scan.timing && scan.timing.totalMs) {
        timingInfo = `<span class="timing-badge" title="Total scan time">${scan.timing.totalMs}ms</span>`;
      }

      return `
        <div class="history-item ${cls}" title="${escapeHtml(scan.url)}">
          <span class="history-icon">${icon}</span>
          <div class="history-details">
            <span class="history-url">${escapeHtml(shortUrl)}</span>
            <div class="history-meta">
              <span>${time}</span>
              ${badges ? `<span>·</span><span class="source-badges">${badges}</span>` : ''}
              ${timingInfo}
            </div>
            <div class="history-reason-row">
              <span class="history-reason">${escapeHtml(scan.reason || 'No details')}</span>
            </div>
          </div>
        </div>
      `;
    }).join('');
  });
}

function clearHistory() {
  if (!confirm('Clear all scan history and stats?')) return;

  chrome.runtime.sendMessage({ action: 'clear_history' }, () => {
    document.getElementById('stat-total').textContent = '0';
    document.getElementById('stat-safe').textContent = '0';
    document.getElementById('stat-blocked').textContent = '0';
    document.getElementById('history-list').innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">📋</div>
        <p>No links scanned yet</p>
        <p class="empty-hint">Click a link on Gmail or WhatsApp Web to start</p>
      </div>
    `;
  });
}

// ─── Utilities ───────────────────────────────────────────
function formatNumber(n) {
  if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
  return String(n);
}

function formatTime(timestamp) {
  const diff = Date.now() - timestamp;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function truncateUrl(url, maxLen) {
  try {
    const u = new URL(url);
    const display = u.hostname + u.pathname;
    if (display.length > maxLen) return display.substring(0, maxLen) + '…';
    return display;
  } catch {
    return url.length > maxLen ? url.substring(0, maxLen) + '…' : url;
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
