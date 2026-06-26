/**
 * Smart Link Interceptor — Content Script
 * 
 * Injected into Gmail and WhatsApp Web.
 * Intercepts all link clicks during the capturing phase,
 * queries the backend for a safety verdict, and either
 * proceeds or shows a warning.
 */

(function () {
  'use strict';

  // Prevent double-injection in SPAs
  if (window.__smartLinkInterceptorLoaded) return;
  window.__smartLinkInterceptorLoaded = true;

  /**
   * Creates and shows a scanning overlay near the clicked position
   */
  function showScanningOverlay(x, y) {
    // Remove any existing overlay
    removeScanningOverlay();

    const overlay = document.createElement('div');
    overlay.id = 'sli-scanning-overlay';
    overlay.innerHTML = `
      <div class="sli-scanning-card">
        <div class="sli-spinner"></div>
        <div class="sli-scanning-text">
          <span class="sli-title">🛡️ Smart Link Interceptor</span>
          <span class="sli-subtitle">Scanning link for threats...</span>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    // Position the card near the click
    const card = overlay.querySelector('.sli-scanning-card');
    const cardWidth = 320;
    const cardHeight = 72;
    let left = x + 12;
    let top = y - cardHeight / 2;

    // Keep within viewport
    if (left + cardWidth > window.innerWidth) left = x - cardWidth - 12;
    if (top < 8) top = 8;
    if (top + cardHeight > window.innerHeight) top = window.innerHeight - cardHeight - 8;

    card.style.left = left + 'px';
    card.style.top = top + 'px';
  }

  /**
   * Updates the overlay with the scan result
   */
  function showResultOverlay(isSafe, reason) {
    const card = document.querySelector('.sli-scanning-card');
    if (!card) return;

    card.classList.add(isSafe ? 'sli-safe' : 'sli-unsafe');
    card.innerHTML = `
      <div class="sli-result-icon">${isSafe ? '✅' : '🚨'}</div>
      <div class="sli-scanning-text">
        <span class="sli-title">${isSafe ? 'Link is Safe' : 'Threat Detected!'}</span>
        <span class="sli-subtitle">${reason || (isSafe ? 'Redirecting...' : 'Navigation blocked')}</span>
      </div>
    `;

    // Auto-remove after a delay
    setTimeout(removeScanningOverlay, isSafe ? 1500 : 4000);
  }

  function removeScanningOverlay() {
    const existing = document.getElementById('sli-scanning-overlay');
    if (existing) existing.remove();
  }

  /**
   * Saves scan result to extension storage for the popup stats
   */
  function saveScanResult(url, isSafe, reason) {
    try {
      chrome.runtime.sendMessage({
        action: 'save_scan',
        data: {
          url: url,
          isSafe: isSafe,
          reason: reason || '',
          timestamp: Date.now(),
          site: window.location.hostname
        }
      });
    } catch (e) {
      // Extension context may be invalidated — fail silently
    }
  }

  /**
   * Main click interceptor — uses capturing phase for priority
   */
  document.addEventListener('click', function (event) {
    const target = event.target.closest('a');

    if (!target || !target.href) return;

    const url = target.href;

    // Skip mailto:, tel:, javascript:, chrome-extension:, and # links
    if (/^(mailto:|tel:|javascript:|chrome-extension:|#)/.test(url)) return;

    // Skip same-page anchor links
    try {
      const linkUrl = new URL(url);
      if (linkUrl.origin === window.location.origin && linkUrl.pathname === window.location.pathname) return;
    } catch {
      return;
    }

    // Check local whitelist first — zero latency
    if (isWhitelisted(url)) {
      // Allow navigation, just log it
      saveScanResult(url, true, 'Whitelisted domain');
      return;
    }

    // Prevent default navigation for unknown links
    event.preventDefault();
    event.stopPropagation();

    // Show scanning UI
    showScanningOverlay(event.clientX, event.clientY);

    // Query the backend via the service worker
    chrome.runtime.sendMessage(
      { action: 'check_link', url: url },
      (response) => {
        if (chrome.runtime.lastError) {
          // Extension context error — allow navigation as fallback
          removeScanningOverlay();
          window.location.href = url;
          return;
        }

        const isSafe = response && response.isSafe;
        const reason = response ? response.reason : 'Unknown';

        saveScanResult(url, isSafe, reason);

        if (isSafe) {
          showResultOverlay(true, reason);
          setTimeout(() => {
            window.open(url, '_blank');
          }, 600);
        } else {
          showResultOverlay(false, reason);

          // Show full warning page
          const warningUrl = chrome.runtime.getURL('warning.html') +
            '?url=' + encodeURIComponent(url) +
            '&reason=' + encodeURIComponent(reason);
          window.open(warningUrl, '_blank');
        }
      }
    );
  }, true); // Capturing phase

  console.log('[Smart Link Interceptor] Content script loaded on', window.location.hostname);
})();
