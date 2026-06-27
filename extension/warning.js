/**
 * Smart Link Interceptor — Warning Page Script (v2.0)
 * 
 * Parses URL parameters to display the blocked URL, threat reason,
 * and multi-source intelligence details.
 * Handles user actions (go back or proceed anyway).
 */

document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get('url') || 'Unknown URL';
  const reason = params.get('reason') || 'This link was flagged as potentially malicious.';
  const sourcesRaw = params.get('sources');

  document.getElementById('blocked-url').textContent = blockedUrl;
  document.getElementById('threat-reason').textContent = reason;

  // Populate multi-source intelligence panel
  if (sourcesRaw) {
    try {
      const sources = JSON.parse(sourcesRaw);
      const panel = document.getElementById('sources-panel');
      panel.style.display = 'block';

      // VirusTotal
      if (sources.virusTotal) {
        const vt = sources.virusTotal;
        const vtBody = document.getElementById('src-vt-body');
        if (vt.available) {
          const status = vt.malicious > 0 ? '🚨' : '✅';
          vtBody.innerHTML = `${status} ${vt.malicious}/${vt.totalEngines} engines flagged`;
          if (vt.flaggedBy && vt.flaggedBy.length > 0) {
            vtBody.innerHTML += `<br><small style="color:#64748b">By: ${vt.flaggedBy.join(', ')}</small>`;
          }
          if (vt.malicious > 0) {
            document.getElementById('src-vt').classList.add('source-danger');
          }
        } else {
          vtBody.textContent = '⚪ Not available';
        }
      }

      // Google Safe Browsing
      if (sources.safeBrowsing) {
        const gsb = sources.safeBrowsing;
        const gsbBody = document.getElementById('src-gsb-body');
        if (gsb.available) {
          if (gsb.isThreat) {
            gsbBody.innerHTML = `🚨 Threat: ${(gsb.threatTypes || []).join(', ')}`;
            document.getElementById('src-gsb').classList.add('source-danger');
          } else {
            gsbBody.textContent = '✅ No threats found';
          }
        } else {
          gsbBody.textContent = '⚪ Not available';
        }
      }

      // Heuristics
      if (sources.heuristics) {
        const h = sources.heuristics;
        const hBody = document.getElementById('src-heur-body');
        const patterns = h.suspiciousPatterns || [];
        if (patterns.length > 0) {
          hBody.innerHTML = `⚠️ ${patterns.slice(0, 3).join('<br>⚠️ ')}`;
          document.getElementById('src-heuristics').classList.add('source-danger');
        } else {
          let info = '✅ No suspicious patterns';
          if (h.isShortUrl) info += '<br>🔗 Shortened URL';
          if (h.hasIPAddress) info += '<br>🌐 IP-based URL';
          hBody.innerHTML = info;
        }
      }
    } catch (e) {
      // Failed to parse sources — don't show the panel
    }
  }

  // Go Back button
  document.getElementById('btn-go-back').addEventListener('click', () => {
    window.close();
  });

  // Proceed Anyway button (dangerous)
  document.getElementById('btn-proceed').addEventListener('click', () => {
    const confirmed = confirm(
      '⚠️ You are about to visit a link flagged as potentially malicious.\n\n' +
      'This could expose you to:\n' +
      '• Phishing (credential theft)\n' +
      '• Malware downloads\n' +
      '• Financial scams\n\n' +
      'Are you absolutely sure you want to continue?'
    );

    if (confirmed) {
      window.location.href = blockedUrl;
    }
  });
});
