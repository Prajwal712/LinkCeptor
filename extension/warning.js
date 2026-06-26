/**
 * Smart Link Interceptor — Warning Page Script
 * 
 * Parses URL parameters to display the blocked URL and threat reason,
 * and handles user actions (go back or proceed anyway).
 */

document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get('url') || 'Unknown URL';
  const reason = params.get('reason') || 'This link was flagged as potentially malicious.';

  document.getElementById('blocked-url').textContent = blockedUrl;
  document.getElementById('threat-reason').textContent = reason;

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
