/**
 * Smart Link Interceptor — VirusTotal Service
 * 
 * Queries VirusTotal v3 API for URL reputation data.
 * Returns detection stats from 70+ security vendors.
 * 
 * API Docs: https://docs.virustotal.com/reference/url-info
 */

let apiKey = null;
let isEnabled = false;

/**
 * Initialize VirusTotal client
 */
export function initVirusTotal() {
  apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey || apiKey === 'your_virustotal_api_key_here') {
    console.warn('⚠️  VIRUSTOTAL_API_KEY not set — VirusTotal scanning disabled');
    console.warn('   Get one at: https://www.virustotal.com/gui/my-apikey');
    isEnabled = false;
    return;
  }

  isEnabled = true;
  console.log('✅ VirusTotal API initialized');
}

/**
 * Scan a URL with VirusTotal
 * 
 * Strategy: First try to GET existing analysis (fast, ~200ms).
 * If no analysis exists, POST to submit for scan, then poll once.
 * 
 * @param {string} targetUrl - URL to scan
 * @returns {object} { malicious, suspicious, harmless, undetected, totalEngines, vendors }
 */
export async function scanWithVirusTotal(targetUrl) {
  if (!isEnabled) {
    return {
      available: false,
      error: 'VirusTotal API key not configured',
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      totalEngines: 0,
      vendors: [],
    };
  }

  try {
    // VirusTotal uses base64-encoded URL (without padding) as the ID
    const urlId = Buffer.from(targetUrl).toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    // Step 1: Try to GET existing analysis
    const getResponse = await fetchWithTimeout(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      {
        method: 'GET',
        headers: { 'x-apikey': apiKey },
      },
      8000 // 8s timeout
    );

    if (getResponse.ok) {
      const data = await getResponse.json();
      return parseVTResponse(data);
    }

    // Step 2: If not found (404), submit the URL for scanning
    if (getResponse.status === 404) {
      const submitResponse = await fetchWithTimeout(
        'https://www.virustotal.com/api/v3/urls',
        {
          method: 'POST',
          headers: {
            'x-apikey': apiKey,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: `url=${encodeURIComponent(targetUrl)}`,
        },
        8000
      );

      if (submitResponse.ok) {
        const submitData = await submitResponse.json();
        const analysisId = submitData.data?.id;

        if (analysisId) {
          // Brief wait for analysis to process, then poll
          await new Promise(r => setTimeout(r, 2000));

          const pollResponse = await fetchWithTimeout(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            {
              method: 'GET',
              headers: { 'x-apikey': apiKey },
            },
            8000
          );

          if (pollResponse.ok) {
            const pollData = await pollResponse.json();
            return parseVTAnalysisResponse(pollData);
          }
        }
      }

      // Submitted but couldn't get results yet
      return {
        available: true,
        pending: true,
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        totalEngines: 0,
        vendors: [],
      };
    }

    // Rate limited or other error
    const errorText = await getResponse.text().catch(() => '');
    return {
      available: false,
      error: `VirusTotal HTTP ${getResponse.status}: ${errorText.slice(0, 100)}`,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      totalEngines: 0,
      vendors: [],
    };

  } catch (error) {
    return {
      available: false,
      error: `VirusTotal error: ${error.message}`,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      totalEngines: 0,
      vendors: [],
    };
  }
}

/**
 * Parse a VT URL report response
 */
function parseVTResponse(data) {
  const stats = data.data?.attributes?.last_analysis_stats || {};
  const results = data.data?.attributes?.last_analysis_results || {};

  // Extract vendors that flagged it as malicious
  const maliciousVendors = Object.entries(results)
    .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
    .map(([vendor, v]) => ({ name: vendor, result: v.result || v.category }));

  return {
    available: true,
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    totalEngines: (stats.malicious || 0) + (stats.suspicious || 0) +
                  (stats.harmless || 0) + (stats.undetected || 0),
    vendors: maliciousVendors.slice(0, 10), // Top 10 flagging vendors
  };
}

/**
 * Parse a VT analysis (from fresh submission) response
 */
function parseVTAnalysisResponse(data) {
  const stats = data.data?.attributes?.stats || {};
  const results = data.data?.attributes?.results || {};

  const maliciousVendors = Object.entries(results)
    .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
    .map(([vendor, v]) => ({ name: vendor, result: v.result || v.category }));

  return {
    available: true,
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    totalEngines: (stats.malicious || 0) + (stats.suspicious || 0) +
                  (stats.harmless || 0) + (stats.undetected || 0),
    vendors: maliciousVendors.slice(0, 10),
  };
}

/**
 * Fetch with timeout support
 */
function fetchWithTimeout(url, options, timeoutMs) {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`Timeout after ${timeoutMs}ms`)), timeoutMs)
    ),
  ]);
}
