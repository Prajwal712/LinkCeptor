/**
 * Smart Link Interceptor — Google Safe Browsing Service
 * 
 * Queries Google Safe Browsing v4 Lookup API to check if a URL
 * is flagged as malware, social engineering, unwanted software,
 * or potentially harmful.
 * 
 * API Docs: https://developers.google.com/safe-browsing/v4/lookup-api
 */

let apiKey = null;
let isEnabled = false;

const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
];

const PLATFORM_TYPES = [
  'ANY_PLATFORM',
  'WINDOWS',
  'LINUX',
  'OSX',
];

const THREAT_ENTRY_TYPES = ['URL'];

/**
 * Initialize Google Safe Browsing client
 */
export function initSafeBrowsing() {
  apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (!apiKey || apiKey === 'your_google_safe_browsing_api_key_here') {
    console.warn('⚠️  GOOGLE_SAFE_BROWSING_API_KEY not set — Safe Browsing disabled');
    console.warn('   Get one at: https://console.cloud.google.com/apis/credentials');
    isEnabled = false;
    return;
  }

  isEnabled = true;
  console.log('✅ Google Safe Browsing API initialized');
}

/**
 * Check a URL against Google Safe Browsing
 * 
 * @param {string} targetUrl - URL to check
 * @returns {object} { isThreat, threats[], threatTypes[] }
 */
export async function scanWithSafeBrowsing(targetUrl) {
  if (!isEnabled) {
    return {
      available: false,
      error: 'Google Safe Browsing API key not configured',
      isThreat: false,
      threats: [],
      threatTypes: [],
    };
  }

  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

    const requestBody = {
      client: {
        clientId: 'smart-link-interceptor',
        clientVersion: '2.0.0',
      },
      threatInfo: {
        threatTypes: THREAT_TYPES,
        platformTypes: PLATFORM_TYPES,
        threatEntryTypes: THREAT_ENTRY_TYPES,
        threatEntries: [{ url: targetUrl }],
      },
    };

    const response = await fetchWithTimeout(
      endpoint,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      },
      5000 // 5s timeout — GSB is typically fast
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      return {
        available: false,
        error: `Safe Browsing HTTP ${response.status}: ${errorText.slice(0, 100)}`,
        isThreat: false,
        threats: [],
        threatTypes: [],
      };
    }

    const data = await response.json();
    return parseSafeBrowsingResponse(data);

  } catch (error) {
    return {
      available: false,
      error: `Safe Browsing error: ${error.message}`,
      isThreat: false,
      threats: [],
      threatTypes: [],
    };
  }
}

/**
 * Parse Safe Browsing threat match response
 */
function parseSafeBrowsingResponse(data) {
  const matches = data.matches || [];

  if (matches.length === 0) {
    return {
      available: true,
      isThreat: false,
      threats: [],
      threatTypes: [],
    };
  }

  // Extract unique threat types
  const threatTypes = [...new Set(matches.map(m => m.threatType))];

  // Build human-readable threat descriptions
  const threats = matches.map(match => ({
    type: match.threatType,
    platform: match.platformType,
    description: formatThreatType(match.threatType),
  }));

  return {
    available: true,
    isThreat: true,
    threats,
    threatTypes,
  };
}

/**
 * Convert threat type enum to human-readable description
 */
function formatThreatType(threatType) {
  const descriptions = {
    'MALWARE': 'Contains malware that can harm your device',
    'SOCIAL_ENGINEERING': 'Phishing or social engineering attempt',
    'UNWANTED_SOFTWARE': 'Contains unwanted or deceptive software',
    'POTENTIALLY_HARMFUL_APPLICATION': 'Potentially harmful application detected',
  };
  return descriptions[threatType] || threatType;
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
