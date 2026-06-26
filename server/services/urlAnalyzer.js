/**
 * Smart Link Interceptor — URL Analyzer
 * 
 * Extracts security-relevant metadata from a URL before passing
 * it to the Gemini API. This provides structured context that
 * significantly reduces LLM hallucinations.
 */

import https from 'https';
import http from 'http';

/**
 * Analyze a URL and extract security metadata
 * @param {string} targetUrl
 * @returns {object} URL analysis results
 */
export async function analyzeUrl(targetUrl) {
  const analysis = {
    url: targetUrl,
    domain: null,
    tld: null,
    hasSSL: false,
    isShortUrl: false,
    resolvedUrl: null,
    urlEntropy: 0,
    suspiciousPatterns: [],
    pathDepth: 0,
    hasIPAddress: false,
    queryParams: 0,
    domainLength: 0,
    subdomainCount: 0,
  };

  try {
    const parsed = new URL(targetUrl);

    analysis.domain = parsed.hostname;
    analysis.domainLength = parsed.hostname.length;
    analysis.hasSSL = parsed.protocol === 'https:';
    analysis.pathDepth = parsed.pathname.split('/').filter(Boolean).length;
    analysis.queryParams = [...parsed.searchParams].length;

    // Extract TLD
    const parts = parsed.hostname.split('.');
    analysis.tld = parts[parts.length - 1];
    analysis.subdomainCount = Math.max(0, parts.length - 2);

    // Check if domain is an IP address
    analysis.hasIPAddress = /^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname);

    // Check for known shortlink services
    const shortDomains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
      'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy'];
    analysis.isShortUrl = shortDomains.includes(parsed.hostname);

    // Calculate URL entropy (higher = more random = more suspicious)
    analysis.urlEntropy = calculateEntropy(targetUrl);

    // Detect suspicious patterns
    analysis.suspiciousPatterns = detectSuspiciousPatterns(targetUrl, parsed);

    // If it's a short URL, attempt to resolve it
    if (analysis.isShortUrl) {
      try {
        analysis.resolvedUrl = await unshortenUrl(targetUrl);
      } catch {
        analysis.resolvedUrl = null;
      }
    }

  } catch (error) {
    analysis.suspiciousPatterns.push('Invalid URL format');
  }

  return analysis;
}

/**
 * Shannon entropy of a string — high entropy = random-looking = suspicious
 */
function calculateEntropy(str) {
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

/**
 * Detect common phishing patterns in the URL
 */
function detectSuspiciousPatterns(rawUrl, parsed) {
  const patterns = [];

  // Typosquatting indicators
  const typoTargets = [
    { legit: 'google', pattern: /g[o0]{2,}gle|go+gle|googl[e3]/i },
    { legit: 'facebook', pattern: /faceb[o0]{2,}k|facebo+k|faceb00k/i },
    { legit: 'amazon', pattern: /amaz[o0]n|amaz0n|amazn/i },
    { legit: 'paypal', pattern: /paypa[l1]|paypai|payp[a@]l/i },
    { legit: 'microsoft', pattern: /micr[o0]s[o0]ft|micros0ft/i },
    { legit: 'apple', pattern: /app[l1]e|app1e|appl3/i },
  ];

  for (const { legit, pattern } of typoTargets) {
    if (pattern.test(parsed.hostname) && !parsed.hostname.includes(legit + '.com')) {
      patterns.push(`Possible typosquatting of ${legit}.com`);
    }
  }

  // Suspicious TLDs
  const suspiciousTlds = ['xyz', 'top', 'click', 'club', 'work', 'loan', 'tk', 'ml', 'ga', 'cf', 'gq'];
  const tld = parsed.hostname.split('.').pop();
  if (suspiciousTlds.includes(tld)) {
    patterns.push(`Suspicious TLD: .${tld}`);
  }

  // IP address as domain
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) {
    patterns.push('Uses IP address instead of domain name');
  }

  // Excessive subdomains (e.g., secure.login.google.com.evil.com)
  if (parsed.hostname.split('.').length > 4) {
    patterns.push('Excessive subdomains (possible domain spoofing)');
  }

  // Login/account keywords in path (credential phishing)
  if (/\/(login|signin|account|verify|secure|auth|password|update)/i.test(parsed.pathname)) {
    patterns.push('Contains credential-harvesting keywords in path');
  }

  // @ symbol in URL (obscure actual destination)
  if (rawUrl.includes('@')) {
    patterns.push('Contains @ symbol (may redirect to different domain)');
  }

  // Extremely long URLs (often used to hide actual destination)
  if (rawUrl.length > 200) {
    patterns.push('Unusually long URL');
  }

  // Encoded characters that look suspicious
  if (/%[0-9a-f]{2}/i.test(rawUrl) && rawUrl.split('%').length > 5) {
    patterns.push('Heavy URL encoding (possible obfuscation)');
  }

  // Data URI
  if (rawUrl.startsWith('data:')) {
    patterns.push('Data URI (bypasses normal URL security)');
  }

  return patterns;
}

/**
 * Attempt to resolve a shortened URL via HTTP HEAD request
 */
function unshortenUrl(shortUrl, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    let redirects = 0;

    function follow(url) {
      if (redirects >= maxRedirects) {
        resolve(url);
        return;
      }

      const client = url.startsWith('https') ? https : http;
      const req = client.request(url, { method: 'HEAD', timeout: 5000 }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          redirects++;
          const next = res.headers.location.startsWith('http')
            ? res.headers.location
            : new URL(res.headers.location, url).href;
          follow(next);
        } else {
          resolve(url);
        }
      });

      req.on('error', () => reject(new Error('Failed to unshorten')));
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.end();
    }

    follow(shortUrl);
  });
}
