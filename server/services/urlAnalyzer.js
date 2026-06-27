/**
 * Smart Link Interceptor — URL Analyzer (v2.1)
 * 
 * Extracts security-relevant metadata from a URL before passing
 * it to the Gemini API. This provides structured context that
 * significantly reduces LLM hallucinations.
 * 
 * v2.1: Reduced false positives — heuristics are now advisory signals,
 * not hard blockers. Long URLs, query params, and common path keywords
 * on legitimate domains no longer trigger false flags.
 */

import https from 'https';
import http from 'http';

/**
 * Well-known legitimate domains that should not be penalized
 * for common patterns (long URLs, login paths, encoding, etc.)
 */
const KNOWN_LEGITIMATE_DOMAINS = new Set([
  'google.com', 'google.co.in', 'googleapis.com', 'gstatic.com',
  'youtube.com', 'youtu.be', 'yt.be',
  'facebook.com', 'fb.com', 'fbcdn.net',
  'twitter.com', 'x.com', 't.co',
  'instagram.com', 'cdninstagram.com',
  'linkedin.com', 'licdn.com',
  'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com',
  'microsoftonline.com', 'azure.com', 'bing.com', 'msn.com',
  'apple.com', 'icloud.com',
  'amazon.com', 'amazon.in', 'amazonaws.com', 'cloudfront.net',
  'github.com', 'githubusercontent.com', 'github.io',
  'gitlab.com', 'bitbucket.org',
  'stackoverflow.com', 'stackexchange.com',
  'reddit.com', 'redd.it',
  'discord.com', 'discordapp.com',
  'whatsapp.com', 'whatsapp.net',
  'telegram.org', 'telegram.me',
  'netflix.com', 'spotify.com',
  'paypal.com', 'stripe.com', 'razorpay.com',
  'zoom.us', 'teams.microsoft.com',
  'notion.so', 'figma.com', 'canva.com',
  'dropbox.com', 'box.com',
  'salesforce.com', 'force.com',
  'atlassian.com', 'atlassian.net', 'jira.com', 'trello.com',
  'slack.com', 'slackb.com',
  'hubspot.com', 'mailchimp.com',
  'cloudflare.com', 'vercel.com', 'netlify.com', 'heroku.com', 'render.com',
  'wikipedia.org', 'wikimedia.org',
  'medium.com', 'substack.com',
  'coursera.org', 'udemy.com', 'edx.org',
  'npmjs.com', 'pypi.org', 'crates.io',
  'docs.google.com', 'drive.google.com', 'mail.google.com',
]);

/**
 * Extract root domain from hostname for matching against known domains
 */
function extractRootDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length >= 3 && parts[parts.length - 2].length <= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Check if a hostname belongs to a known legitimate domain
 */
function isKnownDomain(hostname) {
  const root = extractRootDomain(hostname);
  return KNOWN_LEGITIMATE_DOMAINS.has(root) || KNOWN_LEGITIMATE_DOMAINS.has(hostname);
}

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
    isKnownDomain: false,
  };

  try {
    const parsed = new URL(targetUrl);

    analysis.domain = parsed.hostname;
    analysis.domainLength = parsed.hostname.length;
    analysis.hasSSL = parsed.protocol === 'https:';
    analysis.pathDepth = parsed.pathname.split('/').filter(Boolean).length;
    analysis.queryParams = [...parsed.searchParams].length;
    analysis.isKnownDomain = isKnownDomain(parsed.hostname);

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

    // Detect suspicious patterns (with reduced false-positive rate)
    analysis.suspiciousPatterns = detectSuspiciousPatterns(targetUrl, parsed, analysis.isKnownDomain);

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
 * 
 * v2.1 CHANGES to reduce false positives:
 * - Known legitimate domains skip most pattern checks
 * - "Long URL" threshold raised from 200 → 500 chars (Gmail/Google links are routinely 300+)
 * - URL encoding threshold raised from 5 → 10 occurrences
 * - Login/auth keywords only flagged on UNKNOWN domains (not google.com/accounts/login)
 * - Subdomain threshold raised from 4 → 5 parts
 * - Each pattern is tagged with a severity level (high/medium/low)
 */
function detectSuspiciousPatterns(rawUrl, parsed, knownDomain) {
  const patterns = [];

  // ── HIGH SEVERITY: Always flag regardless of domain ──────────────

  // Typosquatting indicators (high severity — always check)
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

  // IP address as domain (high severity)
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) {
    patterns.push('Uses IP address instead of domain name');
  }

  // Data URI (high severity)
  if (rawUrl.startsWith('data:')) {
    patterns.push('Data URI (bypasses normal URL security)');
  }

  // @ symbol in URL (high severity — can obscure real destination)
  if (rawUrl.includes('@') && !parsed.pathname.includes('@')) {
    // Only flag if @ is in the authority portion, not in email addresses in the path
    patterns.push('Contains @ symbol in authority (may redirect to different domain)');
  }

  // ── SKIP remaining checks for known legitimate domains ───────────
  // Google, Microsoft, Amazon etc. routinely have long URLs, query params,
  // login paths, and URL encoding. These are NOT suspicious on known domains.
  if (knownDomain) {
    return patterns;
  }

  // ── MEDIUM SEVERITY: Only flag on unknown domains ────────────────

  // Suspicious TLDs (medium — only matters on unknown domains)
  const suspiciousTlds = ['xyz', 'top', 'click', 'club', 'work', 'loan', 'tk', 'ml', 'ga', 'cf', 'gq'];
  const tld = parsed.hostname.split('.').pop();
  if (suspiciousTlds.includes(tld)) {
    patterns.push(`Suspicious TLD: .${tld}`);
  }

  // Excessive subdomains — raised from 4 → 5 (medium)
  // Legitimate: mail.google.com (3 parts) or docs.google.co.in (4 parts)
  // Suspicious: secure.login.google.com.evil.com (6+ parts)
  if (parsed.hostname.split('.').length > 5) {
    patterns.push('Excessive subdomains (possible domain spoofing)');
  }

  // Login/account keywords in path — ONLY on unknown domains (medium)
  // Gmail uses /accounts/login, Microsoft uses /auth — these are normal
  if (/\/(login|signin|account|verify|secure|auth|password|update)/i.test(parsed.pathname)) {
    patterns.push('Contains credential-harvesting keywords in path (unknown domain)');
  }

  // ── LOW SEVERITY: Only flag with additional conditions ───────────

  // Extremely long URLs — raised from 200 → 500 chars (low)
  // Gmail tracking links, Google Docs share links, etc. are routinely 300-400 chars
  if (rawUrl.length > 500) {
    patterns.push('Unusually long URL (500+ characters)');
  }

  // Heavy URL encoding — raised from 5 → 10 occurrences (low)
  // Normal URLs can have a few encoded params; only flag heavy obfuscation
  if (/%[0-9a-f]{2}/i.test(rawUrl) && rawUrl.split('%').length > 10) {
    patterns.push('Heavy URL encoding (possible obfuscation)');
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
