/**
 * Smart Link Interceptor — Gemini AI Service (v2.0)
 * 
 * Acts as the FINAL ARBITER in the multi-source threat intelligence pipeline.
 * Receives concurrent results from VirusTotal, Google Safe Browsing, and
 * local heuristics, then makes the definitive safety classification.
 * 
 * Uses gemini-2.0-flash for optimal latency in real-time applications.
 */

import { GoogleGenerativeAI } from '@google/generative-ai';

let genAI = null;
let model = null;

/**
 * Initialize the Gemini AI client
 */
export function initGemini() {
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey || apiKey === 'your_gemini_api_key_here') {
    console.error('❌ GEMINI_API_KEY is not set! Add it to your .env file.');
    console.error('   Get one at: https://aistudio.google.com/apikey');
    process.exit(1);
  }

  genAI = new GoogleGenerativeAI(apiKey);
  model = genAI.getGenerativeModel({
    model: 'gemini-2.0-flash',
    generationConfig: {
      temperature: 0.1,        // Low temperature for deterministic safety classification
      maxOutputTokens: 512,    // Slightly larger for multi-source reasoning
      responseMimeType: 'application/json',
    }
  });

  console.log('✅ Gemini AI initialized (gemini-2.0-flash) — Final Arbiter mode');
}

/**
 * Classify a URL using Gemini AI with ALL threat intelligence context
 * 
 * @param {string} targetUrl - The URL to analyze
 * @param {object} urlAnalysis - Pre-computed URL metadata from urlAnalyzer
 * @param {object} [threatIntel={}] - Concurrent results from VirusTotal + Safe Browsing
 * @returns {object} { isSafe: boolean, reason: string, confidence: string }
 */
export async function classifyUrl(targetUrl, urlAnalysis, threatIntel = {}) {
  if (!model) {
    throw new Error('Gemini AI not initialized');
  }

  const prompt = buildPrompt(targetUrl, urlAnalysis, threatIntel);

  try {
    const result = await model.generateContent(prompt);
    const responseText = result.response.text();

    // Parse the JSON response
    const parsed = JSON.parse(responseText);

    return {
      isSafe: Boolean(parsed.isSafe),
      reason: String(parsed.reason || 'No explanation provided'),
      confidence: String(parsed.confidence || 'medium'),
    };
  } catch (error) {
    console.error('[Gemini] Classification error:', error.message);

    // If the LLM fails, fall back to rule-based decision using available data
    return ruleBasedFallback(urlAnalysis, threatIntel);
  }
}

/**
 * Build a structured prompt with ALL threat intelligence context
 * This is where Gemini acts as the "final arbiter" — synthesizing
 * results from multiple concurrent scanners into one verdict.
 */
function buildPrompt(targetUrl, analysis, threatIntel) {
  const { virusTotal = {}, safeBrowsing = {} } = threatIntel;

  let vtSection = '';
  if (virusTotal.available) {
    vtSection = `
VIRUSTOTAL RESULTS (${virusTotal.totalEngines} security engines):
- Malicious detections: ${virusTotal.malicious}
- Suspicious detections: ${virusTotal.suspicious}
- Harmless: ${virusTotal.harmless}
- Undetected: ${virusTotal.undetected}
${virusTotal.vendors && virusTotal.vendors.length > 0
      ? `- Flagged by: ${virusTotal.vendors.map(v => `${v.name} (${v.result})`).join(', ')}`
      : '- No vendors flagged this URL'}`;
  } else {
    vtSection = `
VIRUSTOTAL: Unavailable (${virusTotal.error || 'API key not configured'})`;
  }

  let gsbSection = '';
  if (safeBrowsing.available) {
    if (safeBrowsing.isThreat) {
      gsbSection = `
GOOGLE SAFE BROWSING: ⚠️ THREAT DETECTED
- Threat types: ${safeBrowsing.threatTypes.join(', ')}
- Details: ${(safeBrowsing.threats || []).map(t => t.description).join('; ')}`;
    } else {
      gsbSection = `
GOOGLE SAFE BROWSING: ✅ No threats found`;
    }
  } else {
    gsbSection = `
GOOGLE SAFE BROWSING: Unavailable (${safeBrowsing.error || 'API key not configured'})`;
  }

  return `You are a cybersecurity URL analyzer acting as the FINAL ARBITER. You have received results from multiple threat intelligence sources run CONCURRENTLY. Your job is to synthesize all evidence and make a definitive safety classification.

ANALYZE THIS URL:
URL: ${targetUrl}
${analysis.resolvedUrl ? `Resolved URL (from shortener): ${analysis.resolvedUrl}` : ''}

═══ THREAT INTELLIGENCE — HIGH AUTHORITY (from concurrent scanners) ═══
${vtSection}
${gsbSection}

═══ LOCAL HEURISTIC ANALYSIS — LOW AUTHORITY (advisory only) ═══
- Domain: ${analysis.domain}
- Is known legitimate domain: ${analysis.isKnownDomain || false}
- TLD: .${analysis.tld}
- Has SSL: ${analysis.hasSSL}
- Domain length: ${analysis.domainLength} characters
- Subdomain count: ${analysis.subdomainCount}
- Path depth: ${analysis.pathDepth}
- Query parameters: ${analysis.queryParams}
- URL entropy: ${analysis.urlEntropy} (higher = more random)
- Uses IP address: ${analysis.hasIPAddress}
- Is shortened URL: ${analysis.isShortUrl}
${analysis.suspiciousPatterns.length > 0
      ? `- Heuristic flags (advisory — may be false positives):\n${analysis.suspiciousPatterns.map(p => `  • ${p}`).join('\n')}`
      : '- No suspicious patterns detected by static analysis'}

═══ DECISION RULES (strict priority order) ═══

AUTHORITY HIERARCHY: VirusTotal & Google Safe Browsing >>> Heuristics.
Heuristics alone should almost NEVER block a URL if VT and GSB say it is clean.

1. If Google Safe Browsing flags it as a threat → UNSAFE (high confidence)
2. If VirusTotal shows ≥3 malicious detections → UNSAFE (high confidence)
3. If VirusTotal shows 1-2 malicious detections + heuristic flags → UNSAFE (medium confidence)
4. If VirusTotal AND Google Safe Browsing both say CLEAN → SAFE (high confidence), REGARDLESS of heuristic flags
   - Long URLs, query parameters, /login paths, URL encoding are NORMAL on legitimate sites (Gmail, Google Docs, Microsoft, Amazon, etc.)
   - Do NOT flag these as suspicious if VT/GSB are clean
5. If ONLY heuristics flag something but VT/GSB are clean → SAFE (medium confidence)
   - Explain the heuristic concern in the reason but still mark as SAFE
6. If threat intel sources are unavailable AND there are high-severity heuristic flags (typosquatting, IP address domain, data URI) → UNSAFE (low confidence)
7. If threat intel sources are unavailable AND heuristics are low-severity only (long URL, encoding) → SAFE (low confidence)
8. Typosquatting of major brands is ALWAYS UNSAFE regardless of other signals
9. IP addresses as domains are UNSAFE unless known CDN/cloud provider

CRITICAL: Legitimate services like Gmail, Google Docs, Outlook, Amazon regularly produce URLs that are 300+ characters long with heavy query parameters and /login, /auth, /account paths. These are NOT phishing indicators. Trust VT/GSB over heuristics.

Respond in this exact JSON format:
{"isSafe": true_or_false, "reason": "Concise explanation citing which sources informed the decision", "confidence": "high_or_medium_or_low"}`;
}

/**
 * Rule-based fallback when Gemini is unavailable
 * 
 * AUTHORITY HIERARCHY: VT/GSB >>> Heuristics
 * Heuristics alone should NOT block a URL if VT/GSB are clean.
 */
function ruleBasedFallback(analysis, threatIntel = {}) {
  const { virusTotal = {}, safeBrowsing = {} } = threatIntel;
  const risks = analysis.suspiciousPatterns || [];

  // VT is only "clean" if it actually scanned with real engines (totalEngines > 0).
  // VT returning 0/0 means the URL has no data — that's NOT clean, that's unknown.
  const vtHasData = virusTotal.available && virusTotal.totalEngines > 0;
  const vtClean = vtHasData && virusTotal.malicious === 0;
  const gsbClean = safeBrowsing.available && !safeBrowsing.isThreat;

  const hasHighSeverityRisk = risks.some(r =>
    r.includes('typosquatting') ||
    r.includes('IP address') ||
    r.includes('Data URI') ||
    r.includes('@ symbol')
  );

  // Rule 1: Google Safe Browsing flagged it → BLOCK
  if (safeBrowsing.available && safeBrowsing.isThreat) {
    const types = (safeBrowsing.threatTypes || []).join(', ');
    return {
      isSafe: false,
      reason: `Google Safe Browsing flagged: ${types} (rule-based fallback)`,
      confidence: 'high',
    };
  }

  // Rule 2: VirusTotal has significant detections → BLOCK
  if (vtHasData && virusTotal.malicious >= 3) {
    return {
      isSafe: false,
      reason: `${virusTotal.malicious}/${virusTotal.totalEngines} VirusTotal engines flagged as malicious (rule-based fallback)`,
      confidence: 'high',
    };
  }

  // Rule 3: VirusTotal has some detections + high-severity heuristic → BLOCK
  if (vtHasData && virusTotal.malicious >= 1 && hasHighSeverityRisk) {
    return {
      isSafe: false,
      reason: `${virusTotal.malicious} VT detection(s) + ${risks[0]} (rule-based fallback)`,
      confidence: 'medium',
    };
  }

  // Rule 3.5: High-severity heuristics (typosquatting, IP domain) → BLOCK
  // even if VT has no data (0/0 engines). These are definitive phishing indicators
  // that should not be overridden by absence of threat intel data.
  if (hasHighSeverityRisk && !vtClean) {
    // Only allow override if VT actually scanned and found nothing (e.g., 0/90)
    // VT having 0/0 data does NOT override typosquatting detection
    return {
      isSafe: false,
      reason: `${risks[0]}${!vtHasData ? ' — no VT data to override' : ''} (rule-based fallback)`,
      confidence: vtHasData ? 'medium' : 'high',
    };
  }

  // Rule 4: VT AND/OR GSB are MEANINGFULLY clean → ALLOW (even if heuristics flag something)
  // This is the KEY rule that prevents false positives on legitimate long URLs.
  // Requires vtClean (0 malicious out of 50+ engines) — NOT just 0/0.
  if (vtClean || gsbClean) {
    const vtInfo = vtClean ? `VT: 0/${virusTotal.totalEngines}` : '';
    const gsbInfo = gsbClean ? 'GSB: clean' : '';
    const sources = [vtInfo, gsbInfo].filter(Boolean).join(', ');
    const heuristicNote = risks.length > 0
      ? ` (heuristic note: ${risks[0]} — overridden by clean threat intel)`
      : '';
    return {
      isSafe: true,
      reason: `Threat intelligence clean (${sources})${heuristicNote} (rule-based fallback)`,
      confidence: vtClean && gsbClean ? 'high' : 'medium',
    };
  }

  // Rule 5: No threat intel available + high-severity heuristic flag → BLOCK
  if (!virusTotal.available && !safeBrowsing.available && hasHighSeverityRisk) {
    return {
      isSafe: false,
      reason: `${risks[0]} — no threat intel available to verify (rule-based fallback)`,
      confidence: 'low',
    };
  }

  // Rule 6: No threat intel available + only low-severity heuristics → ALLOW
  // Don't block just because a URL is long or has encoding
  if (!virusTotal.available && !safeBrowsing.available && !hasHighSeverityRisk) {
    if (analysis.hasSSL && !analysis.hasIPAddress) {
      return {
        isSafe: true,
        reason: `SSL present, no high-severity risks (rule-based fallback — threat intel unavailable)`,
        confidence: 'low',
      };
    }
  }

  // Rule 7: IP address domain — always suspicious
  if (analysis.hasIPAddress) {
    return {
      isSafe: false,
      reason: `Uses IP address instead of domain name (rule-based fallback)`,
      confidence: 'medium',
    };
  }

  // Default: Allow with low confidence rather than false-positive block
  return {
    isSafe: true,
    reason: `No definitive threat signals (rule-based fallback — Gemini unavailable)`,
    confidence: 'low',
  };
}
