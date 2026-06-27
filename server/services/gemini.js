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

═══ THREAT INTELLIGENCE (from concurrent scanners) ═══
${vtSection}
${gsbSection}

═══ LOCAL HEURISTIC ANALYSIS ═══
- Domain: ${analysis.domain}
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
      ? `- Detected suspicious patterns:\n${analysis.suspiciousPatterns.map(p => `  • ${p}`).join('\n')}`
      : '- No suspicious patterns detected by static analysis'}

═══ DECISION RULES (priority order) ═══
1. If Google Safe Browsing flags it as a threat → UNSAFE (high confidence)
2. If VirusTotal shows ≥3 malicious detections → UNSAFE (high confidence)
3. If VirusTotal shows 1-2 malicious detections + suspicious heuristics → UNSAFE (medium confidence)
4. If the domain is well-known and legitimate with clean threat intel → SAFE (high confidence)
5. If all threat intel is clean but heuristics show concerns → exercise caution, likely UNSAFE (medium confidence)
6. If threat intel sources are unavailable, rely on heuristics + domain reputation
7. Typosquatting of major brands is ALWAYS UNSAFE regardless of other signals
8. IP addresses as domains are ALWAYS UNSAFE unless known CDN

IMPORTANT: When multiple sources agree, confidence is HIGH. When they disagree, explain why and lean toward safety (block if unsure).

Respond in this exact JSON format:
{"isSafe": true_or_false, "reason": "Concise explanation citing which sources informed the decision", "confidence": "high_or_medium_or_low"}`;
}

/**
 * Rule-based fallback when Gemini is unavailable
 * Uses data from VirusTotal + Safe Browsing + heuristics
 */
function ruleBasedFallback(analysis, threatIntel = {}) {
  const { virusTotal = {}, safeBrowsing = {} } = threatIntel;
  const risks = analysis.suspiciousPatterns || [];

  // Rule 1: Google Safe Browsing flagged it
  if (safeBrowsing.available && safeBrowsing.isThreat) {
    const types = (safeBrowsing.threatTypes || []).join(', ');
    return {
      isSafe: false,
      reason: `Google Safe Browsing flagged: ${types} (rule-based fallback — Gemini unavailable)`,
      confidence: 'high',
    };
  }

  // Rule 2: VirusTotal has significant detections
  if (virusTotal.available && virusTotal.malicious >= 3) {
    return {
      isSafe: false,
      reason: `${virusTotal.malicious}/${virusTotal.totalEngines} VirusTotal engines flagged as malicious (rule-based fallback)`,
      confidence: 'high',
    };
  }

  // Rule 3: VirusTotal has some detections + heuristic concerns
  if (virusTotal.available && virusTotal.malicious >= 1 && risks.length > 0) {
    return {
      isSafe: false,
      reason: `${virusTotal.malicious} VT detection(s) + ${risks[0]} (rule-based fallback)`,
      confidence: 'medium',
    };
  }

  // Rule 4: No threat intel issues, no heuristic issues
  if (risks.length === 0 && analysis.hasSSL && !analysis.hasIPAddress) {
    const vtClean = virusTotal.available ? `, VT: 0/${virusTotal.totalEngines} detections` : '';
    const gsbClean = safeBrowsing.available ? ', GSB: clean' : '';
    return {
      isSafe: true,
      reason: `No suspicious patterns detected${vtClean}${gsbClean} (rule-based fallback)`,
      confidence: 'low',
    };
  }

  // Rule 5: Heuristic issues but no threat intel data
  if (risks.length >= 2 || analysis.hasIPAddress) {
    return {
      isSafe: false,
      reason: `Multiple risk indicators: ${risks.slice(0, 2).join('; ')} (rule-based fallback)`,
      confidence: 'medium',
    };
  }

  return {
    isSafe: false,
    reason: `Flagged for: ${risks[0] || 'Unable to verify'} (rule-based fallback — Gemini unavailable)`,
    confidence: 'low',
  };
}
