/**
 * Smart Link Interceptor — Gemini AI Service
 * 
 * Sends URL analysis data to Gemini API for phishing classification.
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
      maxOutputTokens: 256,    // Short responses only
      responseMimeType: 'application/json',
    }
  });

  console.log('✅ Gemini AI initialized (gemini-2.0-flash)');
}

/**
 * Classify a URL using Gemini AI with full analysis context
 * 
 * @param {string} targetUrl - The URL to analyze
 * @param {object} urlAnalysis - Pre-computed URL metadata from urlAnalyzer
 * @returns {object} { isSafe: boolean, reason: string, confidence: string }
 */
export async function classifyUrl(targetUrl, urlAnalysis) {
  if (!model) {
    throw new Error('Gemini AI not initialized');
  }

  const prompt = buildPrompt(targetUrl, urlAnalysis);

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

    // If the LLM fails, fall back to heuristic analysis
    return heuristicFallback(urlAnalysis);
  }
}

/**
 * Build a structured prompt with all URL analysis context
 */
function buildPrompt(targetUrl, analysis) {
  return `You are a cybersecurity URL analyzer. Your job is to classify whether a URL is safe or potentially malicious (phishing, malware, scam, etc.).

ANALYZE THIS URL:
URL: ${targetUrl}
${analysis.resolvedUrl ? `Resolved URL (from shortener): ${analysis.resolvedUrl}` : ''}

PRE-COMPUTED ANALYSIS:
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

CLASSIFICATION RULES:
1. If the domain is a well-known, legitimate service (e.g., google.com, youtube.com) and the URL structure is normal → SAFE
2. If the domain closely mimics a legitimate service (typosquatting like g00gle.com) → UNSAFE
3. If the URL uses an IP address instead of a domain → UNSAFE
4. If the domain uses suspicious TLDs (.xyz, .tk, .ml, .ga, .cf, .gq) combined with other red flags → UNSAFE
5. Shortened URLs that resolve to unknown or suspicious domains → UNSAFE
6. URLs with credential-harvesting keywords (/login, /verify, /account) on non-legitimate domains → UNSAFE
7. Very long URLs with heavy encoding on unknown domains → UNSAFE

Respond in this exact JSON format:
{"isSafe": true_or_false, "reason": "One concise sentence explaining why", "confidence": "high_or_medium_or_low"}`;
}

/**
 * Heuristic fallback if Gemini API fails
 */
function heuristicFallback(analysis) {
  const risks = analysis.suspiciousPatterns || [];

  if (risks.length === 0 && analysis.hasSSL && !analysis.hasIPAddress) {
    return {
      isSafe: true,
      reason: 'No suspicious patterns detected (heuristic fallback)',
      confidence: 'low'
    };
  }

  if (risks.length >= 2 || analysis.hasIPAddress) {
    return {
      isSafe: false,
      reason: `Multiple risk indicators: ${risks.slice(0, 2).join('; ')} (heuristic fallback)`,
      confidence: 'medium'
    };
  }

  return {
    isSafe: false,
    reason: `Flagged for: ${risks[0] || 'Unable to verify'} (heuristic fallback — Gemini unavailable)`,
    confidence: 'low'
  };
}
