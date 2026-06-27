/**
 * Smart Link Interceptor — Concurrent URL Scanner Orchestrator
 * 
 * This is the heart of the concurrency model. Instead of calling
 * each threat intelligence source sequentially:
 * 
 *   Call VirusTotal → wait... → Call Safe Browsing → wait... → Call Heuristics → wait...
 * 
 * We launch all scanners simultaneously using Promise.allSettled():
 * 
 *   Future1 → VirusTotal      ┐
 *   Future2 → Safe Browsing   ├─ All run in parallel
 *   Future3 → URL Heuristics  ┘
 * 
 * This is the Node.js equivalent of C++ std::async:
 * 
 *   auto vt     = std::async(std::launch::async, virusTotalScan, url);
 *   auto google = std::async(std::launch::async, safeBrowsingScan, url);
 *   auto heur   = std::async(std::launch::async, heuristicScan, url);
 * 
 * After all futures resolve, results are aggregated and fed to
 * Gemini AI as the final arbiter for the definitive verdict.
 */

import { scanWithVirusTotal } from './virusTotal.js';
import { scanWithSafeBrowsing } from './safeBrowsing.js';
import { analyzeUrl } from './urlAnalyzer.js';
import { classifyUrl } from './gemini.js';

/**
 * Execute full concurrent scan pipeline
 * 
 * @param {string} targetUrl - URL to scan
 * @returns {object} Complete verdict with all source data
 */
export async function concurrentScan(targetUrl) {
  const startTime = Date.now();

  // ═══════════════════════════════════════════════════════════
  //  CONCURRENT EXECUTION — All scanners launch simultaneously
  // ═══════════════════════════════════════════════════════════
  const [vtResult, gsbResult, heuristicResult] = await Promise.allSettled([
    scanWithVirusTotal(targetUrl),     // Future 1: VirusTotal (70+ engines)
    scanWithSafeBrowsing(targetUrl),   // Future 2: Google Safe Browsing
    analyzeUrl(targetUrl),             // Future 3: Local heuristic analysis
  ]);

  // Extract values (with safe fallbacks for rejected promises)
  const virusTotal = vtResult.status === 'fulfilled'
    ? vtResult.value
    : { available: false, error: vtResult.reason?.message, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, totalEngines: 0, vendors: [] };

  const safeBrowsing = gsbResult.status === 'fulfilled'
    ? gsbResult.value
    : { available: false, error: gsbResult.reason?.message, isThreat: false, threats: [], threatTypes: [] };

  const heuristics = heuristicResult.status === 'fulfilled'
    ? heuristicResult.value
    : { suspiciousPatterns: [], domain: 'unknown', hasSSL: false, hasIPAddress: false };

  const concurrentMs = Date.now() - startTime;

  // ═══════════════════════════════════════════════════════════
  //  GEMINI AI — Final Arbiter
  //  Feed ALL concurrent results to Gemini for the definitive verdict
  // ═══════════════════════════════════════════════════════════
  const geminiStartTime = Date.now();

  const verdict = await classifyUrl(targetUrl, heuristics, {
    virusTotal,
    safeBrowsing,
  });

  const geminiMs = Date.now() - geminiStartTime;
  const totalMs = Date.now() - startTime;

  // ═══════════════════════════════════════════════════════════
  //  BUILD ENRICHED RESPONSE
  // ═══════════════════════════════════════════════════════════
  return {
    isSafe: verdict.isSafe,
    reason: verdict.reason,
    confidence: verdict.confidence,
    cached: false,

    // Multi-source intelligence report
    sources: {
      virusTotal: {
        available: virusTotal.available || false,
        malicious: virusTotal.malicious || 0,
        suspicious: virusTotal.suspicious || 0,
        totalEngines: virusTotal.totalEngines || 0,
        flaggedBy: (virusTotal.vendors || []).map(v => v.name).slice(0, 5),
      },
      safeBrowsing: {
        available: safeBrowsing.available || false,
        isThreat: safeBrowsing.isThreat || false,
        threatTypes: safeBrowsing.threatTypes || [],
      },
      heuristics: {
        suspiciousPatterns: heuristics.suspiciousPatterns || [],
        entropy: heuristics.urlEntropy || 0,
        isShortUrl: heuristics.isShortUrl || false,
        hasIPAddress: heuristics.hasIPAddress || false,
      },
    },

    // Performance telemetry
    timing: {
      concurrentMs,  // Time for all parallel scanners
      geminiMs,      // Time for Gemini classification
      totalMs,       // Total end-to-end
    },
  };
}
