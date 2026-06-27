/**
 * Smart Link Interceptor — Verify Route (v2.0)
 * 
 * POST /api/verify
 * Body: { url: string }
 * Response: { isSafe, reason, confidence, cached, sources, timing }
 * 
 * Now uses the concurrent scanner pipeline instead of
 * sequential urlAnalyzer → Gemini calls.
 */

import { Router } from 'express';
import { getCached, setCached } from '../services/cache.js';
import { concurrentScan } from '../services/scanner.js';

const router = Router();

router.post('/verify', async (req, res) => {
  const { url } = req.body;

  // Validate input
  if (!url || typeof url !== 'string') {
    return res.status(400).json({
      isSafe: false,
      reason: 'Invalid request: URL is required',
      cached: false
    });
  }

  // Validate URL format
  try {
    new URL(url);
  } catch {
    return res.status(400).json({
      isSafe: false,
      reason: 'Invalid URL format',
      cached: false
    });
  }

  try {
    // 1. Check cache first
    const cached = await getCached(url);
    if (cached) {
      console.log(`[CACHE HIT] ${url}`);
      return res.json({ ...cached, cached: true });
    }

    console.log(`[CACHE MISS] Concurrent scan: ${url}`);

    // 2. Run concurrent scan pipeline
    //    VirusTotal + Safe Browsing + Heuristics → all in parallel
    //    Then Gemini AI as final arbiter
    const result = await concurrentScan(url);

    // 3. Cache the result
    await setCached(url, result);

    const vtInfo = result.sources?.virusTotal?.available
      ? `VT:${result.sources.virusTotal.malicious}/${result.sources.virusTotal.totalEngines}`
      : 'VT:off';
    const gsbInfo = result.sources?.safeBrowsing?.available
      ? (result.sources.safeBrowsing.isThreat ? 'GSB:⚠️' : 'GSB:✅')
      : 'GSB:off';

    console.log(
      `[VERDICT] ${url} → ${result.isSafe ? '✅ SAFE' : '🚨 UNSAFE'} ` +
      `(${vtInfo} | ${gsbInfo} | ${result.timing?.totalMs}ms): ${result.reason}`
    );

    return res.json(result);

  } catch (error) {
    console.error(`[ERROR] Failed to analyze ${url}:`, error.message);

    return res.status(500).json({
      isSafe: false,
      reason: 'Server error during analysis. Blocked as a precaution.',
      cached: false
    });
  }
});

// GET /api/health — Enhanced health check with service status
router.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Smart Link Interceptor API v2.0',
    version: '2.0.0',
    features: {
      virusTotal: !!process.env.VIRUSTOTAL_API_KEY,
      safeBrowsing: !!process.env.GOOGLE_SAFE_BROWSING_API_KEY,
      gemini: !!process.env.GEMINI_API_KEY,
      redis: !!process.env.REDIS_URL,
    },
    instance: process.env.INSTANCE_ID || `pid-${process.pid}`,
    timestamp: new Date().toISOString(),
  });
});

export default router;
