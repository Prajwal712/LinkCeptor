/**
 * Smart Link Interceptor — Verify Route
 * 
 * POST /api/verify
 * Body: { url: string }
 * Response: { isSafe: boolean, reason: string, confidence: string, cached: boolean }
 */

import { Router } from 'express';
import { getCached, setCached } from '../services/cache.js';
import { analyzeUrl } from '../services/urlAnalyzer.js';
import { classifyUrl } from '../services/gemini.js';

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

    console.log(`[CACHE MISS] Analyzing: ${url}`);

    // 2. Extract URL metadata
    const analysis = await analyzeUrl(url);

    // 3. Classify with Gemini AI
    const verdict = await classifyUrl(url, analysis);

    // 4. Build response
    const result = {
      isSafe: verdict.isSafe,
      reason: verdict.reason,
      confidence: verdict.confidence,
      cached: false
    };

    // 5. Cache the result
    await setCached(url, result);

    console.log(`[VERDICT] ${url} → ${result.isSafe ? '✅ SAFE' : '🚨 UNSAFE'}: ${result.reason}`);

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

// GET /api/health — Health check
router.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'Smart Link Interceptor API', timestamp: new Date().toISOString() });
});

export default router;
