/**
 * Smart Link Interceptor — Cloudflare Worker (Edge Cache)
 * 
 * Sits at the edge (closest to user) and checks the KV store
 * before forwarding to the backend. This layer provides:
 * - Sub-50ms responses for cached URLs
 * - Global distribution via Cloudflare's network
 * - 24-hour TTL on cached verdicts
 * 
 * Deploy with: npx wrangler deploy
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

export default {
  async fetch(request, env) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/api/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        service: 'Smart Link Interceptor Edge',
        location: request.cf?.colo || 'unknown',
        timestamp: new Date().toISOString()
      }), { headers: CORS_HEADERS });
    }

    // Main verification endpoint
    if (url.pathname === '/api/verify' && request.method === 'POST') {
      return handleVerify(request, env);
    }

    // Root
    return new Response(JSON.stringify({
      name: '🛡️ Smart Link Interceptor Edge',
      version: '1.0.0',
      edge: request.cf?.colo || 'unknown',
    }), { headers: CORS_HEADERS });
  }
};

async function handleVerify(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({
      isSafe: false,
      reason: 'Invalid request body',
      cached: false
    }), { status: 400, headers: CORS_HEADERS });
  }

  const targetUrl = body.url;
  if (!targetUrl) {
    return new Response(JSON.stringify({
      isSafe: false,
      reason: 'URL is required',
      cached: false
    }), { status: 400, headers: CORS_HEADERS });
  }

  // ─── 1. Check Edge Cache (KV Store) ───────────────
  try {
    const cached = await env.LINK_CACHE.get(targetUrl);
    if (cached) {
      const result = JSON.parse(cached);
      result.cached = true;
      result.edge = true;
      return new Response(JSON.stringify(result), { headers: CORS_HEADERS });
    }
  } catch {
    // KV error — continue to backend
  }

  // ─── 2. Cache Miss → Forward to Backend ────────────
  const backendUrl = env.BACKEND_URL || 'http://localhost:3001';

  try {
    const backendResponse = await fetch(`${backendUrl}/api/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl })
    });

    const resultText = await backendResponse.text();

    // ─── 3. Cache the Result (24-hour TTL) ────────────
    try {
      await env.LINK_CACHE.put(targetUrl, resultText, {
        expirationTtl: 86400 // 24 hours
      });
    } catch {
      // Cache write failure — non-critical
    }

    return new Response(resultText, {
      status: backendResponse.status,
      headers: CORS_HEADERS
    });

  } catch (error) {
    return new Response(JSON.stringify({
      isSafe: false,
      reason: `Edge: Backend unreachable (${error.message}). Blocked as a precaution.`,
      cached: false
    }), { status: 502, headers: CORS_HEADERS });
  }
}
