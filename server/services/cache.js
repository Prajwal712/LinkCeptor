/**
 * Smart Link Interceptor — Cache Service
 * 
 * Provides a unified caching interface. Uses Redis if available,
 * otherwise falls back to an in-memory Map with TTL support.
 */

let redisClient = null;
const memoryCache = new Map();
const DEFAULT_TTL = parseInt(process.env.CACHE_TTL || '86400', 10); // 24 hours

/**
 * Attempts to connect to Redis. If it fails, falls back to in-memory.
 */
export async function initCache() {
  const redisUrl = process.env.REDIS_URL;

  if (redisUrl) {
    try {
      const { default: Redis } = await import('ioredis');
      redisClient = new Redis(redisUrl, {
        maxRetriesPerRequest: 3,
        retryStrategy(times) {
          if (times > 3) return null;
          return Math.min(times * 200, 2000);
        }
      });

      await redisClient.ping();
      console.log('✅ Redis cache connected');
      return;
    } catch (error) {
      console.warn('⚠️  Redis unavailable, using in-memory cache:', error.message);
      redisClient = null;
    }
  } else {
    console.log('ℹ️  No REDIS_URL set, using in-memory cache');
  }
}

/**
 * Get a cached verdict for a URL
 * @param {string} url
 * @returns {object|null} Cached result or null
 */
export async function getCached(url) {
  const key = `sli:${url}`;

  if (redisClient) {
    try {
      const data = await redisClient.get(key);
      return data ? JSON.parse(data) : null;
    } catch {
      return null;
    }
  }

  // In-memory fallback
  const entry = memoryCache.get(key);
  if (!entry) return null;

  // Check TTL
  if (Date.now() > entry.expiresAt) {
    memoryCache.delete(key);
    return null;
  }

  return entry.value;
}

/**
 * Cache a verdict for a URL
 * @param {string} url
 * @param {object} result
 * @param {number} [ttl] TTL in seconds
 */
export async function setCached(url, result, ttl = DEFAULT_TTL) {
  const key = `sli:${url}`;

  if (redisClient) {
    try {
      await redisClient.setex(key, ttl, JSON.stringify(result));
    } catch {
      // Silently fail — cache is best-effort
    }
    return;
  }

  // In-memory fallback
  memoryCache.set(key, {
    value: result,
    expiresAt: Date.now() + ttl * 1000
  });

  // Evict old entries if the cache grows too large (> 10k entries)
  if (memoryCache.size > 10000) {
    const now = Date.now();
    for (const [k, v] of memoryCache) {
      if (now > v.expiresAt) memoryCache.delete(k);
    }
    // If still too large, evict oldest 20%
    if (memoryCache.size > 10000) {
      const keys = [...memoryCache.keys()];
      const toEvict = Math.floor(keys.length * 0.2);
      for (let i = 0; i < toEvict; i++) {
        memoryCache.delete(keys[i]);
      }
    }
  }
}

/**
 * Get cache stats (for debugging)
 */
export function getCacheStats() {
  if (redisClient) {
    return { type: 'redis', connected: true };
  }
  return { type: 'memory', size: memoryCache.size };
}
