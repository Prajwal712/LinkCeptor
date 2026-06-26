/**
 * Smart Link Interceptor — Rate Limiter Middleware
 * 
 * Prevents abuse of the verification endpoint.
 * Default: 60 requests per minute per IP.
 */

import rateLimit from 'express-rate-limit';

export const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,             // 60 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    isSafe: false,
    reason: 'Rate limit exceeded. Please wait before scanning more links.',
    cached: false
  },
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip;
  }
});
