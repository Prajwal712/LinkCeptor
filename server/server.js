/**
 * Smart Link Interceptor — Express Server
 * 
 * Entry point for the backend API.
 * Initializes cache, Gemini AI, and starts the Express server.
 */

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { initCache } from './services/cache.js';
import { initGemini } from './services/gemini.js';
import { apiLimiter } from './middleware/rateLimit.js';
import verifyRouter from './routes/verify.js';

const app = express();
const PORT = process.env.PORT || 3001;

// ─── Middleware ────────────────────────────────────────────
app.use(cors({
  origin: '*', // In production, restrict to your extension's origin
  methods: ['POST', 'GET'],
  allowedHeaders: ['Content-Type']
}));
app.use(express.json({ limit: '1mb' }));

// ─── Rate Limiting ────────────────────────────────────────
app.use('/api', apiLimiter);

// ─── Routes ───────────────────────────────────────────────
app.use('/api', verifyRouter);

// ─── Root ─────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    name: '🛡️ Smart Link Interceptor API',
    version: '1.0.0',
    endpoints: {
      verify: 'POST /api/verify',
      health: 'GET /api/health'
    }
  });
});

// ─── Startup ──────────────────────────────────────────────
async function start() {
  console.log('');
  console.log('🛡️  Smart Link Interceptor — Backend Server');
  console.log('─'.repeat(48));

  // Initialize services
  await initCache();
  initGemini();

  // Start server
  app.listen(PORT, () => {
    console.log('─'.repeat(48));
    console.log(`🚀 Server running at http://localhost:${PORT}`);
    console.log(`📡 Verify endpoint: POST http://localhost:${PORT}/api/verify`);
    console.log(`💚 Health check:    GET  http://localhost:${PORT}/api/health`);
    console.log('');
  });
}

start().catch((error) => {
  console.error('❌ Failed to start server:', error);
  process.exit(1);
});
