/**
 * Smart Link Interceptor — Express Server (v2.0)
 * 
 * Entry point for the backend API.
 * Initializes all services: cache, Gemini AI, VirusTotal, Safe Browsing.
 * Supports Node.js cluster mode for multi-core scaling.
 */

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { initCache } from './services/cache.js';
import { initGemini } from './services/gemini.js';
import { initVirusTotal } from './services/virusTotal.js';
import { initSafeBrowsing } from './services/safeBrowsing.js';
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
    version: '2.0.0',
    architecture: 'Concurrent Multi-Source Threat Intelligence',
    endpoints: {
      verify: 'POST /api/verify',
      health: 'GET /api/health'
    },
    scanners: {
      virusTotal: !!process.env.VIRUSTOTAL_API_KEY ? 'enabled' : 'disabled',
      safeBrowsing: !!process.env.GOOGLE_SAFE_BROWSING_API_KEY ? 'enabled' : 'disabled',
      gemini: 'enabled (final arbiter)',
      heuristics: 'enabled (entropy, typosquatting, TLD analysis)',
    },
    instance: process.env.INSTANCE_ID || `pid-${process.pid}`,
  });
});

// ─── Startup ──────────────────────────────────────────────
async function start() {
  console.log('');
  console.log('🛡️  Smart Link Interceptor — Backend Server v2.0');
  console.log('═'.repeat(56));

  // Initialize all services
  await initCache();
  initVirusTotal();
  initSafeBrowsing();
  initGemini();

  console.log('─'.repeat(56));
  console.log('📐 Architecture: Concurrent Multi-Source Scanning');
  console.log('   ├── VirusTotal API (70+ engines)');
  console.log('   ├── Google Safe Browsing (malware/phishing)');
  console.log('   ├── Local Heuristics (entropy, typosquatting)');
  console.log('   └── Gemini AI (final arbiter)');
  console.log('');
  console.log('   All scanners run simultaneously via Promise.allSettled()');
  console.log('   Results are aggregated and fed to Gemini for final verdict');
  console.log('─'.repeat(56));

  // Start server
  app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
    console.log(`📡 Verify endpoint: POST http://localhost:${PORT}/api/verify`);
    console.log(`💚 Health check:    GET  http://localhost:${PORT}/api/health`);
    console.log(`🔧 Instance: ${process.env.INSTANCE_ID || `pid-${process.pid}`}`);
    console.log('');
  });
}

start().catch((error) => {
  console.error('❌ Failed to start server:', error);
  process.exit(1);
});
