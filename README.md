# 🛡️ Smart Link Interceptor v2.0

**Real-time phishing & malicious link detection with concurrent multi-source threat intelligence.**

Smart Link Interceptor is a Chrome extension that intercepts every link you click on Gmail and WhatsApp Web, runs it through **VirusTotal (70+ engines)**, **Google Safe Browsing**, and **local heuristics** — all **simultaneously** — then feeds everything to **Gemini AI** for the final verdict.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Chrome Extension                              │
│  ┌─────────────┐    ┌─────────────────┐    ┌───────────────────┐   │
│  │ Content.js   │───▶│ Background.js   │───▶│ Popup UI          │   │
│  │ (Intercepts  │    │ (Service Worker)│    │ (Stats/History/   │   │
│  │  clicks)     │◀───│                 │    │  Source Badges)   │   │
│  └─────────────┘    └────────┬────────┘    └───────────────────┘   │
│                              │                                       │
└──────────────────────────────┼───────────────────────────────────────┘
                               │ POST /api/verify
                               ▼
                  ┌─────────────────────────────┐
                  │  Load Balancer (Nginx)       │  ← Distributed System
                  │  Round-robin / Least-conn    │
                  └──────────┬──────────────────┘
                  ┌──────────┼──────────────────┐
                  │          │                  │
            Server 1    Server 2          Server N
                  │          │                  │
                  └──────────┼──────────────────┘
                             │
                  ┌──────────▼──────────────────┐
                  │     Backend Server           │
                  │                              │
                  │  ┌─── Promise.allSettled ──┐ │
                  │  │                         │ │
                  │  │  Future 1: VirusTotal   │ │  70+ security engines
                  │  │  Future 2: Safe Browse  │ │  Google's threat DB
                  │  │  Future 3: Heuristics   │ │  Entropy, typosquatting
                  │  │                         │ │
                  │  └─── All concurrent ──────┘ │
                  │            │                  │
                  │     ┌──────▼────────┐        │
                  │     │  Gemini AI    │        │  Final arbiter
                  │     │  (2.0-flash)  │        │  Synthesizes all results
                  │     └───────────────┘        │
                  │                              │
                  │     ┌───────────────┐        │
                  │     │ Redis Cache   │        │  Shared across instances
                  │     └───────────────┘        │
                  └──────────────────────────────┘
```

## Features

### Concurrent Multi-Source Scanning
- 🔵 **VirusTotal API** — 70+ antivirus engines scan URLs concurrently
- 🟢 **Google Safe Browsing** — Real-time malware/phishing database
- 🟡 **Local Heuristics** — Entropy analysis, typosquatting detection, suspicious TLD flagging
- 🟣 **Gemini AI (Final Arbiter)** — Synthesizes all results into one definitive verdict

### Core Features
- 🔍 **Real-time link scanning** on Gmail and WhatsApp Web
- ⚡ **All scanners run simultaneously** via `Promise.allSettled()` (like C++ `std::async`)
- 🧠 **AI-powered final decision** — Gemini weighs all evidence, not just one source
- 📊 **Multi-source badges** in popup showing VT detections, GSB status, scan timing
- 🚨 **Enhanced warning page** with per-source threat breakdown
- 📈 **Performance telemetry** — see concurrent vs. sequential timing per scan

### Infrastructure
- 🔀 **Distributed System** — Docker Compose with Nginx load balancer + multiple server replicas
- 📦 **Node.js Cluster Mode** — Fork workers across CPU cores on a single machine
- 🗄️ **Shared Redis Cache** — All server instances share the same cache
- ⚡ **Multi-layer caching** — whitelist → Redis → edge CDN
- 🔗 **URL unshortening** — resolves bit.ly, t.co, etc. before analysis
- 🛡️ **Rule-based fallback** — works even if Gemini API is down

## Quick Start

### 1. Set Up the Backend Server

```bash
cd server

# Copy the env template
cp .env.example .env

# Add your API keys to .env:
#   GEMINI_API_KEY         (required) — https://aistudio.google.com/apikey
#   VIRUSTOTAL_API_KEY     (optional) — https://www.virustotal.com/gui/my-apikey
#   GOOGLE_SAFE_BROWSING_API_KEY (optional) — https://console.cloud.google.com

# Install dependencies
npm install

# Start the server (single instance)
npm run dev

# Or start in cluster mode (multi-core)
npm run cluster
```

### 2. Or Deploy with Docker (Distributed System)

```bash
# Set API keys in root .env or export them
export GEMINI_API_KEY=your_key
export VIRUSTOTAL_API_KEY=your_key
export GOOGLE_SAFE_BROWSING_API_KEY=your_key

# Launch: 3 server replicas + Redis + Nginx load balancer
docker-compose up -d --build

# Scale to 5 instances
docker-compose up -d --scale server=5

# View logs
docker-compose logs -f server
```

### 3. Load the Chrome Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** → select the `extension/` folder
4. The 🛡️ icon appears in your toolbar

### 4. Test It

1. Open [Gmail](https://mail.google.com) or [WhatsApp Web](https://web.whatsapp.com)
2. Click any link
3. Watch the scanning overlay — now shows "VT + SafeBrowsing + Gemini AI"
4. Check the popup for multi-source badges (VT:0/70, GSB:✓, timing)
5. Blocked links show per-source threat breakdown on the warning page

## Concurrency Model

The system uses **concurrent futures** — the Node.js equivalent of C++ `std::async`:

```
// C++ equivalent:
auto vt     = std::async(std::launch::async, virusTotalScan, url);
auto google = std::async(std::launch::async, safeBrowsingScan, url);
auto heur   = std::async(std::launch::async, heuristicScan, url);

// Node.js implementation:
const [vtResult, gsbResult, heuristicResult] = await Promise.allSettled([
  scanWithVirusTotal(url),      // Future 1
  scanWithSafeBrowsing(url),    // Future 2
  analyzeUrl(url),              // Future 3
]);

// ALL results → Gemini AI (final arbiter)
const verdict = await classifyUrl(url, heuristicResult, { vtResult, gsbResult });
```

**Sequential (old):** VT: 3s → GSB: 1s → Heuristics: 0.1s = **4.1s total**
**Concurrent (new):** max(VT: 3s, GSB: 1s, Heuristics: 0.1s) = **3s total** 🚀

## Distributed System

```
                Load Balancer (Nginx)
                /        |         \
          Server 1   Server 2   Server 3
                \        |         /
                 Redis Cache (shared)
```

- **Every server processes URLs independently**
- **Redis** ensures cache consistency across all instances
- **Nginx** distributes requests using least-connections algorithm
- **Auto-failover**: if a server dies, requests go to the next one
- **Scale**: `docker-compose up --scale server=N`

## Project Structure

```
Smart link interceptor/
├── extension/                    # Chrome Extension (Manifest V3)
│   ├── manifest.json             # Extension configuration (v2.0.0)
│   ├── content.js                # Click interceptor + multi-source overlay
│   ├── content.css               # Scanning overlay with scanner labels
│   ├── background.js             # Service worker (passes enriched data)
│   ├── popup.html/css/js         # Dashboard with source badges
│   ├── warning.html/css/js       # Threat warning with source breakdown
│   ├── whitelist.js              # Zero-latency safe domain list
│   └── icons/                    # Extension icons
├── server/                       # Backend API (Node.js)
│   ├── server.js                 # Express entry point (v2.0)
│   ├── cluster.js                # Multi-core cluster mode
│   ├── Dockerfile                # Container image
│   ├── routes/verify.js          # POST /api/verify (concurrent pipeline)
│   ├── services/
│   │   ├── scanner.js            # ★ Concurrent orchestrator (Promise.allSettled)
│   │   ├── virusTotal.js         # ★ VirusTotal v3 API
│   │   ├── safeBrowsing.js       # ★ Google Safe Browsing v4
│   │   ├── gemini.js             # Gemini AI — final arbiter (v2.0 prompt)
│   │   ├── urlAnalyzer.js        # URL metadata extraction
│   │   └── cache.js              # Redis / in-memory cache
│   └── middleware/rateLimit.js   # Rate limiting (60 req/min)
├── edge/                         # Cloudflare Worker (optional CDN)
│   ├── wrangler.toml
│   └── src/index.js
├── docker-compose.yml            # ★ Distributed system (LB + replicas + Redis)
├── nginx.conf                    # ★ Load balancer configuration
└── README.md
```

## How Detection Works

The system uses a **5-layer defense**:

| Layer | Speed | How It Works |
|-------|-------|-------------|
| **1. Local Whitelist** | 0ms | 70+ hardcoded safe domains bypass the server entirely |
| **2. Cache (Redis/Memory)** | < 5ms | Previously analyzed URLs return instantly (24h TTL) |
| **3. VirusTotal** | ~2-3s | 70+ security vendors scan the URL concurrently |
| **4. Google Safe Browsing** | ~200ms | Google's real-time malware/phishing database |
| **5. Gemini AI (Final Arbiter)** | ~500ms | Synthesizes ALL evidence into a definitive verdict |

Layers 3, 4, and the heuristic analysis all run **simultaneously** (concurrent futures).

## API Reference

### `POST /api/verify`

```json
// Request
{ "url": "https://suspicious-site.xyz/login" }

// Response (enriched)
{
  "isSafe": false,
  "reason": "VirusTotal: 5/70 engines flagged + Google Safe Browsing: SOCIAL_ENGINEERING",
  "confidence": "high",
  "cached": false,
  "sources": {
    "virusTotal": {
      "available": true,
      "malicious": 5,
      "suspicious": 1,
      "totalEngines": 70,
      "flaggedBy": ["Kaspersky", "BitDefender", "ESET"]
    },
    "safeBrowsing": {
      "available": true,
      "isThreat": true,
      "threatTypes": ["SOCIAL_ENGINEERING"]
    },
    "heuristics": {
      "suspiciousPatterns": ["Suspicious TLD: .xyz", "Credential-harvesting path"],
      "entropy": 4.2,
      "isShortUrl": false,
      "hasIPAddress": false
    }
  },
  "timing": {
    "concurrentMs": 2800,
    "geminiMs": 450,
    "totalMs": 3250
  }
}
```

### `GET /api/health`

```json
{
  "status": "ok",
  "service": "Smart Link Interceptor API v2.0",
  "version": "2.0.0",
  "features": {
    "virusTotal": true,
    "safeBrowsing": true,
    "gemini": true,
    "redis": true
  },
  "instance": "worker-1"
}
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | — | **Required.** Google AI Studio API key |
| `VIRUSTOTAL_API_KEY` | — | Optional. VirusTotal API key (free: 4 req/min) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | — | Optional. Google Cloud API key |
| `PORT` | `3001` | Server port |
| `REDIS_URL` | — | Optional Redis connection URL |
| `CACHE_TTL` | `86400` | Cache expiration in seconds (24h) |
| `CLUSTER_WORKERS` | `0` (auto) | Number of cluster workers (0 = CPU cores) |

## License

MIT
