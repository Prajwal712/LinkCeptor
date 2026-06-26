# 🛡️ Smart Link Interceptor

**Real-time phishing & malicious link detection for Gmail and WhatsApp Web, powered by Gemini AI.**

Smart Link Interceptor is a Chrome extension that intercepts every link you click on Gmail and WhatsApp Web, analyzes it for phishing, malware, and scam indicators, and warns you before you navigate to a dangerous site.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Chrome Extension                            │
│  ┌─────────────┐    ┌─────────────────┐    ┌───────────────┐   │
│  │ Content.js   │───▶│ Background.js   │───▶│ Popup UI      │   │
│  │ (Intercepts  │    │ (Service Worker)│    │ (Stats/History)│   │
│  │  clicks)     │◀───│                 │    │               │   │
│  └─────────────┘    └────────┬────────┘    └───────────────┘   │
│                              │                                   │
└──────────────────────────────┼───────────────────────────────────┘
                               │ POST /api/verify
                               ▼
                   ┌──────────────────────┐
                   │  Edge Cache Layer    │  (Cloudflare Worker + KV)
                   │  < 50ms response     │  Optional — for production
                   └──────────┬───────────┘
                              │ Cache Miss
                              ▼
                   ┌──────────────────────┐
                   │  Backend Server      │  (Node.js + Express)
                   │  ┌────────────────┐  │
                   │  │ URL Analyzer   │  │  Entropy, typosquatting,
                   │  │                │  │  SSL check, unshortening
                   │  └───────┬────────┘  │
                   │          │           │
                   │  ┌───────▼────────┐  │
                   │  │  Gemini API    │  │  AI-powered classification
                   │  │  (2.0-flash)   │  │
                   │  └────────────────┘  │
                   │                      │
                   │  ┌────────────────┐  │
                   │  │  Redis / Mem   │  │  24-hour verdict cache
                   │  │  Cache         │  │
                   │  └────────────────┘  │
                   └──────────────────────┘
```

## Features

- 🔍 **Real-time link scanning** on Gmail and WhatsApp Web
- 🧠 **AI-powered analysis** via Google Gemini 2.0 Flash
- ⚡ **Multi-layer caching** — whitelist → Redis/memory → edge CDN
- 🔗 **URL unshortening** — resolves bit.ly, t.co, etc. before analysis
- 📊 **Dashboard popup** with scan stats and history
- 🚨 **Full-page warning** for dangerous links with proceed-anyway option
- 🛡️ **Heuristic fallback** — works even if Gemini API is down
- 📈 **Entropy analysis**, typosquatting detection, suspicious TLD flagging

## Quick Start

### 1. Set Up the Backend Server

```bash
cd server

# Copy the env template and add your Gemini API key
cp .env.example .env
# Edit .env and set GEMINI_API_KEY

# Install dependencies
npm install

# Start the server
npm run dev
```

The server will start at `http://localhost:3001`.

> **Get a Gemini API key**: https://aistudio.google.com/apikey

### 2. Load the Chrome Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder from this project
5. The 🛡️ icon should appear in your Chrome toolbar

### 3. Test It

1. Open [Gmail](https://mail.google.com) or [WhatsApp Web](https://web.whatsapp.com)
2. Click on any link
3. Watch the scanning overlay appear — the link will either proceed (safe) or show a warning page (unsafe)
4. Click the extension icon to view your scan history and stats

## Project Structure

```
Smart link interceptor/
├── extension/                    # Chrome Extension (Manifest V3)
│   ├── manifest.json             # Extension configuration
│   ├── content.js                # Click interceptor (injected into pages)
│   ├── content.css               # Scanning overlay styles
│   ├── background.js             # Service worker (API communication)
│   ├── popup.html/css/js         # Extension popup dashboard
│   ├── warning.html/css/js       # Full-page threat warning
│   ├── whitelist.js              # Zero-latency safe domain list
│   └── icons/                    # Extension icons
├── server/                       # Backend API (Node.js)
│   ├── server.js                 # Express entry point
│   ├── routes/verify.js          # POST /api/verify endpoint
│   ├── services/
│   │   ├── gemini.js             # Gemini API integration
│   │   ├── urlAnalyzer.js        # URL metadata extraction
│   │   └── cache.js              # Redis / in-memory cache
│   └── middleware/rateLimit.js   # Rate limiting (60 req/min)
├── edge/                         # Cloudflare Worker (optional CDN)
│   ├── wrangler.toml
│   └── src/index.js
└── README.md
```

## How Detection Works

The system uses a **3-layer defense**:

| Layer | Speed | How It Works |
|-------|-------|-------------|
| **1. Local Whitelist** | 0ms | 70+ hardcoded safe domains (google.com, github.com, etc.) bypass the server entirely |
| **2. Cache (Redis/Memory)** | < 5ms | Previously analyzed URLs return instantly from cache (24h TTL) |
| **3. Gemini AI Analysis** | ~500ms | URL metadata is extracted (entropy, TLD, typosquatting patterns) and fed to Gemini for classification |

### URL Analysis Heuristics (before LLM)

- **Typosquatting detection**: `g00gle.com`, `faceb00k.com`, `paypai.com`
- **Suspicious TLDs**: `.xyz`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`
- **IP-based URLs**: `http://192.168.1.1/login`
- **Excessive subdomains**: `secure.login.google.com.evil.com`
- **Credential keywords**: `/login`, `/verify`, `/account` on unknown domains
- **URL entropy**: High randomness = likely auto-generated phishing URL
- **URL encoding**: Heavy `%XX` encoding = possible obfuscation
- **Shortlink resolution**: Follows redirect chains for `bit.ly`, `t.co`, etc.

## Production Deployment

### Backend → Render / Railway / VPS

```bash
# On Render, set these environment variables:
GEMINI_API_KEY=your_key
PORT=3001
REDIS_URL=redis://your-redis-instance:6379   # Optional
```

### Edge Cache → Cloudflare Workers

```bash
cd edge
npx wrangler login
npx wrangler kv:namespace create "LINK_CACHE"
# Update wrangler.toml with the KV namespace ID and your backend URL
npx wrangler deploy
```

Then update `API_ENDPOINT` in `extension/background.js` to point to your Cloudflare Worker URL.

## API Reference

### `POST /api/verify`

```json
// Request
{ "url": "https://suspicious-site.xyz/login" }

// Response
{
  "isSafe": false,
  "reason": "Suspicious TLD (.xyz) combined with credential-harvesting path (/login)",
  "confidence": "high",
  "cached": false
}
```

### `GET /api/health`

```json
{ "status": "ok", "service": "Smart Link Interceptor API", "timestamp": "..." }
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | — | **Required.** Your Google AI Studio API key |
| `PORT` | `3001` | Server port |
| `REDIS_URL` | — | Optional Redis connection URL |
| `CACHE_TTL` | `86400` | Cache expiration in seconds (default: 24h) |

## License

MIT
