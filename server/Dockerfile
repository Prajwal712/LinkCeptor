# ═══════════════════════════════════════════════════════════
#  Smart Link Interceptor — Server Dockerfile
# ═══════════════════════════════════════════════════════════

FROM node:22-alpine

WORKDIR /app

# Copy package files first for Docker layer caching
COPY package.json package-lock.json* ./

# Install all dependencies (including ioredis since we need it in Docker)
RUN npm ci --include=optional

# Copy application source
COPY . .

# Expose server port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3001/api/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

# Start the server
CMD ["node", "server.js"]
