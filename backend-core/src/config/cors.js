'use strict';

// Backend-core also serves the frontend statically (same-origin), so CORS
// only matters when the frontend is hosted separately (e.g. a CDN) or during
// local dev when the frontend is served from a different port.
const DEFAULT_DEV_ORIGINS = ['http://localhost:8080', 'http://127.0.0.1:8080'];

function buildAllowedOrigins() {
  const fromEnv = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

  if (process.env.NODE_ENV === 'production') {
    return fromEnv;
  }
  return [...new Set([...fromEnv, ...DEFAULT_DEV_ORIGINS])];
}

// Checks if origin matches an allowed pattern.
// Supports wildcard prefix patterns like "https://*.vercel.app"
function originMatches(origin, pattern) {
  if (pattern === origin) return true;
  // Wildcard pattern: "https://*.vercel.app" matches any subdomain
  if (pattern.includes('*')) {
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace('\\*', '.*');
    return new RegExp(`^${escaped}$`).test(origin);
  }
  return false;
}

function corsOptions() {
  const allowedOrigins = buildAllowedOrigins();
  return {
    origin(origin, callback) {
      // Same-origin / non-browser requests (curl, server-to-server) have no Origin header.
      if (!origin) return callback(null, true);
      if (allowedOrigins.some(pattern => originMatches(origin, pattern))) {
        return callback(null, true);
      }
      return callback(new Error(`Origin ${origin} is not allowed by CORS policy`));
    },
    credentials: true,
  };
}

module.exports = { corsOptions };
