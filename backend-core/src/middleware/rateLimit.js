'use strict';

const rateLimit = require('express-rate-limit');

// Uses Redis as a shared store when available so limits are enforced
// correctly across multiple backend-core replicas, not just per-process.
// Falls back to the in-memory store (single-instance only) when no
// REDIS_URL is configured, so local dev doesn't require Redis.
function buildStore() {
  if (!process.env.REDIS_URL) return undefined;

  try {
    const Redis = require('ioredis');
    const { RedisStore } = require('rate-limit-redis');
    const client = new Redis(process.env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
    client.on('error', (err) => console.error('Rate-limit Redis error:', err.message));
    client.connect().catch(err => console.error('Rate-limit Redis connect failed:', err.message));
    return new RedisStore({ sendCommand: (...args) => client.call(...args) });
  } catch (err) {
    console.warn('Redis rate-limit store unavailable, falling back to in-memory:', err.message);
    return undefined;
  }
}

const store = buildStore();

// Generous ceiling for normal API traffic (uploads, scans, polling).
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 600,
  standardHeaders: true,
  legacyHeaders: false,
  store,
});

// Tight limit on credential-guessing surfaces.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  store,
  message: { error: 'Too many auth attempts, please try again later' },
});

module.exports = { apiLimiter, authLimiter };
