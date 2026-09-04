'use strict';

const rateLimit = require('express-rate-limit');

// Uses Redis as a shared store when available so limits are enforced
// correctly across multiple backend-core replicas, not just per-process.
// Falls back to the in-memory store (single-instance only) when no
// REDIS_URL is configured, so local dev doesn't require Redis.
//
// Each limiter needs its OWN RedisStore instance (with a unique key
// prefix) — express-rate-limit forbids sharing one store across limiters.
let redisClient;
function getRedisClient() {
  if (redisClient) return redisClient;
  const Redis = require('ioredis');
  redisClient = new Redis(process.env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
  redisClient.on('error', (err) => console.error('Rate-limit Redis error:', err.message));
  redisClient.connect().catch(err => console.error('Rate-limit Redis connect failed:', err.message));
  return redisClient;
}

function buildStore(prefix) {
  if (!process.env.REDIS_URL) return undefined;

  try {
    const { RedisStore } = require('rate-limit-redis');
    const client = getRedisClient();
    return new RedisStore({ prefix, sendCommand: (...args) => client.call(...args) });
  } catch (err) {
    console.warn('Redis rate-limit store unavailable, falling back to in-memory:', err.message);
    return undefined;
  }
}

// Generous ceiling for normal API traffic (uploads, scans, polling).
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 600,
  standardHeaders: true,
  legacyHeaders: false,
  store: buildStore('rl:api:'),
});

// Tight limit on credential-guessing surfaces.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  store: buildStore('rl:auth:'),
  message: { error: 'Too many auth attempts, please try again later' },
});

module.exports = { apiLimiter, authLimiter };
