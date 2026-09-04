/**
 * Node.js version preflight check.
 *
 * ML-DSA-65 (NIST FIPS 204) native keygen requires Node.js >= 24.7.0.
 * Older Node LTS releases (v20, v22) fall back to KMS / pure JS abstractions.
 */

'use strict';

const MIN_MAJOR = 24;
const MIN_MINOR = 7;
const MIN_PATCH = 0;

const raw = process.versions.node; // e.g. "24.13.0"
const [major, minor, patch] = raw.split('.').map(Number);

function satisfies(maj, min, pat) {
  if (maj > MIN_MAJOR) return true;
  if (maj < MIN_MAJOR) return false;
  if (min > MIN_MINOR) return true;
  if (min < MIN_MINOR) return false;
  return pat >= MIN_PATCH;
}

if (!satisfies(major, minor, patch)) {
  const required = `${MIN_MAJOR}.${MIN_MINOR}.${MIN_PATCH}`;
  const found    = raw;
  console.warn(
    `[Preflight Warning] Native ML-DSA-65 requires Node >= ${required}. Found: v${found}. Falling back to KMS / alternate provider.`
  );
  if (process.env.STRICT_NODE_VERSION === 'true') {
    process.exit(1);
  }
}
