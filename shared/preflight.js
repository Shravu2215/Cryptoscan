/**
 * Node.js version preflight check.
 *
 * Must be required as the VERY FIRST thing in server.js before any other
 * imports, so that a clear human-readable error is shown instead of a
 * cryptic ERR_INVALID_ARG_VALUE deep inside the ML-DSA signing call.
 *
 * ML-DSA-65 (NIST FIPS 204) requires Node.js >= 24.7.0 with embedded
 * OpenSSL 3.5. Older Node LTS releases (v20, v22) will crash when
 * crypto.generateKeyPairSync('ml-dsa-65') is called.
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
  console.error(
    `\n╔══════════════════════════════════════════════════════════╗\n` +
    `║           CryptoScan Node.js Version Error               ║\n` +
    `╠══════════════════════════════════════════════════════════╣\n` +
    `║  ML-DSA-65 (NIST FIPS 204) requires Node >= ${required}     ║\n` +
    `║  Found: v${found.padEnd(19)}                         ║\n` +
    `║                                                          ║\n` +
    `║  To fix:                                                 ║\n` +
    `║    nvm install 24.7.0 && nvm use 24.7.0                  ║\n` +
    `║    — or —                                                ║\n` +
    `║    See integrity-service/HYBRID_SIGNATURE_DESIGN.md      ║\n` +
    `╚══════════════════════════════════════════════════════════╝\n`
  );
  process.exit(1);
}
