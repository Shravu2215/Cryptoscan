'use strict';

// Fails fast at startup rather than letting the app run half-configured
// (e.g. signing tokens with a placeholder secret, or silently accepting
// requests it can't actually encrypt data for).
const WEAK_JWT_SECRETS = new Set([
  'change-this-to-a-long-random-string',
  'secret',
  'changeme',
]);

function validateEnv() {
  const isProd = process.env.NODE_ENV === 'production';
  const errors = [];

  if (!process.env.JWT_SECRET) {
    errors.push('JWT_SECRET is not set');
  } else if (process.env.JWT_SECRET.length < 32) {
    errors.push('JWT_SECRET is too short (need >= 32 chars of randomness)');
  } else if (WEAK_JWT_SECRETS.has(process.env.JWT_SECRET)) {
    errors.push('JWT_SECRET is still set to the example placeholder value');
  }

  if (!process.env.DATABASE_URL) {
    errors.push('DATABASE_URL is not set');
  }

  if (!process.env.DATA_ENCRYPTION_KEY) {
    errors.push('DATA_ENCRYPTION_KEY is not set (base64-encoded 32-byte AES-256 key)');
  } else {
    const decoded = Buffer.from(process.env.DATA_ENCRYPTION_KEY, 'base64');
    if (decoded.length !== 32) {
      errors.push('DATA_ENCRYPTION_KEY must decode to exactly 32 bytes');
    }
  }

  if (isProd) {
    if (!process.env.ALLOWED_ORIGINS) {
      errors.push('ALLOWED_ORIGINS must be set in production (comma-separated list of allowed frontend origins)');
    }
    if (!process.env.PRIVATE_KEY && process.env.KMS_PROVIDER !== 'aws-kms') {
      errors.push('PRIVATE_KEY is not set and KMS_PROVIDER is not aws-kms — anchoring will fail');
    }
  }

  if (errors.length > 0) {
    // eslint-disable-next-line no-console
    console.error('Refusing to start: invalid configuration:\n' + errors.map(e => `  - ${e}`).join('\n'));
    process.exit(1);
  }
}

module.exports = { validateEnv };
