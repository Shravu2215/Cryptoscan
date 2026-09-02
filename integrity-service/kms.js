'use strict';

const util = require('util');

/**
 * Key representation returned by KMS wrapper.
 * Protects private key from accidental exposure in logs, console output, or JSON.
 */
class SigningKey {
  constructor(keyId, privateKey) {
    this.keyId = keyId;
    this.privateKey = privateKey;
  }

  /**
   * Prevents private key from appearing in JSON serialization.
   */
  toJSON() {
    return {
      keyId: this.keyId,
    };
  }

  /**
   * Clean string representation without secrets.
   */
  toString() {
    return `[SigningKey keyId=${this.keyId}]`;
  }

  /**
   * Custom Node.js util.inspect handler so console.log(key) redacts the secret.
   */
  [util.inspect.custom]() {
    return {
      keyId: this.keyId,
      privateKey: '[REDACTED]',
    };
  }
}

// In-memory key state for the local demo KMS
let activeKey = null;
let keyVersion = 1;
const keyHistory = new Map(); // keyId -> SigningKey

/**
 * Retrieves the current signing key through the KMS interface.
 * Reads process.env.PRIVATE_KEY internally if an active key has not been explicitly loaded or rotated.
 *
 * @returns {SigningKey} The active signing key instance containing { keyId, privateKey }.
 * @throws {Error} If no signing key is configured in the environment.
 */
function getSigningKey() {
  if (activeKey) {
    return activeKey;
  }

  const envKey = process.env.PRIVATE_KEY;
  if (!envKey || typeof envKey !== 'string' || envKey.trim() === '') {
    throw new Error('Signing key not configured — refusing to sign without a real signer');
  }

  const keyId = `local-demo-key-v${keyVersion}`;
  activeKey = new SigningKey(keyId, envKey.trim());
  keyHistory.set(keyId, activeKey);
  return activeKey;
}

/**
 * Rotates the signing key in a controlled, explicit manner.
 *
 * In this local demo KMS, key rotation requires an explicit new private key
 * (passed via options.newPrivateKey or process.env.ROTATED_PRIVATE_KEY) to avoid
 * silently invalidating the configured blockchain wallet.
 *
 * The previous active key is preserved in history so past signatures can be audited.
 *
 * @param {object|string} [options={}] - Options object or new private key string.
 * @param {string} [options.newPrivateKey] - The new private key to activate.
 * @param {string} [options.newKeyId] - Optional custom key identifier.
 * @returns {{ status: string, keyId: string, previousKeyId: string }} Non-secret rotation receipt.
 * @throws {Error} If no new private key is provided.
 */
function rotateKey(options = {}) {
  const newPrivateKey =
    typeof options === 'string'
      ? options
      : (options && options.newPrivateKey) || process.env.ROTATED_PRIVATE_KEY;

  if (!newPrivateKey || typeof newPrivateKey !== 'string' || newPrivateKey.trim() === '') {
    throw new Error(
      'Key rotation requires an explicit new private key (via options.newPrivateKey, argument string, or ROTATED_PRIVATE_KEY env var) to avoid invalidating the configured blockchain wallet.'
    );
  }

  // Ensure current active key is loaded and archived
  const currentKey = getSigningKey();
  keyHistory.set(currentKey.keyId, currentKey);

  keyVersion += 1;
  const customKeyId = typeof options === 'object' && options.newKeyId ? options.newKeyId : null;
  const nextKeyId = customKeyId || `local-demo-key-v${keyVersion}`;

  activeKey = new SigningKey(nextKeyId, newPrivateKey.trim());
  keyHistory.set(activeKey.keyId, activeKey);

  return {
    status: 'ROTATED',
    keyId: activeKey.keyId,
    previousKeyId: currentKey.keyId,
  };
}

/**
 * Returns non-secret metadata about the active signing key.
 *
 * @returns {{ keyId: string, algorithm: string, status: string, provider: string }}
 */
function getKeyInfo() {
  const key = getSigningKey();
  return {
    keyId: key.keyId,
    algorithm: 'ECDSA/secp256k1',
    status: 'ACTIVE',
    provider: 'LocalKMS-Demo',
  };
}

/**
 * Retrieves a historical key by keyId for verifying signatures created before rotation.
 *
 * @param {string} keyId - The key identifier.
 * @returns {SigningKey|null} The key if found, or null.
 */
function getKeyById(keyId) {
  return keyHistory.get(keyId) || null;
}

/**
 * Resets the KMS state back to reading the environment variable.
 * Primarily used for test isolation.
 */
function reset() {
  activeKey = null;
  keyVersion = 1;
  keyHistory.clear();
}

const kms = {
  getSigningKey,
  rotateKey,
  getKeyInfo,
  getKeyById,
  reset,
};

module.exports = {
  getSigningKey,
  rotateKey,
  getKeyInfo,
  getKeyById,
  reset,
  kms,
};
