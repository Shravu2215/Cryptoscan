'use strict';

const crypto = require('node:crypto');
const path = require('path');

// Resolve ethers safely across submodules
let ethers;
try {
  ethers = require('ethers');
} catch (err) {
  ethers = require('../blockchain-module/node_modules/ethers');
}

const { getSigningKey } = require('./kms');

/**
 * Exact algorithm identifier for the hybrid dual-signature scheme.
 * Combines classical ECDSA (secp256k1) with NIST FIPS 204 ML-DSA-65.
 */
const ALGORITHM_IDENTIFIER = 'ECDSA-secp256k1+ML-DSA-65';

/**
 * Domain separation context string to prevent cross-protocol signature replay.
 */
const DOMAIN_TAG = 'CryptoScan-Integrity-v1';
const DOMAIN_PREFIX = Buffer.from(`${DOMAIN_TAG}\n`, 'utf8');

// In-memory registry for ML-DSA keys: keyId -> { keyId, publicKey, privateKey }
const pqcKeyRegistry = new Map();
let activePqcKeyId = null;

/**
 * Prepares the raw message with domain separation prefix.
 *
 * @param {Buffer|Uint8Array|string} message - The input payload to sign.
 * @returns {Buffer} Domain-separated message buffer.
 * @throws {TypeError} If message is not a Buffer, Uint8Array, or string.
 */
function prepareMessage(message) {
  let msgBuf;
  if (Buffer.isBuffer(message)) {
    msgBuf = message;
  } else if (typeof message === 'string') {
    msgBuf = Buffer.from(message, 'utf8');
  } else if (message instanceof Uint8Array) {
    msgBuf = Buffer.from(message);
  } else {
    throw new TypeError('Message must be a Buffer, Uint8Array, or string');
  }

  return Buffer.concat([DOMAIN_PREFIX, msgBuf]);
}

/**
 * Computes a deterministic, non-secret key identifier for an ML-DSA public key.
 *
 * @param {crypto.KeyObject} publicKey - ML-DSA public key object.
 * @returns {string} Safe opaque key identifier.
 */
function computePqcKeyId(publicKey) {
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const hashPrefix = crypto.createHash('sha256').update(spkiDer).digest('hex').slice(0, 16);
  return `pqc-mldsa65-${hashPrefix}`;
}

/**
 * Generates and registers an independent ML-DSA-65 keypair (NIST FIPS 204).
 *
 * @param {object} [options={}] - Options.
 * @param {string} [options.keyId] - Optional custom key identifier.
 * @param {boolean} [options.makeActive=true] - Whether to set as active signing key.
 * @returns {{ keyId: string, publicKey: crypto.KeyObject }} Public key registration info.
 */
function generatePqcKeyPair(options = {}) {
  const keyPair = crypto.generateKeyPairSync('ml-dsa-65');
  const keyId = options.keyId || computePqcKeyId(keyPair.publicKey);

  const entry = {
    keyId,
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };

  pqcKeyRegistry.set(keyId, entry);

  if (options.makeActive !== false) {
    activePqcKeyId = keyId;
  }

  return {
    keyId,
    publicKey: keyPair.publicKey,
  };
}

/**
 * Resolves an ML-DSA public key from the registry by key identifier.
 *
 * @param {string} keyId - Key identifier.
 * @returns {crypto.KeyObject|null}
 */
function getPqcPublicKey(keyId) {
  const entry = pqcKeyRegistry.get(keyId);
  return entry ? entry.publicKey : null;
}

/**
 * Registers an existing ML-DSA keypair into the registry.
 *
 * @param {{ publicKey: crypto.KeyObject, privateKey: crypto.KeyObject }} keyPair - Keypair.
 * @param {string} [keyId] - Optional key identifier.
 * @returns {string} Registered keyId.
 */
function registerPqcKeyPair(keyPair, keyId) {
  if (!keyPair || !keyPair.publicKey || !keyPair.privateKey) {
    throw new TypeError('Invalid keyPair: must contain publicKey and privateKey KeyObjects');
  }

  const id = keyId || computePqcKeyId(keyPair.publicKey);
  pqcKeyRegistry.set(id, {
    keyId: id,
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  });
  activePqcKeyId = id;
  return id;
}

/**
 * Retrieves the currently active PQC keypair, auto-generating one if registry is empty.
 *
 * @returns {{ keyId: string, publicKey: crypto.KeyObject, privateKey: crypto.KeyObject }}
 */
function getActivePqcKey() {
  if (activePqcKeyId && pqcKeyRegistry.has(activePqcKeyId)) {
    return pqcKeyRegistry.get(activePqcKeyId);
  }

  const generated = generatePqcKeyPair({ makeActive: true });
  return pqcKeyRegistry.get(generated.keyId);
}

/**
 * Resets the PQC key registry. Useful for test isolation.
 */
function resetPqcRegistry() {
  pqcKeyRegistry.clear();
  activePqcKeyId = null;
}

/**
 * Signs a message using the hybrid signature scheme:
 * 1. Classical ECDSA over secp256k1 (via KMS-managed wallet).
 * 2. Post-Quantum ML-DSA-65 (NIST FIPS 204 via native node:crypto).
 *
 * Both signatures authenticate the exact same domain-separated byte sequence.
 *
 * @param {Buffer|Uint8Array|string} message - Message payload to sign.
 * @param {object} [options={}] - Signing options.
 * @param {string} [options.pqcKeyId] - Specific PQC key ID to sign with.
 * @returns {Promise<{ algorithm: string, classicalSig: string, pqcSig: string, pqcKeyId: string }>}
 */
async function signHybrid(message, options = {}) {
  const preparedMessage = prepareMessage(message);

  // 1. Classical signature via existing KMS abstraction
  const classicalSigningKey = getSigningKey();
  const wallet = new ethers.Wallet(classicalSigningKey.privateKey);
  const classicalSig = await wallet.signMessage(preparedMessage);

  // 2. Post-quantum signature via native ML-DSA-65
  let pqcKeyEntry;
  if (options.pqcKeyId) {
    pqcKeyEntry = pqcKeyRegistry.get(options.pqcKeyId);
    if (!pqcKeyEntry) {
      throw new Error(`PQC key ID not found in registry: ${options.pqcKeyId}`);
    }
  } else {
    pqcKeyEntry = getActivePqcKey();
  }

  const rawPqcSig = crypto.sign(null, preparedMessage, pqcKeyEntry.privateKey);
  const pqcSig = rawPqcSig.toString('base64');

  return {
    algorithm: ALGORITHM_IDENTIFIER,
    classicalSig,
    pqcSig,
    pqcKeyId: pqcKeyEntry.keyId,
  };
}

/**
 * Verifies a hybrid dual-signature against a message.
 *
 * Both classical (ECDSA/secp256k1) and post-quantum (ML-DSA-65) signatures must be valid.
 * If either signature is invalid, missing, or tampered, the overall verification returns false.
 *
 * @param {Buffer|Uint8Array|string} message - The original message.
 * @param {object} hybridSignature - The hybrid signature object.
 * @param {string} hybridSignature.algorithm - Must be 'ECDSA-secp256k1+ML-DSA-65'.
 * @param {string} hybridSignature.classicalSig - The classical ECDSA signature.
 * @param {string} hybridSignature.pqcSig - The base64 or hex ML-DSA-65 signature.
 * @param {string} hybridSignature.pqcKeyId - The PQC key identifier.
 * @param {object} [options={}] - Verification options.
 * @param {string} [options.signerAddress] - Expected Ethereum signer address for classical verification.
 * @param {crypto.KeyObject} [options.pqcPublicKey] - Direct ML-DSA public key (if not resolving from registry).
 * @returns {{ valid: boolean, classicalValid: boolean, pqcValid: boolean, reason?: string }}
 */
function verifyHybrid(message, hybridSignature, options = {}) {
  if (!hybridSignature || typeof hybridSignature !== 'object') {
    return { valid: false, classicalValid: false, pqcValid: false, reason: 'Malformed hybrid signature object' };
  }

  if (hybridSignature.algorithm !== ALGORITHM_IDENTIFIER) {
    return { valid: false, classicalValid: false, pqcValid: false, reason: `Unsupported algorithm: ${hybridSignature.algorithm}` };
  }

  let preparedMessage;
  try {
    preparedMessage = prepareMessage(message);
  } catch (err) {
    return { valid: false, classicalValid: false, pqcValid: false, reason: err.message };
  }

  let classicalValid = false;
  let pqcValid = false;

  // 1. Classical Verification (ECDSA secp256k1)
  if (hybridSignature.classicalSig && typeof hybridSignature.classicalSig === 'string') {
    try {
      const recoveredAddress = ethers.verifyMessage(preparedMessage, hybridSignature.classicalSig);

      let expectedAddress = options.signerAddress || options.expectedSignerAddress;
      if (!expectedAddress) {
        try {
          const classicalSigningKey = getSigningKey();
          if (classicalSigningKey && classicalSigningKey.privateKey) {
            const wallet = new ethers.Wallet(classicalSigningKey.privateKey);
            expectedAddress = wallet.address;
          }
        } catch {
          // KMS not configured in this environment
        }
      }

      if (expectedAddress) {
        classicalValid = (recoveredAddress.toLowerCase() === expectedAddress.toLowerCase());
      } else {
        classicalValid = ethers.isAddress(recoveredAddress) && recoveredAddress !== ethers.ZeroAddress;
      }
    } catch {
      classicalValid = false;
    }
  }

  // 2. Post-Quantum Verification (ML-DSA-65)
  if (hybridSignature.pqcSig) {
    try {
      let pqcPublicKey = options.pqcPublicKey;
      if (!pqcPublicKey && hybridSignature.pqcKeyId) {
        pqcPublicKey = getPqcPublicKey(hybridSignature.pqcKeyId);
      }

      if (pqcPublicKey) {
        let pqcSigBuf;
        if (typeof hybridSignature.pqcSig === 'string') {
          if (hybridSignature.pqcSig.startsWith('0x')) {
            pqcSigBuf = Buffer.from(hybridSignature.pqcSig.slice(2), 'hex');
          } else {
            pqcSigBuf = Buffer.from(hybridSignature.pqcSig, 'base64');
          }
        } else if (Buffer.isBuffer(hybridSignature.pqcSig)) {
          pqcSigBuf = hybridSignature.pqcSig;
        }

        // FIPS 204 ML-DSA-65 signatures are exactly 3,309 bytes
        if (pqcSigBuf && pqcSigBuf.length === 3309) {
          pqcValid = crypto.verify(null, preparedMessage, pqcPublicKey, pqcSigBuf);
        }
      }
    } catch {
      pqcValid = false;
    }
  }

  const valid = (classicalValid === true && pqcValid === true);

  return {
    valid,
    classicalValid,
    pqcValid,
  };
}

module.exports = {
  signHybrid,
  verifyHybrid,
  generatePqcKeyPair,
  getPqcPublicKey,
  registerPqcKeyPair,
  resetPqcRegistry,
  prepareMessage,
  DOMAIN_TAG,
  ALGORITHM_IDENTIFIER,
};
