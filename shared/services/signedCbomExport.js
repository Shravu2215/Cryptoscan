/**
 * Signed CBOM Export Service (Person 3 — Phase 8)
 *
 * Integrates the existing integrity-service Merkle and hybrid-signature
 * implementations with the CBOM generation/export flow.
 *
 * This module:
 *  - generates CBOM using the existing CBOM 2.0 generator
 *  - computes the CBOM content hash
 *  - builds a Merkle commitment from CBOM components
 *  - creates a hybrid ECDSA+ML-DSA-65 signature over the Merkle root
 *  - returns the signed CBOM package and all verification metadata
 *
 * NON-DESTRUCTIVE:
 *  - Does not alter stored scan/CBOM/DB data
 *  - Does not alter blockchain anchoring
 *  - Does not introduce new private-key handling
 *  - Reuses existing KMS and key-management conventions
 *
 * REUSES (not reimplements):
 *  - integrity-service/merkle.js  — buildMerkleTree, getProof, verifyProof, canonicalize, hash
 *  - integrity-service/hybrid-signature.js — signHybrid, verifyHybrid, generatePqcKeyPair, resetPqcRegistry
 */

'use strict';

const path = require('path');

// Resolve integrity-service relative to shared/services, backend-core, cbom-service, or cwd
function resolveIntegrityService(mod) {
  const candidates = [
    path.resolve(__dirname, '../../integrity-service', mod),      // from shared/services/
    path.resolve(__dirname, '../../../integrity-service', mod),   // from backend-core or cbom-service
    path.resolve(process.cwd(), 'integrity-service', mod),        // from project root
  ];
  for (const c of candidates) {
    try {
      return require(c);
    } catch (_) {}
  }
  throw new Error(`Cannot resolve integrity-service module: ${mod}`);
}

const {
  buildMerkleTree,
  getProof,
  verifyProof,
  canonicalize,
  hash,
} = resolveIntegrityService('merkle');

const {
  signHybrid,
  verifyHybrid,
  generatePqcKeyPair,
  getPqcPublicKey,
  resetPqcRegistry,
  ALGORITHM_IDENTIFIER,
} = resolveIntegrityService('hybrid-signature');

// -----------------------------------------------------------------------
// Content hash
// -----------------------------------------------------------------------

/**
 * Computes the canonical content hash of a CBOM object.
 * Uses merkle.js canonicalize + hash to ensure deterministic output.
 *
 * @param {object} cbom - CBOM object
 * @returns {string} 64-char lowercase hex SHA-256 content hash
 */
function computeCbomContentHash(cbom) {
  const canonical = canonicalize(cbom);
  return hash(canonical);
}

// -----------------------------------------------------------------------
// Merkle commitment from CBOM components
// -----------------------------------------------------------------------

/**
 * Builds a Merkle commitment from the components array of a CBOM.
 * Falls back to hashing the entire CBOM when components is empty.
 *
 * @param {object} cbom - CBOM object
 * @returns {{ merkleRoot: string, leaves: string[], tree: string[][], componentCount: number, mode: string }}
 */
function buildCbomMerkleCommitment(cbom) {
  const components = cbom.components;

  if (Array.isArray(components) && components.length > 0) {
    const treeResult = buildMerkleTree(components);
    return {
      merkleRoot: treeResult.root,
      leaves: treeResult.leaves,
      tree: treeResult.tree,
      componentCount: components.length,
      mode: 'component-merkle',
    };
  }

  // No components — hash the full CBOM as a single leaf
  const contentHash = computeCbomContentHash(cbom);
  return {
    merkleRoot: contentHash,
    leaves: [contentHash],
    tree: [[contentHash]],
    componentCount: 0,
    mode: 'full-cbom-hash',
  };
}

/**
 * Returns Merkle inclusion proofs for every component in the CBOM.
 *
 * @param {object} commitment - Result from buildCbomMerkleCommitment
 * @returns {Array<{ componentIndex: number, leaf: string, proof: Array }>}
 */
function buildComponentProofs(commitment) {
  if (commitment.componentCount === 0) {
    return [];
  }
  return commitment.leaves.map((leaf, idx) => ({
    componentIndex: idx,
    leaf,
    proof: getProof(commitment.tree, idx),
  }));
}

// -----------------------------------------------------------------------
// Signed CBOM export
// -----------------------------------------------------------------------

/**
 * Generates a signed CBOM export package.
 *
 * Signing payload: the Merkle root (hex) of the CBOM components.
 * Both classical ECDSA and ML-DSA-65 sign the same domain-separated
 * Merkle root string as their message.
 *
 * @param {object} cbom - CBOM object from cbomGenerator
 * @param {object} [options={}]
 * @param {string} [options.pqcKeyId] - Specific PQC key ID (auto-generated if absent)
 * @returns {Promise<object>} Signed CBOM export package
 */
async function exportSignedCbom(cbom, options = {}) {
  if (!cbom || typeof cbom !== 'object') {
    throw new TypeError('cbom must be a non-null object');
  }

  // 1. Content hash of the full CBOM
  const contentHash = computeCbomContentHash(cbom);

  // 2. Merkle commitment from components
  const commitment = buildCbomMerkleCommitment(cbom);

  // 3. Component inclusion proofs
  const componentProofs = buildComponentProofs(commitment);

  // 4. Hybrid signature over the Merkle root
  const signingPayload = commitment.merkleRoot;
  const hybridSig = await signHybrid(signingPayload, { pqcKeyId: options.pqcKeyId });

  // 5. Build signed package
  const signedAt = new Date().toISOString();

  return {
    // Full CBOM — all Phase 1-7 fields preserved
    cbom,
    // Integrity metadata
    integrity: {
      contentHash,                        // SHA-256 of canonical CBOM
      merkleRoot: commitment.merkleRoot,  // Merkle root from components
      merkleMode: commitment.mode,        // 'component-merkle' | 'full-cbom-hash'
      componentCount: commitment.componentCount,
      algorithm: 'SHA-256',
    },
    // Merkle component proofs (for independent per-component verification)
    componentProofs,
    // Hybrid dual-signature
    signature: {
      algorithm: hybridSig.algorithm,     // 'ECDSA-secp256k1+ML-DSA-65'
      classicalSig: hybridSig.classicalSig,
      pqcSig: hybridSig.pqcSig,
      pqcKeyId: hybridSig.pqcKeyId,
      signedAt,
      signedOver: 'merkleRoot',           // what was signed (for clarity)
    },
    // CBOM version/provenance summary (top-level for quick access)
    version: cbom.metadata?.component?.version || null,
    cbomVersion: cbom.metadata?.provenance?.cbomVersion || null,
    signedAt,
  };
}

// -----------------------------------------------------------------------
// Signed CBOM verification
// -----------------------------------------------------------------------

/**
 * Verifies a signed CBOM export package.
 *
 * Checks:
 *  1. Content hash integrity (canonical CBOM hash must match stored hash)
 *  2. Merkle root integrity (recompute from components and compare)
 *  3. Hybrid signature validity (classical ECDSA + ML-DSA-65 over Merkle root)
 *  4. At least one optional component Merkle proof if provided
 *
 * @param {object} signedPackage - Result from exportSignedCbom
 * @param {object} [options={}]
 * @param {string} [options.signerAddress] - Expected Ethereum signer address
 * @param {crypto.KeyObject} [options.pqcPublicKey] - ML-DSA public key for verification
 * @param {number} [options.verifyComponentIndex] - Index of a specific component to verify its proof
 * @returns {object} Detailed verification result
 */
function verifySignedCbom(signedPackage, options = {}) {
  const result = {
    valid: false,
    contentHashValid: false,
    merkleRootValid: false,
    signatureValid: false,
    classicalSigValid: false,
    pqcSigValid: false,
    componentProofValid: null, // null = not checked
    details: {},
    errors: [],
  };

  if (!signedPackage || typeof signedPackage !== 'object') {
    result.errors.push('Malformed signed package: not an object');
    return result;
  }

  const { cbom, integrity, signature, componentProofs } = signedPackage;

  if (!cbom || !integrity || !signature) {
    result.errors.push('Signed package missing required fields: cbom, integrity, or signature');
    return result;
  }

  // ---- Check 1: Content hash ----
  try {
    const recomputedContentHash = computeCbomContentHash(cbom);
    result.contentHashValid = (recomputedContentHash === integrity.contentHash);
    result.details.recomputedContentHash = recomputedContentHash;
    result.details.storedContentHash = integrity.contentHash;
    if (!result.contentHashValid) {
      result.errors.push('Content hash mismatch: CBOM data may have been tampered');
    }
  } catch (err) {
    result.errors.push(`Content hash computation failed: ${err.message}`);
  }

  // ---- Check 2: Merkle root ----
  try {
    let recomputedMerkleRoot;
    const components = cbom.components;

    if (Array.isArray(components) && components.length > 0) {
      const treeResult = buildMerkleTree(components);
      recomputedMerkleRoot = treeResult.root;
    } else {
      // Single-leaf mode
      recomputedMerkleRoot = computeCbomContentHash(cbom);
    }

    result.merkleRootValid = (recomputedMerkleRoot === integrity.merkleRoot);
    result.details.recomputedMerkleRoot = recomputedMerkleRoot;
    result.details.storedMerkleRoot = integrity.merkleRoot;
    if (!result.merkleRootValid) {
      result.errors.push('Merkle root mismatch: component data may have been tampered');
    }
  } catch (err) {
    result.errors.push(`Merkle root verification failed: ${err.message}`);
  }

  // ---- Check 3: Hybrid signature ----
  try {
    let pqcPublicKey = options.pqcPublicKey;
    if (!pqcPublicKey && signature.pqcKeyId) {
      pqcPublicKey = getPqcPublicKey(signature.pqcKeyId);
    }

    const verifyOpts = {};
    if (options.signerAddress) verifyOpts.signerAddress = options.signerAddress;
    if (pqcPublicKey) verifyOpts.pqcPublicKey = pqcPublicKey;

    const sigResult = verifyHybrid(integrity.merkleRoot, signature, verifyOpts);
    result.signatureValid = sigResult.valid;
    result.classicalSigValid = sigResult.classicalValid;
    result.pqcSigValid = sigResult.pqcValid;

    if (!result.signatureValid) {
      if (!sigResult.classicalValid) result.errors.push('Classical ECDSA signature is invalid or signer mismatch');
      if (!sigResult.pqcValid) result.errors.push('ML-DSA-65 PQC signature is invalid or key unavailable');
    }
  } catch (err) {
    result.errors.push(`Hybrid signature verification error: ${err.message}`);
  }

  // ---- Check 4: Optional per-component Merkle proof ----
  const verifyIdx = options.verifyComponentIndex;
  if (typeof verifyIdx === 'number' && Array.isArray(componentProofs) && componentProofs[verifyIdx]) {
    try {
      const proofEntry = componentProofs[verifyIdx];
      const proofValid = verifyProof(proofEntry.leaf, proofEntry.proof, integrity.merkleRoot);
      result.componentProofValid = proofValid;
      result.details.verifiedComponentIndex = verifyIdx;
      if (!proofValid) {
        result.errors.push(`Merkle proof for component index ${verifyIdx} is invalid`);
      }
    } catch (err) {
      result.errors.push(`Component proof verification failed: ${err.message}`);
      result.componentProofValid = false;
    }
  }

  // Overall: content hash + Merkle root + hybrid signature must all pass
  result.valid = result.contentHashValid && result.merkleRootValid && result.signatureValid;

  return result;
}

// -----------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------

module.exports = {
  exportSignedCbom,
  verifySignedCbom,
  computeCbomContentHash,
  buildCbomMerkleCommitment,
  buildComponentProofs,
  // Re-export helpers for tests
  generatePqcKeyPair,
  resetPqcRegistry,
  getPqcPublicKey,
  ALGORITHM_IDENTIFIER,
};
