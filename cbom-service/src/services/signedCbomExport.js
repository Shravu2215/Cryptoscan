/**
 * Signed CBOM Export Service (Person 3 — Phase 8)
 * cbom-service mirror of backend-core/src/services/signedCbomExport.js
 *
 * Integrates the existing integrity-service Merkle and hybrid-signature
 * implementations with the CBOM generation/export flow.
 *
 * NON-DESTRUCTIVE: does not alter stored scan/CBOM/DB data, blockchain
 * anchoring, key handling, or any upstream state.
 *
 * REUSES (not reimplements):
 *  - integrity-service/merkle.js  — buildMerkleTree, getProof, verifyProof, canonicalize, hash
 *  - integrity-service/hybrid-signature.js — signHybrid, verifyHybrid, generatePqcKeyPair, resetPqcRegistry
 */

'use strict';

const path = require('path');

// Resolve integrity-service from cbom-service (lives two levels up in the monorepo)
function resolveIntegrityService(mod) {
  const candidates = [
    path.resolve(__dirname, '../../../integrity-service', mod),
    path.resolve(__dirname, '../../../../integrity-service', mod),
    path.resolve(process.cwd(), 'integrity-service', mod),
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

function computeCbomContentHash(cbom) {
  const canonical = canonicalize(cbom);
  return hash(canonical);
}

// -----------------------------------------------------------------------
// Merkle commitment from CBOM components
// -----------------------------------------------------------------------

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

  const contentHash = computeCbomContentHash(cbom);
  return {
    merkleRoot: contentHash,
    leaves: [contentHash],
    tree: [[contentHash]],
    componentCount: 0,
    mode: 'full-cbom-hash',
  };
}

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

async function exportSignedCbom(cbom, options = {}) {
  if (!cbom || typeof cbom !== 'object') {
    throw new TypeError('cbom must be a non-null object');
  }

  const contentHash = computeCbomContentHash(cbom);
  const commitment = buildCbomMerkleCommitment(cbom);
  const componentProofs = buildComponentProofs(commitment);
  const signingPayload = commitment.merkleRoot;
  const hybridSig = await signHybrid(signingPayload, { pqcKeyId: options.pqcKeyId });
  const signedAt = new Date().toISOString();

  return {
    cbom,
    integrity: {
      contentHash,
      merkleRoot: commitment.merkleRoot,
      merkleMode: commitment.mode,
      componentCount: commitment.componentCount,
      algorithm: 'SHA-256',
    },
    componentProofs,
    signature: {
      algorithm: hybridSig.algorithm,
      classicalSig: hybridSig.classicalSig,
      pqcSig: hybridSig.pqcSig,
      pqcKeyId: hybridSig.pqcKeyId,
      signedAt,
      signedOver: 'merkleRoot',
    },
    version: cbom.metadata?.component?.version || null,
    cbomVersion: cbom.metadata?.provenance?.cbomVersion || null,
    signedAt,
  };
}

// -----------------------------------------------------------------------
// Signed CBOM verification
// -----------------------------------------------------------------------

function verifySignedCbom(signedPackage, options = {}) {
  const result = {
    valid: false,
    contentHashValid: false,
    merkleRootValid: false,
    signatureValid: false,
    classicalSigValid: false,
    pqcSigValid: false,
    componentProofValid: null,
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

  // Check 1: Content hash
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

  // Check 2: Merkle root
  try {
    let recomputedMerkleRoot;
    const components = cbom.components;

    if (Array.isArray(components) && components.length > 0) {
      const treeResult = buildMerkleTree(components);
      recomputedMerkleRoot = treeResult.root;
    } else {
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

  // Check 3: Hybrid signature
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

  // Check 4: Optional per-component Merkle proof
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

  result.valid = result.contentHashValid && result.merkleRootValid && result.signatureValid;
  return result;
}

module.exports = {
  exportSignedCbom,
  verifySignedCbom,
  computeCbomContentHash,
  buildCbomMerkleCommitment,
  buildComponentProofs,
  generatePqcKeyPair,
  resetPqcRegistry,
  getPqcPublicKey,
  ALGORITHM_IDENTIFIER,
};
