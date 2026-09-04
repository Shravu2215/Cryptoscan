'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
const { canonicalize, hashPair, buildBatchMerkleTree } = require('../../integrity-service/merkle');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
require('dotenv').config();

const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;
function isValidSha256Hex(str) {
  return typeof str === 'string' && SHA256_HEX_REGEX.test(str);
}

/**
 * Minimal read-only ABI to interact with CryptoAnchor without full project dependencies.
 */
const INDEPENDENT_VERIFIER_ABI = [
  'function getAnchor(bytes32 scanId) external view returns (bytes32 merkleRoot, address anchoredBy, uint256 timestamp, string orgId, string scannerVersion, bool exists)',
  'function isAnchored(bytes32 scanId) external view returns (bool)',
];

/**
 * Directly queries the smart contract via raw JSON-RPC to fetch the anchor record.
 * Does not depend on any internal helper, wallet, or private key.
 *
 * @param {string} contractAddress - 0x EVM contract address.
 * @param {string} rpcUrl - EVM RPC endpoint.
 * @param {string} batchId - Batch identifier (e.g. "batch:<hash>").
 * @returns {Promise<{
 *   exists: boolean,
 *   merkleRoot: string,
 *   merkleRootClean: string,
 *   anchoredBy: string,
 *   timestamp: number,
 *   orgId: string,
 *   scannerVersion: string
 * }>}
 */
async function fetchOnChainAnchor(contractAddress, rpcUrl, batchId) {
  if (!ethers.isAddress(contractAddress)) {
    throw new TypeError(`Invalid contract address: ${contractAddress}`);
  }
  if (!rpcUrl || typeof rpcUrl !== 'string') {
    throw new TypeError('RPC URL must be a valid string');
  }
  if (!batchId || typeof batchId !== 'string') {
    throw new TypeError('batchId must be a valid string');
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const contract = new ethers.Contract(contractAddress, INDEPENDENT_VERIFIER_ABI, provider);

  const batchIdBytes32 =
    batchId.startsWith('0x') && batchId.length === 66
      ? batchId
      : ethers.keccak256(ethers.toUtf8Bytes(batchId));

  const [onChainRoot, anchoredBy, timestamp, orgId, scannerVersion, exists] =
    await contract.getAnchor(batchIdBytes32);

  return {
    exists: Boolean(exists),
    merkleRoot: onChainRoot,
    merkleRootClean: (onChainRoot || '').replace(/^0x/i, '').toLowerCase(),
    anchoredBy,
    timestamp: Number(timestamp),
    orgId,
    scannerVersion,
  };
}

/**
 * Independently recomputes a scan's leaf hash from scratch without internal library state.
 *
 * @param {object} scan - Scan record { scanId, merkleRoot, [orgId], [scannerVersion] }.
 * @returns {string} 64-character lowercase hexadecimal SHA-256 leaf.
 */
function computeIndependentLeaf(scan) {
  if (!scan || typeof scan !== 'object') {
    throw new TypeError('Scan record must be a non-null object');
  }
  if (!scan.scanId || typeof scan.scanId !== 'string') {
    throw new TypeError('Scan record must have a valid string scanId');
  }
  const cleanRoot = String(scan.merkleRoot || '').replace(/^0x/i, '').toLowerCase();
  if (!isValidSha256Hex(cleanRoot)) {
    throw new TypeError(`Scan '${scan.scanId}' must have a valid 64-hex merkleRoot`);
  }

  const normalized = {
    scanId: String(scan.scanId),
    merkleRoot: cleanRoot,
    ...(scan.orgId ? { orgId: String(scan.orgId) } : {}),
    ...(scan.scannerVersion ? { scannerVersion: String(scan.scannerVersion) } : {}),
  };

  const canonicalJson = canonicalize(normalized);
  return crypto.createHash('sha256').update(canonicalJson, 'utf8').digest('hex').toLowerCase();
}

/**
 * Independently verifies an individual scan's Merkle proof against a known batch root.
 * Evaluates the proof from leaf to root using sorted-pair binary hashing.
 *
 * @param {object} scan - Scan record.
 * @param {Array<{ sibling: string, position: string }>} proof - Merkle proof path.
 * @param {string} targetBatchRoot - Expected batch root (64 hex characters, with or without 0x).
 * @returns {{
 *   valid: boolean,
 *   computedLeaf: string,
 *   derivedRoot: string,
 *   targetRoot: string,
 *   proofLength: number
 * }}
 */
function verifyIndependentProof(scan, proof, targetBatchRoot) {
  const cleanTargetRoot = String(targetBatchRoot || '').replace(/^0x/i, '').toLowerCase();
  if (!isValidSha256Hex(cleanTargetRoot)) {
    return {
      valid: false,
      reason: 'Invalid targetBatchRoot: expected 64-hex string',
      derivedRoot: '',
      targetRoot: cleanTargetRoot,
      proofLength: 0,
    };
  }

  if (!Array.isArray(proof)) {
    throw new TypeError('Proof must be an array');
  }

  const leaf = computeIndependentLeaf(scan);
  let currentHash = leaf;

  for (let i = 0; i < proof.length; i++) {
    const step = proof[i];
    if (!step || !step.sibling || !isValidSha256Hex(step.sibling.toLowerCase())) {
      return {
        valid: false,
        reason: `Invalid proof element at index ${i}`,
        computedLeaf: leaf,
        derivedRoot: currentHash,
        targetRoot: cleanTargetRoot,
        proofLength: proof.length,
      };
    }

    currentHash = hashPair(currentHash, step.sibling.toLowerCase());
  }

  const isValid = currentHash === cleanTargetRoot;
  return {
    valid: isValid,
    computedLeaf: leaf,
    derivedRoot: currentHash,
    targetRoot: cleanTargetRoot,
    proofLength: proof.length,
  };
}

/**
 * Runs a complete, independent, zero-trust audit of an on-chain batch anchor.
 *
 * Verification Steps:
 *   1. Fetches on-chain commitment from blockchain contract.
 *   2. Recomputes batch Merkle root from the raw scan records.
 *   3. Compares recomputed batch root with the on-chain commitment.
 *   4. For every scan in the batch, independently traverses its Merkle proof.
 *   5. Verifies every scan belongs mathematically to the on-chain batch root.
 *
 * @param {object} auditInput
 * @param {string} auditInput.contractAddress - Target EVM contract address.
 * @param {string} auditInput.rpcUrl - Target network RPC endpoint.
 * @param {string} auditInput.batchId - Batch identifier.
 * @param {Array<object>} auditInput.scans - Array of scan records in the batch.
 * @param {Array<object>} [auditInput.proofs] - Optional array of { scanId, proof } objects.
 * @param {string} [auditInput.expectedBatchRoot] - Optional expected root to cross-check.
 * @returns {Promise<{
 *   overallPass: boolean,
 *   onChainExists: boolean,
 *   onChainRoot: string,
 *   recomputedBatchRoot: string,
 *   batchRootMatchesOnChain: boolean,
 *   expectedRootMatches: boolean | null,
 *   scansAuditedCount: number,
 *   scansPassedCount: number,
 *   scanVerifications: Array<{
 *     scanId: string,
 *     valid: boolean,
 *     leaf: string,
 *     proofLength: number
 *   }>,
 *   blockTimestamp: number,
 *   anchoredBy: string
 * }>}
 */
async function performIndependentAudit(auditInput) {
  const { contractAddress, rpcUrl, batchId, scans, proofs, expectedBatchRoot } = auditInput;

  // 1. Raw on-chain fetch
  const onChainData = await fetchOnChainAnchor(contractAddress, rpcUrl, batchId);
  if (!onChainData.exists) {
    return {
      overallPass: false,
      reason: `Batch '${batchId}' does not exist on-chain at ${contractAddress}`,
      onChainExists: false,
    };
  }

  // 2. Independent batch root recomputation
  const recomputedTree = buildBatchMerkleTree(scans);
  const recomputedRoot = recomputedTree.batchRoot;
  const batchRootMatchesOnChain = recomputedRoot === onChainData.merkleRootClean;

  // 3. Expected root check (if supplied)
  let expectedRootMatches = null;
  if (expectedBatchRoot) {
    const cleanExpected = expectedBatchRoot.replace(/^0x/i, '').toLowerCase();
    expectedRootMatches = cleanExpected === onChainData.merkleRootClean;
  }

  // 4. Verify proofs for every scan
  const scanVerifications = [];
  let allProofsValid = true;

  for (const scan of scans) {
    // Find proof from supplied proofs or from the recomputed tree
    let scanProof;
    if (Array.isArray(proofs)) {
      const match = proofs.find((p) => p.scanId === scan.scanId);
      scanProof = match ? match.proof : null;
    }
    if (!scanProof && scan.proof) {
      scanProof = scan.proof;
    }
    if (!scanProof) {
      // Recompute proof from reconstructed tree
      const scanIndex = recomputedTree.scans.findIndex((s) => s.scanId === scan.scanId);
      if (scanIndex !== -1) {
        const { getProof } = require('../../integrity-service/merkle');
        scanProof = getProof(recomputedTree.tree, scanIndex);
      }
    }

    if (!scanProof) {
      scanVerifications.push({
        scanId: scan.scanId,
        valid: false,
        reason: 'Proof not available for scan',
      });
      allProofsValid = false;
      continue;
    }

    // Zero-trust verification against on-chain root
    const proofResult = verifyIndependentProof(scan, scanProof, onChainData.merkleRootClean);
    scanVerifications.push({
      scanId: scan.scanId,
      valid: proofResult.valid,
      leaf: proofResult.computedLeaf,
      proofLength: proofResult.proofLength,
    });

    if (!proofResult.valid) {
      allProofsValid = false;
    }
  }

  const overallPass =
    onChainData.exists &&
    batchRootMatchesOnChain &&
    (expectedRootMatches === null || expectedRootMatches === true) &&
    allProofsValid &&
    scanVerifications.length === scans.length;

  return {
    overallPass,
    onChainExists: onChainData.exists,
    onChainRoot: onChainData.merkleRootClean,
    onChainRootHex: onChainData.merkleRoot,
    recomputedBatchRoot: recomputedRoot,
    batchRootMatchesOnChain,
    expectedRootMatches,
    scansAuditedCount: scans.length,
    scansPassedCount: scanVerifications.filter((s) => s.valid).length,
    scanVerifications,
    blockTimestamp: onChainData.timestamp,
    anchoredBy: onChainData.anchoredBy,
    orgId: onChainData.orgId,
    scannerVersion: onChainData.scannerVersion,
  };
}

module.exports = {
  fetchOnChainAnchor,
  computeIndependentLeaf,
  verifyIndependentProof,
  performIndependentAudit,
  INDEPENDENT_VERIFIER_ABI,
};
