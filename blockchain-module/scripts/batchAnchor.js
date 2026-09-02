'use strict';

const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
const {
  buildBatchMerkleTree,
  getBatchProof,
  verifyBatchProof,
  computeScanLeaf,
  buildMerkleTree,
} = require('../../integrity-service/merkle');
const { getSigningKey } = require('../../integrity-service/kms');
const { uploadCBOMToIPFS, verifyIPFSContent } = require('./ipfs');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
require('dotenv').config();

/**
 * Deterministic convention:
 * `CryptoAnchor.sol` accepts a `bytes32 scanId`.
 * For batch anchoring, the batch anchor identifier is derived deterministically as:
 *   keccak256("batch:" + batchRoot)
 * This prevents accidental collisions between batch IDs and individual scan IDs while
 * preserving write-once historical immutability without changing the smart contract.
 */
function deriveDeterministicBatchId(batchRoot) {
  const cleanRoot = String(batchRoot).replace(/^0x/i, '').toLowerCase();
  const label = `batch:${cleanRoot}`;
  return {
    batchId: label,
    batchIdBytes32: ethers.keccak256(ethers.toUtf8Bytes(label)),
  };
}

/**
 * Prepares a complete, deterministic batch from an array of scan records.
 *
 * Each scan record in `scans` must have:
 *   - scanId: string
 *   - merkleRoot: string (or `cbom` from which merkleRoot will be computed)
 *   - optional: cbom, ipfsCid, orgId, scannerVersion
 *
 * Flow:
 *   1. If `cbom` is provided without `merkleRoot`, computes the CBOM Merkle root.
 *   2. If `cbom` is provided and IPFS upload is enabled, pins CBOM off-chain to IPFS.
 *   3. Computes the deterministic batch Merkle tree via `buildBatchMerkleTree()`.
 *   4. Generates and attaches individual Merkle audit proofs for each scan.
 *   5. Derives the deterministic `batchId` and `batchIdBytes32`.
 *
 * @param {Array<object>} scans - Array of scan records.
 * @param {object} [options]
 * @param {string} [options.orgId] - Default orgId.
 * @param {string} [options.scannerVersion] - Default scannerVersion.
 * @param {boolean} [options.uploadIpfs=true] - Upload CBOMs to IPFS if cbom provided.
 * @param {boolean} [options.mockIpfs=false] - Force mock boundary for IPFS upload.
 * @returns {Promise<object>} Complete batch manifest.
 */
async function prepareScanBatch(scans, options = {}) {
  if (!Array.isArray(scans) || scans.length === 0) {
    throw new TypeError('Scans must be a non-empty array of scan records');
  }

  const processedScans = [];

  for (const scan of scans) {
    if (!scan || typeof scan !== 'object') {
      throw new TypeError('Each scan in batch must be a non-null object');
    }
    if (!scan.scanId || typeof scan.scanId !== 'string') {
      throw new TypeError('Each scan must have a valid string scanId');
    }

    let merkleRoot = scan.merkleRoot;
    let ipfsCid = scan.ipfsCid || null;
    let ipfsUri = scan.ipfsUri || (ipfsCid ? `ipfs://${ipfsCid}` : null);

    // If CBOM provided, calculate component Merkle root if not already provided
    if (scan.cbom && !merkleRoot) {
      const components = Array.isArray(scan.cbom.components)
        ? scan.cbom.components
        : Array.isArray(scan.cbom)
        ? scan.cbom
        : [scan.cbom];
      merkleRoot = buildMerkleTree(components).root;
    }

    if (!merkleRoot) {
      throw new Error(`Scan '${scan.scanId}' must provide either a merkleRoot or a cbom object`);
    }

    // Clean 64-char hex format
    merkleRoot = merkleRoot.replace(/^0x/i, '').toLowerCase();

    // Off-chain IPFS upload if CBOM provided and CID missing
    if (scan.cbom && !ipfsCid && options.uploadIpfs !== false) {
      const ipfsRes = await uploadCBOMToIPFS(scan.cbom, {
        scanId: scan.scanId,
        mock: options.mockIpfs || false,
      });
      ipfsCid = ipfsRes.cid;
      ipfsUri = ipfsRes.uri;
    }

    processedScans.push({
      scanId: scan.scanId,
      merkleRoot,
      ipfsCid,
      ipfsUri,
      orgId: scan.orgId || options.orgId || process.env.ORG_ID || 'default-org',
      scannerVersion: scan.scannerVersion || options.scannerVersion || process.env.SCANNER_VERSION || '1.0.0',
    });
  }

  // Build the deterministic batch Merkle tree (sorts scans lexicographically by scanId)
  const batchTree = buildBatchMerkleTree(processedScans);

  // Generate audit proof for each scan
  const scansWithProofs = batchTree.scans.map((s) => {
    const proofRes = getBatchProof(batchTree, s.scanId);
    return {
      scanId: s.scanId,
      merkleRoot: s.merkleRoot,
      leaf: proofRes.leaf,
      ipfsCid: s.ipfsCid,
      ipfsUri: s.ipfsUri,
      orgId: s.orgId,
      scannerVersion: s.scannerVersion,
      proof: proofRes.proof,
    };
  });

  const { batchId, batchIdBytes32 } = deriveDeterministicBatchId(batchTree.batchRoot);

  return {
    batchId,
    batchIdBytes32,
    batchRoot: batchTree.batchRoot,
    batchRootHex: batchTree.batchRootHex,
    scanCount: scansWithProofs.length,
    scanIds: scansWithProofs.map((s) => s.scanId),
    scans: scansWithProofs,
    orgId: options.orgId || process.env.ORG_ID || 'default-org',
    scannerVersion: options.scannerVersion || process.env.SCANNER_VERSION || '1.0.0',
    createdAt: new Date().toISOString(),
    tree: batchTree.tree,
  };
}

/**
 * Resolves the contract instance, signer wallet, and provider using network configuration.
 */
function resolveContractAndWallet(options = {}) {
  const chainMode =
    (options && options.chainMode) ||
    process.env.CHAIN_MODE ||
    'permissioned';
  const isPermissioned = chainMode === 'permissioned';
  const targetNetwork = isPermissioned ? 'localhost' : 'sepolia';

  const netPath = path.join(__dirname, '..', `deployed-${targetNetwork}.json`);
  const defaultPath = path.join(__dirname, '..', 'deployed-contract.json');

  let deployedAddress = '';
  let deployedNetwork = targetNetwork;

  if (fs.existsSync(netPath)) {
    const data = JSON.parse(fs.readFileSync(netPath, 'utf8'));
    deployedAddress = data.address;
    deployedNetwork = data.network || targetNetwork;
  } else if (fs.existsSync(defaultPath)) {
    const data = JSON.parse(fs.readFileSync(defaultPath, 'utf8'));
    deployedAddress = data.address;
    deployedNetwork = data.network || targetNetwork;
  } else if (!options.contractAddress && !process.env.PERMISSIONED_CONTRACT_ADDRESS && !process.env.PUBLIC_CONTRACT_ADDRESS) {
    throw new Error('No deployment file found — run deploy.js first');
  }

  const rpcUrl =
    (options && options.rpcUrl) ||
    (isPermissioned
      ? process.env.PERMISSIONED_RPC_URL || 'http://127.0.0.1:8545'
      : process.env.PUBLIC_RPC_URL || process.env.SEPOLIA_RPC_URL || process.env.RPC_URL || 'http://127.0.0.1:8545');

  const contractAddress =
    (options && options.contractAddress) ||
    (isPermissioned
      ? process.env.PERMISSIONED_CONTRACT_ADDRESS || deployedAddress
      : process.env.PUBLIC_CONTRACT_ADDRESS || deployedAddress);

  const network = isPermissioned ? 'localhost' : 'sepolia';
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  const signingKey = getSigningKey();
  const wallet = new ethers.Wallet(signingKey.privateKey, provider);

  const artifactPath = path.join(__dirname, '..', 'artifacts', 'contracts', 'CryptoAnchor.sol', 'CryptoAnchor.json');
  let abi;
  if (fs.existsSync(artifactPath)) {
    abi = JSON.parse(fs.readFileSync(artifactPath, 'utf8')).abi;
  } else {
    abi = [
      'function anchorScan(bytes32 scanId, bytes32 merkleRoot, string orgId, string scannerVersion) external',
      'function getAnchor(bytes32 scanId) external view returns (bytes32 merkleRoot, address anchoredBy, uint256 timestamp, string orgId, string scannerVersion, bool exists)',
      'function isAnchored(bytes32 scanId) external view returns (bool)',
    ];
  }

  const contract = new ethers.Contract(contractAddress, abi, wallet);

  return { contract, provider, wallet, contractAddress, network };
}

/**
 * Anchors a batch Merkle root on the existing CryptoAnchor smart contract.
 *
 * The batch root is anchored as a single transaction under `batchIdBytes32`.
 *
 * @param {object} batchObject - Batch manifest from prepareScanBatch().
 * @param {object} [options]
 * @returns {Promise<object>} On-chain transaction confirmation.
 */
async function anchorBatchOnChain(batchObject, options = {}) {
  if (!batchObject || !batchObject.batchIdBytes32 || !batchObject.batchRootHex) {
    throw new TypeError('Invalid batchObject: must be prepared with prepareScanBatch()');
  }

  const { contract, provider, wallet, contractAddress, network } = resolveContractAndWallet(options);

  const nonce = await provider.getTransactionCount(wallet.address, 'pending');
  const tx = await contract['anchorScan(bytes32,bytes32,string,string)'](
    batchObject.batchIdBytes32,
    batchObject.batchRootHex,
    batchObject.orgId,
    batchObject.scannerVersion,
    { nonce }
  );

  const receipt = await tx.wait();

  return {
    success: true,
    batchId: batchObject.batchId,
    batchIdBytes32: batchObject.batchIdBytes32,
    batchRoot: batchObject.batchRoot,
    batchRootHex: batchObject.batchRootHex,
    txHash: tx.hash,
    blockNumber: receipt.blockNumber,
    network,
    contractAddress,
    scanCount: batchObject.scanCount,
    scanIds: batchObject.scanIds,
    anchoredAt: new Date().toISOString(),
  };
}

/**
 * Verifies an individual scan against an on-chain batch anchor.
 *
 * Steps:
 *   1. Queries `getAnchor(batchIdBytes32)` on the smart contract.
 *   2. Confirms batch exists on-chain.
 *   3. Extracts anchored on-chain `batchRoot`.
 *   4. Independently verifies the scan's Merkle proof against the on-chain `batchRoot`.
 *   5. If CBOM is provided, verifies CBOM hash against the scan's Merkle root.
 *
 * @param {string} batchId - Batch identifier (e.g. "batch:<hash>" or raw bytes32).
 * @param {object} scanRecord - Scan record { scanId, merkleRoot, [orgId], [scannerVersion], [cbom] }.
 * @param {Array} proof - Merkle proof path for the scan.
 * @param {object} [options]
 * @returns {Promise<object>} Verification result.
 */
async function verifyBatchScan(batchId, scanRecord, proof, options = {}) {
  if (!batchId) {
    throw new TypeError('batchId is required');
  }
  if (!scanRecord || !scanRecord.scanId || !scanRecord.merkleRoot) {
    throw new TypeError('scanRecord with scanId and merkleRoot is required');
  }
  if (!Array.isArray(proof)) {
    throw new TypeError('proof must be an array');
  }

  const { contract } = resolveContractAndWallet(options);

  const batchIdBytes32 =
    typeof batchId === 'string' && batchId.startsWith('0x') && batchId.length === 66
      ? batchId
      : ethers.keccak256(ethers.toUtf8Bytes(batchId));

  const [onChainBatchRoot, anchoredBy, timestamp, orgId, scannerVersion, exists] =
    await contract.getAnchor(batchIdBytes32);

  if (!exists) {
    return {
      verified: false,
      proofValid: false,
      reason: 'Batch anchor record does not exist on-chain',
      batchId,
      scanId: scanRecord.scanId,
    };
  }

  // Verify the scan's cryptographic proof against the on-chain batch root
  const cleanOnChainRoot = onChainBatchRoot.replace(/^0x/i, '').toLowerCase();
  const proofValid = verifyBatchProof(scanRecord, proof, cleanOnChainRoot);

  if (!proofValid) {
    return {
      verified: false,
      proofValid: false,
      reason: 'Merkle proof verification failed against on-chain batch root',
      batchId,
      scanId: scanRecord.scanId,
      onChainBatchRoot: cleanOnChainRoot,
    };
  }

  // Optional: verify CBOM if supplied
  let ipfsVerified = null;
  if (scanRecord.cbom) {
    const ipfsCheck = verifyIPFSContent(scanRecord.cbom, scanRecord.merkleRoot);
    ipfsVerified = ipfsCheck.valid;
  }

  return {
    verified: true,
    proofValid: true,
    ipfsVerified,
    batchId,
    scanId: scanRecord.scanId,
    onChainBatchRoot: cleanOnChainRoot,
    anchoredBy,
    timestamp: Number(timestamp),
    orgId,
    scannerVersion,
  };
}

module.exports = {
  deriveDeterministicBatchId,
  prepareScanBatch,
  anchorBatchOnChain,
  verifyBatchScan,
  resolveContractAndWallet,
};
