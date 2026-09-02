const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
const { buildMerkleTree } = require('../../integrity-service/merkle');
const { getSigningKey } = require('../../integrity-service/kms');
const { requestTimestamp } = require('../../integrity-service/timestamp');
require('dotenv').config();

/**
 * Real anchor flow — Merkle-tree root commitment + KMS signing + RFC 3161 timestamping:
 *   1. Extract/parse CBOM components and compute deterministic Merkle root (via merkle.js)
 *   2. Obtain an RFC 3161 trusted timestamp for the Merkle root (via timestamp.js)
 *   3. Sign the Merkle root content commitment with the KMS-managed key (ECDSA, secp256k1)
 *   4. Submit a real transaction to CryptoAnchor.anchorScan(scanId, contentHash) on-chain
 *   5. Return { scanId, contentHash, signature, txHash, merkleRoot, timestamp, ... }
 *
 * Usage:
 *   node scripts/anchor.js <scanId> <path-to-content-json>
 */

function sha256Hex(buffer) {
  return '0x' + crypto.createHash('sha256').update(buffer).digest('hex');
}

function scanIdToBytes32(scanId) {
  // scanId from Prisma is a UUID string, not natively bytes32 —
  // keccak256 it so it fits the Solidity mapping key.
  return ethers.keccak256(ethers.toUtf8Bytes(scanId));
}

/**
 * Extracts or wraps CBOM components into a deterministic array for the Merkle tree builder.
 * Accepts:
 *   - CBOM object/string/buffer with a `components` array
 *   - Direct array of components
 *   - Raw content buffer or object (wrapped as a single component)
 */
function extractComponents(contentInput) {
  if (Array.isArray(contentInput)) {
    return contentInput.length > 0 ? contentInput : [{ empty: true }];
  }

  let parsed = contentInput;
  if (Buffer.isBuffer(contentInput) || typeof contentInput === 'string') {
    try {
      parsed = JSON.parse(contentInput.toString('utf8'));
    } catch (err) {
      return [{ content: contentInput.toString('utf8') }];
    }
  }

  if (Array.isArray(parsed)) {
    return parsed.length > 0 ? parsed : [{ empty: true }];
  }

  if (parsed && typeof parsed === 'object') {
    if (Array.isArray(parsed.components) && parsed.components.length > 0) {
      return parsed.components;
    }
    return [parsed];
  }

  return [{ content: String(parsed) }];
}

async function anchorScan(scanId, contentBuffer) {
  const rpcUrl = process.env.RPC_URL || 'http://127.0.0.1:8545';
  const signingKey = getSigningKey();

  const deployedPath = path.join(__dirname, '..', 'deployed-contract.json');
  if (!fs.existsSync(deployedPath)) {
    throw new Error('deployed-contract.json not found — run deploy.js first');
  }
  const { address: contractAddress, network } = JSON.parse(fs.readFileSync(deployedPath, 'utf8'));

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(signingKey.privateKey, provider);

  // Step 1: Merkle tree root commitment (replaces whole-blob hashing)
  const components = extractComponents(contentBuffer);
  const { root: merkleRoot } = buildMerkleTree(components);
  const contentHash = '0x' + merkleRoot;

  // Step 2: RFC 3161 trusted timestamp for the Merkle root
  let timestamp = null;
  try {
    timestamp = await requestTimestamp(merkleRoot);
  } catch (tsErr) {
    console.warn('RFC 3161 timestamp acquisition warning:', tsErr.message);
  }

  // Step 3: KMS-backed signature over the on-chain content commitment
  const signature = await wallet.signMessage(ethers.getBytes(contentHash));

  // Step 4: Real transaction on-chain
  const abi = [
    'function anchorScan(bytes32 scanId, bytes32 contentHash) external',
  ];
  const contract = new ethers.Contract(contractAddress, abi, wallet);

  const scanIdBytes32 = scanIdToBytes32(scanId);
  const tx = await contract.anchorScan(scanIdBytes32, contentHash);
  console.log('Transaction submitted:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed in block:', receipt.blockNumber);

  return {
    scanId,
    contentHash,
    signature,
    txHash: receipt.hash,
    network,
    anchoredBy: wallet.address,
    blockNumber: receipt.blockNumber,
    merkleRoot,
    timestamp,
  };
}

// CLI entry point
if (require.main === module) {
  const [, , scanId, contentPath] = process.argv;
  if (!scanId || !contentPath) {
    console.error('Usage: node scripts/anchor.js <scanId> <path-to-content-json>');
    process.exit(1);
  }
  const contentBuffer = fs.readFileSync(contentPath);

  anchorScan(scanId, contentBuffer)
    .then((result) => {
      console.log(JSON.stringify(result, null, 2));
    })
    .catch((err) => {
      console.error('Anchor failed:', err.message);
      process.exitCode = 1;
    });
}

module.exports = { anchorScan, sha256Hex, scanIdToBytes32 };
