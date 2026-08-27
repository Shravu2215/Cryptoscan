const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
require('dotenv').config();

/**
 * Real anchor flow — no dummy tx id, no fake signature:
 *   1. SHA-256 hash the scan content (findings + CBOM JSON, byte-for-byte)
 *   2. Sign that hash with the wallet's private key (ECDSA, real signature)
 *   3. Submit a real transaction to CryptoAnchor.anchorScan() on-chain
 *   4. Return { contentHash, signature, txHash } — this is exactly what
 *      backend-core writes into the Anchor table.
 *
 * Usage:
 *   node scripts/anchor.js <scanId> <path-to-content-json>
 *
 * In production this logic gets called from the
 * POST /scan/:scanId/anchor route (module 4/5) instead of the CLI —
 * same three steps, just triggered over HTTP.
 */

function sha256Hex(buffer) {
  return '0x' + crypto.createHash('sha256').update(buffer).digest('hex');
}

function scanIdToBytes32(scanId) {
  // scanId from Prisma is a UUID string, not natively bytes32 —
  // keccak256 it so it fits the Solidity mapping key.
  return ethers.keccak256(ethers.toUtf8Bytes(scanId));
}

async function anchorScan(scanId, contentBuffer) {
  const rpcUrl = process.env.RPC_URL || 'http://127.0.0.1:8545';
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    throw new Error('PRIVATE_KEY not set in .env — refusing to anchor without a real signer');
  }

  const deployedPath = path.join(__dirname, '..', 'deployed-contract.json');
  if (!fs.existsSync(deployedPath)) {
    throw new Error('deployed-contract.json not found — run deploy.js first');
  }
  const { address: contractAddress, network } = JSON.parse(fs.readFileSync(deployedPath, 'utf8'));

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(privateKey, provider);

  // Step 1: real hash
  const contentHash = sha256Hex(contentBuffer);

  // Step 2: real signature — wallet signs the content hash itself,
  // independent of the transaction, so it can be verified off-chain
  // even before the tx confirms.
  const signature = await wallet.signMessage(ethers.getBytes(contentHash));

  // Step 3: real transaction
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
