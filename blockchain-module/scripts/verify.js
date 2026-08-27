const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
require('dotenv').config();

/**
 * Real verify flow — this backs module 5's GET /scan/:scanId/verify:
 *   1. Recompute SHA-256 over the CURRENT content (findings + CBOM as
 *      stored today)
 *   2. Read the on-chain record for this scanId (real chain read, not
 *      a DB lookup)
 *   3. Compare recomputed hash vs on-chain hash -> tamper-evidence
 *   4. Optionally verify the stored ECDSA signature recovers the
 *      expected signer address
 *
 * Usage:
 *   node scripts/verify.js <scanId> <path-to-current-content-json> [signature]
 */

function sha256Hex(buffer) {
  return '0x' + crypto.createHash('sha256').update(buffer).digest('hex');
}

function scanIdToBytes32(scanId) {
  return ethers.keccak256(ethers.toUtf8Bytes(scanId));
}

async function verifyScan(scanId, currentContentBuffer, signature) {
  const rpcUrl = process.env.RPC_URL || 'http://127.0.0.1:8545';

  const deployedPath = path.join(__dirname, '..', 'deployed-contract.json');
  if (!fs.existsSync(deployedPath)) {
    throw new Error('deployed-contract.json not found — run deploy.js first');
  }
  const { address: contractAddress } = JSON.parse(fs.readFileSync(deployedPath, 'utf8'));

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const abi = [
    'function getAnchor(bytes32 scanId) external view returns (bytes32 contentHash, address anchoredBy, uint256 timestamp, bool exists)',
  ];
  const contract = new ethers.Contract(contractAddress, abi, provider);

  const scanIdBytes32 = scanIdToBytes32(scanId);
  const [onChainHash, anchoredBy, timestamp, exists] = await contract.getAnchor(scanIdBytes32);

  if (!exists) {
    return { verified: false, reason: 'No anchor found on-chain for this scanId', scanId };
  }

  const recomputedHash = sha256Hex(currentContentBuffer);
  const hashMatches = recomputedHash.toLowerCase() === onChainHash.toLowerCase();

  let signatureValid = null;
  if (signature) {
    try {
      const recoveredAddress = ethers.verifyMessage(ethers.getBytes(onChainHash), signature);
      signatureValid = recoveredAddress.toLowerCase() === anchoredBy.toLowerCase();
    } catch (err) {
      signatureValid = false;
    }
  }

  return {
    verified: hashMatches && signatureValid !== false,
    scanId,
    onChainHash,
    recomputedHash,
    hashMatches,
    signatureValid,
    anchoredBy,
    anchoredAt: new Date(Number(timestamp) * 1000).toISOString(),
  };
}

// CLI entry point
if (require.main === module) {
  const [, , scanId, contentPath, signature] = process.argv;
  if (!scanId || !contentPath) {
    console.error('Usage: node scripts/verify.js <scanId> <path-to-content-json> [signature]');
    process.exit(1);
  }
  const contentBuffer = fs.readFileSync(contentPath);

  verifyScan(scanId, contentBuffer, signature)
    .then((result) => {
      console.log(JSON.stringify(result, null, 2));
      process.exitCode = result.verified ? 0 : 2;
    })
    .catch((err) => {
      console.error('Verify failed:', err.message);
      process.exitCode = 1;
    });
}

module.exports = { verifyScan, sha256Hex, scanIdToBytes32 };
