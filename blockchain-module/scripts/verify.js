const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
const { buildMerkleTree } = require('../../integrity-service/merkle');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
require('dotenv').config();

/**
 * Real verify flow — this backs module 5's GET /scan/:scanId/verify:
 *   1. Recompute the Merkle root over the CURRENT CBOM content (via merkle.js)
 *   2. Read the on-chain record for this scanId (real chain read, not
 *      a DB lookup)
 *   3. Compare recomputed Merkle root vs on-chain hash -> tamper-evidence
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

/**
 * Extracts or wraps CBOM components into a deterministic array for the Merkle tree builder.
 * Mirrors extractComponents() in anchor.js.
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

async function verifyScan(scanId, currentContentBuffer, signature, options = {}) {
  const chainMode = (options && options.chainMode) || process.env.CHAIN_MODE || 'permissioned';
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

  const rpcUrl = (options && options.rpcUrl) ||
    (isPermissioned
      ? (process.env.PERMISSIONED_RPC_URL || 'http://127.0.0.1:8545')
      : (process.env.PUBLIC_RPC_URL || process.env.SEPOLIA_RPC_URL || process.env.RPC_URL || 'http://127.0.0.1:8545'));

  const contractAddress = (options && options.contractAddress) ||
    (isPermissioned
      ? (process.env.PERMISSIONED_CONTRACT_ADDRESS || deployedAddress)
      : (process.env.PUBLIC_CONTRACT_ADDRESS || deployedAddress));

  const provider = new ethers.JsonRpcProvider(rpcUrl);

  let abi;
  const artifactPath = path.join(__dirname, '..', 'artifacts', 'contracts', 'CryptoAnchor.sol', 'CryptoAnchor.json');
  if (fs.existsSync(artifactPath)) {
    abi = JSON.parse(fs.readFileSync(artifactPath, 'utf8')).abi;
  } else {
    abi = [
      'function getAnchor(bytes32 scanId) external view returns (bytes32 merkleRoot, address anchoredBy, uint256 timestamp, string orgId, string scannerVersion, bool exists)',
    ];
  }
  const contract = new ethers.Contract(contractAddress, abi, provider);

  const scanIdBytes32 = scanIdToBytes32(scanId);
  let onChainHash, anchoredBy, timestamp, orgId, scannerVersion, exists;
  const res = await contract.getAnchor(scanIdBytes32);
  if (res.length >= 6) {
    [onChainHash, anchoredBy, timestamp, orgId, scannerVersion, exists] = res;
  } else {
    [onChainHash, anchoredBy, timestamp, exists] = res;
  }

  if (!exists) {
    return { verified: false, reason: 'No anchor found on-chain for this scanId', scanId };
  }

  // Recompute Merkle root commitment matching anchor.js
  const components = extractComponents(currentContentBuffer);
  const { root: merkleRoot } = buildMerkleTree(components);
  const recomputedHash = '0x' + merkleRoot;
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
    orgId: orgId || null,
    scannerVersion: scannerVersion || null,
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
