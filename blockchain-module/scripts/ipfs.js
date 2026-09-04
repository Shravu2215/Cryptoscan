'use strict';

const crypto = require('crypto');
const { canonicalize, buildMerkleTree, isValidSha256Hex } = require('../../integrity-service/merkle');
require('dotenv').config();

/**
 * In-memory store for mocked / local test boundary when real IPFS credentials
 * are unavailable, allowing end-to-end testing without external network dependencies.
 */
const mockIPFSStore = new Map();

/**
 * Computes an authentic IPFS CIDv1 (base32 lowercase, SHA-256 raw multihash)
 * matching official IPFS and Pinata CID derivation.
 *
 * Multihash format: [0x01 (CIDv1), 0x55 (raw), 0x12 (sha2-256), 0x20 (32 bytes), ...digest]
 * Encoded in Base32 with 'b' multibase prefix -> "bafkrei..."
 *
 * @param {Buffer} buffer - Content buffer to hash into CIDv1.
 * @returns {string} 59-character lowercase Base32 CIDv1 string.
 */
function computeDeterministicCID(buffer) {
  const sha256Digest = crypto.createHash('sha256').update(buffer).digest();
  const multihash = Buffer.concat([
    Buffer.from([0x01, 0x55, 0x12, 0x20]),
    sha256Digest,
  ]);

  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0;
  let value = 0;
  let output = 'b';

  for (let i = 0; i < multihash.length; i++) {
    value = (value << 8) | multihash[i];
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Computes the deterministic canonical SHA-256 content hash of a CBOM object.
 *
 * @param {object|string|Buffer} cbomInput - Raw or parsed CBOM.
 * @returns {{
 *   canonicalJson: string,
 *   contentHash: string,
 *   contentHashHex: string,
 *   parsedCBOM: object
 * }}
 */
function hashCBOM(cbomInput) {
  let parsed;
  if (Buffer.isBuffer(cbomInput) || typeof cbomInput === 'string') {
    try {
      parsed = JSON.parse(cbomInput.toString('utf8'));
    } catch (err) {
      throw new TypeError(`Invalid CBOM input: not valid JSON (${err.message})`);
    }
  } else if (cbomInput && typeof cbomInput === 'object') {
    parsed = cbomInput;
  } else {
    throw new TypeError('CBOM input must be a non-null object, JSON string, or Buffer');
  }

  const canonicalJson = canonicalize(parsed);
  const rawHash = crypto.createHash('sha256').update(canonicalJson, 'utf8').digest('hex').toLowerCase();

  return {
    canonicalJson,
    contentHash: rawHash,
    contentHashHex: '0x' + rawHash,
    parsedCBOM: parsed,
  };
}

/**
 * Uploads a CBOM document to IPFS (via Pinata API or mocked local boundary).
 *
 * Guarantees:
 * - Deterministic canonical JSON serialization before upload.
 * - Cryptographic SHA-256 hash & Merkle root computation.
 * - Never returns a fake success if upload fails.
 * - Produces a standardized data structure suitable for blockchain anchoring.
 *
 * @param {object|string|Buffer} cbomInput - CBOM document to upload.
 * @param {object} [options]
 * @param {string} [options.scanId] - Associated scanId (extracted from CBOM if omitted).
 * @param {string} [options.pinataJwt] - Override Pinata JWT token.
 * @param {string} [options.apiUrl] - Override IPFS API endpoint.
 * @param {boolean} [options.mock=false] - Force use of local deterministic mock boundary.
 * @param {boolean} [options.requireLive=false] - Fail immediately if live credentials missing.
 * @returns {Promise<{
 *   cid: string,
 *   uri: string,
 *   contentHash: string,
 *   contentHashHex: string,
 *   merkleRoot: string,
 *   scanId: string,
 *   byteSize: number,
 *   provider: string,
 *   timestamp: string,
 *   isMock: boolean
 * }>}
 */
async function uploadCBOMToIPFS(cbomInput, options = {}) {
  const { canonicalJson, contentHash, contentHashHex, parsedCBOM } = hashCBOM(cbomInput);
  const contentBuffer = Buffer.from(canonicalJson, 'utf8');

  // Extract scanId
  const scanId =
    options.scanId ||
    parsedCBOM.scanId ||
    (parsedCBOM.metadata && parsedCBOM.metadata.scanId) ||
    parsedCBOM.serialNumber ||
    `scan-${contentHash.slice(0, 16)}`;

  // Compute Merkle root of CBOM components for blockchain anchor alignment
  const components = Array.isArray(parsedCBOM.components)
    ? parsedCBOM.components
    : Array.isArray(parsedCBOM)
    ? parsedCBOM
    : [parsedCBOM];
  const { root: merkleRoot } = buildMerkleTree(components);

  const pinataJwt = options.pinataJwt || process.env.PINATA_JWT;
  const apiUrl = options.apiUrl || process.env.IPFS_API_URL || 'https://api.pinata.cloud';

  // If live credentials are explicitly required but missing, throw immediately
  if (options.requireLive && (!pinataJwt || pinataJwt.trim() === '')) {
    throw new Error('IPFS upload failed: Missing required PINATA_JWT credentials for live upload');
  }

  // Determine whether to use mock boundary or live Pinata API
  const useMock = options.mock || !pinataJwt || pinataJwt.trim() === '';

  if (useMock) {
    // Deterministic CID generation matching IPFS v1 raw sha2-256
    const cid = computeDeterministicCID(contentBuffer);
    mockIPFSStore.set(cid, canonicalJson);

    return {
      cid,
      uri: `ipfs://${cid}`,
      contentHash,
      contentHashHex,
      merkleRoot,
      scanId: String(scanId),
      byteSize: contentBuffer.length,
      provider: 'mock-ipfs-gateway',
      timestamp: new Date().toISOString(),
      isMock: true,
    };
  }

  // Live Pinata pinning upload
  try {
    const pinEndpoint = `${apiUrl.replace(/\/+$/, '')}/pinning/pinJSONToIPFS`;
    const payload = {
      pinataContent: JSON.parse(canonicalJson),
      pinataMetadata: {
        name: `cbom-${scanId}.json`,
        keyvalues: {
          scanId: String(scanId),
          contentHash,
          merkleRoot,
          uploadedAt: new Date().toISOString(),
        },
      },
      pinataOptions: {
        cidVersion: 1,
      },
    };

    const response = await fetch(pinEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${pinataJwt}`,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Pinata API returned HTTP ${response.status}: ${errorText}`);
    }

    const data = await response.json();
    if (!data || !data.IpfsHash) {
      throw new Error('Pinata API response missing expected IpfsHash field');
    }

    const cid = data.IpfsHash;

    return {
      cid,
      uri: `ipfs://${cid}`,
      contentHash,
      contentHashHex,
      merkleRoot,
      scanId: String(scanId),
      byteSize: data.PinSize || contentBuffer.length,
      provider: 'pinata-ipfs',
      timestamp: data.Timestamp || new Date().toISOString(),
      isMock: false,
    };
  } catch (uploadErr) {
    throw new Error(`IPFS upload failed: ${uploadErr.message}`);
  }
}

/**
 * Retrieves a CBOM document from IPFS by its CID.
 *
 * @param {string} cid - IPFS Content Identifier.
 * @param {object} [options]
 * @param {string} [options.gatewayUrl] - Gateway base URL (defaults to IPFS_GATEWAY_URL).
 * @returns {Promise<object>} Parsed CBOM object.
 */
async function fetchCBOMFromIPFS(cid, options = {}) {
  if (typeof cid !== 'string' || !cid.trim()) {
    throw new TypeError('Invalid CID: must be a non-empty string');
  }

  // 1. Check local mock storage first
  if (mockIPFSStore.has(cid)) {
    return JSON.parse(mockIPFSStore.get(cid));
  }

  // 2. Fetch from IPFS Gateway
  const gatewayUrl = options.gatewayUrl || process.env.IPFS_GATEWAY_URL || 'https://gateway.pinata.cloud/ipfs';
  const url = `${gatewayUrl.replace(/\/+$/, '')}/${cid}`;

  try {
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Gateway returned HTTP ${res.status}: ${res.statusText}`);
    }
    const text = await res.text();
    return JSON.parse(text);
  } catch (fetchErr) {
    throw new Error(`Failed to retrieve CBOM from IPFS (CID: ${cid}): ${fetchErr.message}`);
  }
}

/**
 * Verifies retrieved CBOM content against an expected cryptographic hash or Merkle root.
 *
 * @param {object|string|Buffer} cbomContent - Retrieved CBOM content.
 * @param {string} expectedHash - Expected SHA-256 hash or Merkle root.
 * @returns {{
 *   valid: boolean,
 *   recomputedHash: string,
 *   expectedHash: string,
 *   recomputedMerkleRoot: string
 * }}
 */
function verifyIPFSContent(cbomContent, expectedHash) {
  const { contentHash, contentHashHex, parsedCBOM } = hashCBOM(cbomContent);

  const components = Array.isArray(parsedCBOM.components)
    ? parsedCBOM.components
    : Array.isArray(parsedCBOM)
    ? parsedCBOM
    : [parsedCBOM];
  const { root: recomputedMerkleRoot } = buildMerkleTree(components);

  const cleanExpected = (expectedHash || '').replace(/^0x/i, '').toLowerCase();
  const cleanContentHash = contentHash.toLowerCase();
  const cleanMerkle = recomputedMerkleRoot.toLowerCase();

  // Valid if expectedHash matches either the canonical whole-CBOM hash OR the component Merkle root
  const hashMatches = cleanExpected === cleanContentHash || cleanExpected === cleanMerkle;

  return {
    valid: hashMatches,
    recomputedHash: cleanContentHash,
    recomputedHashHex: contentHashHex,
    recomputedMerkleRoot: cleanMerkle,
    expectedHash: cleanExpected,
  };
}

module.exports = {
  uploadCBOMToIPFS,
  fetchCBOMFromIPFS,
  verifyIPFSContent,
  hashCBOM,
  computeDeterministicCID,
  mockIPFSStore,
};
