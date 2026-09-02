'use strict';

const crypto = require('crypto');

/**
 * Default hashing algorithm for the Merkle tree.
 * Centralized to support future algorithm agility without breaking API.
 */
const DEFAULT_HASH_ALGORITHM = 'sha256';

/**
 * Regular expression to validate 64-character lowercase hexadecimal SHA-256 strings.
 */
const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;

/**
 * Helper to check if a value is a valid 64-character lowercase hexadecimal SHA-256 hash.
 *
 * @param {*} str - Value to validate.
 * @returns {boolean}
 */
function isValidSha256Hex(str) {
  return typeof str === 'string' && SHA256_HEX_REGEX.test(str);
}

/**
 * Computes cryptographic hash of input data using the specified algorithm.
 * Returns a 64-character lowercase hexadecimal string for SHA-256.
 *
 * @param {string|Buffer} data - The data to hash.
 * @param {string} [algorithm=DEFAULT_HASH_ALGORITHM] - Hashing algorithm.
 * @returns {string} - Lowercase hexadecimal hash string.
 */
function hash(data, algorithm = DEFAULT_HASH_ALGORITHM) {
  const hasher = crypto.createHash(algorithm);
  if (Buffer.isBuffer(data)) {
    hasher.update(data);
  } else {
    hasher.update(String(data), 'utf8');
  }
  return hasher.digest('hex').toLowerCase();
}

/**
 * Hashes two sibling nodes using sorted-pair hashing:
 * 1. Lexicographically sort hashA and hashB.
 * 2. Concatenate: smallerHash + largerHash.
 * 3. Hash the concatenation: SHA256(smallerHash + largerHash).
 *
 * This ensures deterministic Merkle proofs where hashPair(A, B) === hashPair(B, A).
 *
 * @param {string} hashA - First node hash.
 * @param {string} hashB - Second node hash.
 * @param {string} [algorithm=DEFAULT_HASH_ALGORITHM] - Hashing algorithm.
 * @returns {string} - Resulting parent hash.
 */
function hashPair(hashA, hashB, algorithm = DEFAULT_HASH_ALGORITHM) {
  const [smaller, larger] = hashA < hashB ? [hashA, hashB] : [hashB, hashA];
  return hash(smaller + larger, algorithm);
}

/**
 * Recursively canonicalizes a JavaScript value into a deterministic JSON string.
 *
 * Requirements:
 * - Object keys are sorted lexicographically at every nesting level.
 * - Array element ordering is strictly preserved.
 * - Primitives (strings, numbers, booleans, null) are serialized consistently.
 * - Functions, symbols, and undefined values in objects are omitted (standard JSON).
 * - Undefined values in arrays are serialized as null (standard JSON).
 * - Does NOT mutate the input object.
 *
 * @param {*} val - Value to canonicalize.
 * @returns {string} - Deterministic canonical JSON string.
 */
function canonicalize(val) {
  if (val === null || typeof val !== 'object') {
    return JSON.stringify(val);
  }

  // Respect toJSON method if present (e.g. Date objects)
  if (typeof val.toJSON === 'function') {
    return canonicalize(val.toJSON());
  }

  if (Array.isArray(val)) {
    const elements = val.map((item) => {
      const res = canonicalize(item);
      return res === undefined ? 'null' : res;
    });
    return `[${elements.join(',')}]`;
  }

  // Plain / nested object: sort keys lexicographically
  const keys = Object.keys(val).sort();
  const pairs = [];
  for (const key of keys) {
    const itemVal = val[key];
    if (itemVal !== undefined && typeof itemVal !== 'function' && typeof itemVal !== 'symbol') {
      pairs.push(`${JSON.stringify(key)}:${canonicalize(itemVal)}`);
    }
  }
  return `{${pairs.join(',')}}`;
}

/**
 * Builds a deterministic binary Merkle tree from an array of CBOM components.
 *
 * Rules:
 * 1. Each CBOM component is canonicalized and hashed via SHA-256 to form exactly one leaf.
 * 2. Tree construction uses sorted-pair hashing: hash(sort(A, B)).
 * 3. Odd node count at any level uses Bitcoin-style duplication of the last node:
 *    Level: [A, B, C] -> Parent 1 = H(sort(A, B)), Parent 2 = H(sort(C, C)).
 * 4. For a single component, its leaf is the Merkle root (not hashed again).
 * 5. Returns { root, leaves, tree } where tree preserves every level.
 *
 * @param {Array<object>} components - Array of CBOM component objects.
 * @param {object} [options] - Reserved for future hash agility.
 * @param {string} [options.algorithm=DEFAULT_HASH_ALGORITHM] - Hashing algorithm to use.
 * @returns {{ root: string, leaves: string[], tree: string[][] }}
 * @throws {TypeError} If components is not an array.
 * @throws {Error} If components array is empty.
 */
function buildMerkleTree(components, options = {}) {
  if (!Array.isArray(components)) {
    throw new TypeError('Components must be an array');
  }

  if (components.length === 0) {
    throw new Error('Cannot build Merkle tree from empty components');
  }

  const algorithm = options.algorithm || DEFAULT_HASH_ALGORITHM;

  // Step 1: Generate leaves from canonicalized CBOM components
  const leaves = components.map((component) => {
    const canonical = canonicalize(component);
    return hash(canonical, algorithm);
  });

  // Edge case: exactly one component
  // For one component, root = leaf. Do not hash the single leaf again.
  if (leaves.length === 1) {
    return {
      root: leaves[0],
      leaves: [...leaves],
      tree: [[leaves[0]]],
    };
  }

  // Step 2: Build tree levels using sorted-pair hashing and odd-node duplication
  const tree = [[...leaves]];
  let currentLevel = leaves;

  while (currentLevel.length > 1) {
    const nextLevel = [];

    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      // Bitcoin-style duplicate-last-node:
      // If the level has an odd number of nodes, duplicate the last node so no node is discarded.
      const right = (i + 1 < currentLevel.length) ? currentLevel[i + 1] : left;
      nextLevel.push(hashPair(left, right, algorithm));
    }

    tree.push(nextLevel);
    currentLevel = nextLevel;
  }

  const root = currentLevel[0];

  return {
    root,
    leaves: [...leaves],
    tree,
  };
}

/**
 * Generates an audit proof (Merkle path) for a leaf at the specified index.
 *
 * Each element of the returned proof array represents a sibling node:
 * {
 *   sibling: "64-character-hash",
 *   position: "left" | "right"
 * }
 *
 * - "left" indicates the sibling was to the left of the current node.
 * - "right" indicates the sibling was to the right of the current node.
 * - For an odd-node duplication (Bitcoin-style), the duplicated node itself
 *   is returned as the sibling with position "right".
 * - For a single-leaf tree (tree = [[leaf]]), returns an empty array [].
 *
 * @param {string[][]} tree - The Merkle tree levels as returned by buildMerkleTree().
 * @param {number} leafIndex - The index of the leaf in tree[0].
 * @returns {Array<{ sibling: string, position: 'left' | 'right' }>} Proof path.
 * @throws {TypeError|Error|RangeError} If tree or leafIndex is invalid.
 */
function getProof(tree, leafIndex) {
  if (!Array.isArray(tree) || tree.length === 0 || !Array.isArray(tree[0]) || tree[0].length === 0) {
    throw new Error('Invalid Merkle tree structure: tree must be a non-empty 2D array');
  }

  if (typeof leafIndex !== 'number' || !Number.isInteger(leafIndex)) {
    throw new TypeError('leafIndex must be an integer');
  }

  const leafCount = tree[0].length;
  if (leafIndex < 0 || leafIndex >= leafCount) {
    throw new RangeError(`leafIndex out of bounds: expected 0 <= index < ${leafCount}, received ${leafIndex}`);
  }

  // Single-leaf tree: the leaf is already the root, so proof is empty
  if (leafCount === 1) {
    return [];
  }

  const proof = [];
  let currentIndex = leafIndex;

  // Traverse from leaf level up to the level just below the root
  for (let level = 0; level < tree.length - 1; level++) {
    const currentLevel = tree[level];
    const isRightNode = (currentIndex % 2 === 1);

    if (isRightNode) {
      // Current node is on the right, sibling is on the left
      const siblingIndex = currentIndex - 1;
      proof.push({
        sibling: currentLevel[siblingIndex],
        position: 'left',
      });
    } else {
      // Current node is on the left, sibling is on the right
      const siblingIndex = currentIndex + 1;
      if (siblingIndex < currentLevel.length) {
        proof.push({
          sibling: currentLevel[siblingIndex],
          position: 'right',
        });
      } else {
        // Odd node count at this level: Bitcoin-style duplicate last node
        // The sibling is the duplicated current node
        proof.push({
          sibling: currentLevel[currentIndex],
          position: 'right',
        });
      }
    }

    currentIndex = Math.floor(currentIndex / 2);
  }

  return proof;
}

/**
 * Independently verifies whether a leaf belongs to the Merkle tree with the given root.
 *
 * Operates purely on the leaf, proof, and root without needing access to
 * the full CBOM, components list, or tree structure.
 *
 * Note: Position metadata ('left'/'right') is preserved in proof objects for clarity,
 * but sorting order during verification is handled via sorted-pair hashing
 * (hashPair), ensuring robust and tamper-evident verification.
 *
 * @param {string} leaf - 64-character lowercase hexadecimal SHA-256 leaf hash.
 * @param {Array<{ sibling: string, position: 'left' | 'right' }>} proof - Merkle proof path.
 * @param {string} root - 64-character lowercase hexadecimal SHA-256 root hash.
 * @returns {boolean} True if the proof proves membership of leaf in root, false otherwise.
 * @throws {TypeError} If inputs are malformed or invalid types.
 */
function verifyProof(leaf, proof, root) {
  if (!isValidSha256Hex(leaf)) {
    throw new TypeError('Invalid leaf: must be a 64-character lowercase hexadecimal string');
  }

  if (!isValidSha256Hex(root)) {
    throw new TypeError('Invalid root: must be a 64-character lowercase hexadecimal string');
  }

  if (!Array.isArray(proof)) {
    throw new TypeError('Proof must be an array');
  }

  // Validate structural integrity of each proof element
  for (let i = 0; i < proof.length; i++) {
    const element = proof[i];
    if (
      !element ||
      typeof element !== 'object' ||
      !isValidSha256Hex(element.sibling) ||
      (element.position !== 'left' && element.position !== 'right')
    ) {
      throw new TypeError(
        `Invalid proof element at index ${i}: must be an object with valid 64-character hex 'sibling' and position 'left' or 'right'`
      );
    }
  }

  // Progressively calculate parent hashes up to the root
  let currentHash = leaf;

  for (const element of proof) {
    currentHash = hashPair(currentHash, element.sibling);
  }

  return currentHash === root;
}

/**
 * Computes the deterministic leaf hash for a scan record in a batch.
 *
 * @param {object} scan - Scan record object containing at least scanId and merkleRoot.
 * @returns {string} 64-character lowercase hex SHA-256 hash.
 */
function computeScanLeaf(scan) {
  if (!scan || typeof scan !== 'object') {
    throw new TypeError('Scan record must be a non-null object');
  }
  if (!scan.scanId || typeof scan.scanId !== 'string') {
    throw new TypeError('Scan record must have a valid string scanId');
  }
  const rawRoot = scan.merkleRoot || '';
  const cleanRoot = rawRoot.replace(/^0x/i, '').toLowerCase();
  if (!isValidSha256Hex(cleanRoot)) {
    throw new TypeError(`Scan record for '${scan.scanId}' must have a valid 64-character hex merkleRoot`);
  }

  const normalized = {
    scanId: String(scan.scanId),
    merkleRoot: cleanRoot,
    ...(scan.orgId ? { orgId: String(scan.orgId) } : {}),
    ...(scan.scannerVersion ? { scannerVersion: String(scan.scannerVersion) } : {}),
  };

  return hash(canonicalize(normalized));
}

/**
 * Sorts an array of scan records deterministically by scanId (lexicographical order),
 * using merkleRoot as tie-breaker.
 *
 * @param {Array<object>} scans - Array of scan record objects.
 * @returns {Array<object>} New sorted array of scan records.
 */
function sortScanBatch(scans) {
  return [...scans].sort((a, b) => {
    const cmp = String(a.scanId).localeCompare(String(b.scanId));
    if (cmp !== 0) return cmp;
    const rootA = (a.merkleRoot || '').replace(/^0x/i, '').toLowerCase();
    const rootB = (b.merkleRoot || '').replace(/^0x/i, '').toLowerCase();
    return rootA.localeCompare(rootB);
  });
}

/**
 * Builds a deterministic batch Merkle tree combining multiple scan records.
 *
 * Leaf Ordering Rule:
 * Scans are sorted deterministically in lexicographical order by `scanId`.
 * Each scan is canonicalized as { scanId, merkleRoot, [orgId], [scannerVersion] }
 * and hashed via SHA-256 to form a leaf.
 *
 * The tree is constructed using sorted-pair binary hashing and Bitcoin-style
 * odd-node duplication, reusing the core buildMerkleTree engine.
 *
 * @param {Array<object>} scans - Array of scan records.
 * @param {object} [options] - Options passed to buildMerkleTree.
 * @returns {{
 *   batchRoot: string,
 *   batchRootHex: string,
 *   scans: Array<object>,
 *   leaves: string[],
 *   tree: string[][]
 * }}
 */
function buildBatchMerkleTree(scans, options = {}) {
  if (!Array.isArray(scans)) {
    throw new TypeError('Scans must be an array');
  }
  if (scans.length === 0) {
    throw new Error('Cannot build batch Merkle tree from empty scans array');
  }

  // Step 1: Deterministic leaf ordering by scanId
  const sortedScans = sortScanBatch(scans);

  // Step 2: Generate normalized canonical objects for each scan
  const normalizedComponents = sortedScans.map((s) => {
    const rawRoot = s.merkleRoot || '';
    const cleanRoot = rawRoot.replace(/^0x/i, '').toLowerCase();
    if (!isValidSha256Hex(cleanRoot)) {
      throw new TypeError(`Scan record for '${s.scanId}' has invalid merkleRoot: expected 64 hex chars`);
    }
    return {
      scanId: String(s.scanId),
      merkleRoot: cleanRoot,
      ...(s.orgId ? { orgId: String(s.orgId) } : {}),
      ...(s.scannerVersion ? { scannerVersion: String(s.scannerVersion) } : {}),
    };
  });

  // Step 3: Reuse core buildMerkleTree engine
  const treeResult = buildMerkleTree(normalizedComponents, options);

  return {
    batchRoot: treeResult.root,
    batchRootHex: '0x' + treeResult.root,
    scans: sortedScans,
    leaves: treeResult.leaves,
    tree: treeResult.tree,
  };
}

/**
 * Generates an audit proof for a specific scanId within a batch Merkle tree.
 *
 * @param {object} batchResult - Result object from buildBatchMerkleTree.
 * @param {string} scanId - The scanId to generate proof for.
 * @returns {{
 *   scanId: string,
 *   leaf: string,
 *   leafIndex: number,
 *   batchRoot: string,
 *   proof: Array<{ sibling: string, position: 'left' | 'right' }>
 * }}
 */
function getBatchProof(batchResult, scanId) {
  if (!batchResult || !Array.isArray(batchResult.scans) || !Array.isArray(batchResult.tree)) {
    throw new TypeError('Invalid batchResult object: must be returned from buildBatchMerkleTree');
  }
  if (typeof scanId !== 'string' || !scanId) {
    throw new TypeError('scanId must be a non-empty string');
  }

  const index = batchResult.scans.findIndex((s) => s.scanId === scanId);
  if (index === -1) {
    throw new Error(`scanId '${scanId}' not found in batch tree`);
  }

  const proof = getProof(batchResult.tree, index);
  return {
    scanId,
    leaf: batchResult.leaves[index],
    leafIndex: index,
    batchRoot: batchResult.batchRoot,
    proof,
  };
}

/**
 * Independently verifies whether a scan record belongs to a batch Merkle root.
 *
 * @param {object} scan - The scan record { scanId, merkleRoot, [orgId], [scannerVersion] }.
 * @param {Array<{ sibling: string, position: 'left' | 'right' }>} proof - Merkle proof path.
 * @param {string} batchRoot - 64-character lowercase hex (or 0x + 64 hex) batch root.
 * @returns {boolean} True if membership is mathematically proven.
 */
function verifyBatchProof(scan, proof, batchRoot) {
  const cleanBatchRoot = (batchRoot || '').replace(/^0x/i, '').toLowerCase();
  const leaf = computeScanLeaf(scan);
  return verifyProof(leaf, proof, cleanBatchRoot);
}

module.exports = {
  buildMerkleTree,
  canonicalize,
  hash,
  hashPair,
  getProof,
  verifyProof,
  isValidSha256Hex,
  computeScanLeaf,
  sortScanBatch,
  buildBatchMerkleTree,
  getBatchProof,
  verifyBatchProof,
};

