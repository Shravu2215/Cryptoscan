'use strict';

const assert = require('assert').strict;
const {
  buildMerkleTree,
  canonicalize,
  hash,
  hashPair,
  getProof,
  verifyProof,
} = require('./merkle');

console.log('Running Merkle Tree Builder & Proof Test Suite...\n');

// ===========================================================================
// STEP 1 TESTS (1 - 13)
// ===========================================================================

// ---------------------------------------------------------------------------
// Test 1: Empty array throws
// ---------------------------------------------------------------------------
{
  assert.throws(
    () => buildMerkleTree([]),
    (err) => {
      assert(err instanceof Error);
      assert.strictEqual(err.message, 'Cannot build Merkle tree from empty components');
      return true;
    },
    'Test 1 Failed: buildMerkleTree([]) must throw an Error with specific message'
  );
  console.log('✓ Test 1 Passed: Empty array throws expected error');
}

// ---------------------------------------------------------------------------
// Test 2: Non-array input throws TypeError
// ---------------------------------------------------------------------------
{
  const invalidInputs = [null, undefined, 'not-an-array', 12345, {}, false];
  for (const input of invalidInputs) {
    assert.throws(
      () => buildMerkleTree(input),
      (err) => {
        assert(err instanceof TypeError);
        return true;
      },
      `Test 2 Failed: Input ${JSON.stringify(input)} should throw TypeError`
    );
  }
  console.log('✓ Test 2 Passed: Non-array inputs throw TypeError');
}

// ---------------------------------------------------------------------------
// Test 3: One component (leaf = root, not hashed again)
// ---------------------------------------------------------------------------
{
  const comp = { name: 'RSA', keySize: 2048 };
  const expectedLeaf = hash(canonicalize(comp));
  const result = buildMerkleTree([comp]);

  assert.strictEqual(result.leaves.length, 1);
  assert.strictEqual(result.leaves[0], expectedLeaf);
  assert.strictEqual(result.root, expectedLeaf, 'Single component root must equal its leaf');
  assert.strictEqual(result.tree.length, 1, 'Tree for 1 component must have 1 level');
  assert.deepStrictEqual(result.tree, [[expectedLeaf]]);
  assert.strictEqual(result.tree[0][0], result.root);
  console.log('✓ Test 3 Passed: One component produces root equal to single leaf');
}

// ---------------------------------------------------------------------------
// Test 4: Two components
// ---------------------------------------------------------------------------
{
  const comp1 = { name: 'RSA', keySize: 2048 };
  const comp2 = { name: 'AES', mode: 'GCM' };
  const leaf1 = hash(canonicalize(comp1));
  const leaf2 = hash(canonicalize(comp2));

  const result = buildMerkleTree([comp1, comp2]);

  assert.strictEqual(result.leaves.length, 2);
  assert.strictEqual(result.leaves[0], leaf1);
  assert.strictEqual(result.leaves[1], leaf2);

  const expectedRoot = hashPair(leaf1, leaf2);
  assert.strictEqual(result.root, expectedRoot);
  assert.strictEqual(result.tree.length, 2);
  assert.deepStrictEqual(result.tree[0], [leaf1, leaf2]);
  assert.deepStrictEqual(result.tree[1], [expectedRoot]);
  assert.strictEqual(result.tree[result.tree.length - 1][0], result.root);
  console.log('✓ Test 4 Passed: Two components build 2-level tree with sorted-pair root');
}

// ---------------------------------------------------------------------------
// Test 5: Three components (Odd node count handling with Bitcoin-style duplication)
// ---------------------------------------------------------------------------
{
  const comp1 = { id: 'asset-1' };
  const comp2 = { id: 'asset-2' };
  const comp3 = { id: 'asset-3' };
  const l0 = hash(canonicalize(comp1));
  const l1 = hash(canonicalize(comp2));
  const l2 = hash(canonicalize(comp3));

  const result = buildMerkleTree([comp1, comp2, comp3]);

  assert.strictEqual(result.leaves.length, 3);
  assert.strictEqual(result.tree.length, 3);

  // Level 0: [l0, l1, l2]
  assert.deepStrictEqual(result.tree[0], [l0, l1, l2]);

  // Level 1: pair(l0, l1) and pair(l2, l2) [duplicated last node]
  const p0 = hashPair(l0, l1);
  const p1 = hashPair(l2, l2);
  assert.deepStrictEqual(result.tree[1], [p0, p1]);

  // Level 2 (Root): pair(p0, p1)
  const expectedRoot = hashPair(p0, p1);
  assert.deepStrictEqual(result.tree[2], [expectedRoot]);
  assert.strictEqual(result.root, expectedRoot);
  console.log('✓ Test 5 Passed: Three components handle odd-node duplication deterministically');
}

// ---------------------------------------------------------------------------
// Test 6: Four components
// ---------------------------------------------------------------------------
{
  const comps = [
    { name: 'RSA-2048' },
    { name: 'AES-256' },
    { name: 'SHA-256' },
    { name: 'ECDSA-P256' }
  ];
  const leaves = comps.map((c) => hash(canonicalize(c)));

  const result = buildMerkleTree(comps);

  assert.strictEqual(result.leaves.length, 4);
  assert.strictEqual(result.tree.length, 3);

  const p0 = hashPair(leaves[0], leaves[1]);
  const p1 = hashPair(leaves[2], leaves[3]);
  const expectedRoot = hashPair(p0, p1);

  assert.deepStrictEqual(result.tree[0], leaves);
  assert.deepStrictEqual(result.tree[1], [p0, p1]);
  assert.deepStrictEqual(result.tree[2], [expectedRoot]);
  assert.strictEqual(result.root, expectedRoot);
  console.log('✓ Test 6 Passed: Four components build 3-level binary Merkle tree');
}

// ---------------------------------------------------------------------------
// Test 7: Same logical object with different key insertion order produces same leaf hash
// ---------------------------------------------------------------------------
{
  const compA = { name: 'RSA', version: '2048', mode: 'PKCS1' };
  const compB = { mode: 'PKCS1', name: 'RSA', version: '2048' };
  const compC = { version: '2048', mode: 'PKCS1', name: 'RSA' };

  const hashA = hash(canonicalize(compA));
  const hashB = hash(canonicalize(compB));
  const hashC = hash(canonicalize(compC));

  assert.strictEqual(hashA, hashB, 'Key order must not change leaf hash');
  assert.strictEqual(hashB, hashC, 'Key order must not change leaf hash');

  const treeA = buildMerkleTree([compA]);
  const treeB = buildMerkleTree([compB]);
  assert.strictEqual(treeA.root, treeB.root, 'Roots must match regardless of key insertion order');
  console.log('✓ Test 7 Passed: Key insertion order does not affect leaf hash or root');
}

// ---------------------------------------------------------------------------
// Test 8: Nested objects are canonicalized recursively
// ---------------------------------------------------------------------------
{
  const compA = {
    cryptoProperties: {
      assetType: 'algorithm',
      algorithmProperties: {
        primitive: 'RSA',
        parameterSet: 2048,
        mode: 'OAEP'
      }
    },
    metadata: {
      author: 'CryptoScan',
      active: true,
      deprecated: null
    }
  };

  const compB = {
    metadata: {
      deprecated: null,
      active: true,
      author: 'CryptoScan'
    },
    cryptoProperties: {
      algorithmProperties: {
        mode: 'OAEP',
        parameterSet: 2048,
        primitive: 'RSA'
      },
      assetType: 'algorithm'
    }
  };

  const leafA = hash(canonicalize(compA));
  const leafB = hash(canonicalize(compB));
  assert.strictEqual(leafA, leafB, 'Nested objects with shuffled keys must produce identical leaf hashes');

  const treeA = buildMerkleTree([compA]);
  const treeB = buildMerkleTree([compB]);
  assert.strictEqual(treeA.root, treeB.root);
  console.log('✓ Test 8 Passed: Nested objects canonicalized recursively at all depths');
}

// ---------------------------------------------------------------------------
// Test 9: Array ordering remains meaningful
// ---------------------------------------------------------------------------
{
  const compA = {
    name: 'Finding',
    occurrences: [{ line: 10 }, { line: 20 }]
  };
  const compB = {
    name: 'Finding',
    occurrences: [{ line: 20 }, { line: 10 }]
  };

  const leafA = hash(canonicalize(compA));
  const leafB = hash(canonicalize(compB));

  assert.notStrictEqual(leafA, leafB, 'Different array order must yield different leaf hashes');

  const treeA = buildMerkleTree([compA]);
  const treeB = buildMerkleTree([compB]);
  assert.notStrictEqual(treeA.root, treeB.root);
  console.log('✓ Test 9 Passed: Array element ordering is preserved');
}

// ---------------------------------------------------------------------------
// Test 10: Re-running the exact same input produces the exact same root
// ---------------------------------------------------------------------------
{
  const components = [
    { name: 'Kyber768', type: 'PQC' },
    { name: 'Dilithium3', type: 'PQC' },
    { name: 'SPHINCS+', type: 'PQC' },
    { name: 'AES-GCM', keySize: 256 }
  ];

  const run1 = buildMerkleTree(components);
  const run2 = buildMerkleTree(components);
  const run3 = buildMerkleTree(components);

  assert.deepStrictEqual(run1, run2, 'Run 1 and Run 2 must be identical');
  assert.deepStrictEqual(run2, run3, 'Run 2 and Run 3 must be identical');
  console.log('✓ Test 10 Passed: Determinism guaranteed across repeated runs');
}

// ---------------------------------------------------------------------------
// Test 11: Swapping two sibling hashes does not change the parent (sorted-pair hashing)
// ---------------------------------------------------------------------------
{
  const hash1 = '1111111111111111111111111111111111111111111111111111111111111111';
  const hash2 = '2222222222222222222222222222222222222222222222222222222222222222';

  const parent1 = hashPair(hash1, hash2);
  const parent2 = hashPair(hash2, hash1);

  assert.strictEqual(parent1, parent2, 'hashPair must be commutative due to sorted-pair hashing');

  // Verify at tree level with 2 components
  const compX = { asset: 'A' };
  const compY = { asset: 'B' };

  const treeXY = buildMerkleTree([compX, compY]);
  const treeYX = buildMerkleTree([compY, compX]);

  assert.strictEqual(treeXY.root, treeYX.root, 'Roots of 2-leaf tree must match when leaves are swapped');
  console.log('✓ Test 11 Passed: Sorted-pair hashing ensures sibling swap produces same parent');
}

// ---------------------------------------------------------------------------
// Test 12: Root and leaves are 64-character lowercase hexadecimal SHA-256 values
// ---------------------------------------------------------------------------
{
  const sha256HexRegex = /^[0-9a-f]{64}$/;

  const comps = [
    { primitive: 'RSA', keyLength: 2048 },
    { primitive: 'ECDH', curve: 'secp256r1' },
    { primitive: 'SHA256' }
  ];

  const result = buildMerkleTree(comps);

  assert.match(result.root, sha256HexRegex, 'Root must be a 64-character lowercase hex string');
  assert.strictEqual(result.root.length, 64);
  assert.strictEqual(result.root, result.root.toLowerCase());

  for (const leaf of result.leaves) {
    assert.match(leaf, sha256HexRegex, 'Each leaf must be a 64-character lowercase hex string');
    assert.strictEqual(leaf.length, 64);
    assert.strictEqual(leaf, leaf.toLowerCase());
  }

  for (const level of result.tree) {
    for (const node of level) {
      assert.match(node, sha256HexRegex, 'Every node in tree must be a 64-character lowercase hex string');
    }
  }
  console.log('✓ Test 12 Passed: Root and all nodes are 64-character lowercase hexadecimal SHA-256 values');
}

// ---------------------------------------------------------------------------
// Test 13: Input immutability (components are never mutated)
// ---------------------------------------------------------------------------
{
  const originalComp = {
    name: 'AES',
    tags: ['symmetric', 'block-cipher'],
    meta: { active: true }
  };
  const snapshot = JSON.stringify(originalComp);
  const inputList = [originalComp];

  buildMerkleTree(inputList);

  assert.strictEqual(JSON.stringify(originalComp), snapshot, 'Component object must not be mutated');
  assert.strictEqual(inputList.length, 1, 'Input components array must not be mutated');
  console.log('✓ Test 13 Passed: Input components and arrays are not mutated');
}

// ===========================================================================
// STEP 2 TESTS (14 - 23): MERKLE PROOF GENERATION & VERIFICATION
// ===========================================================================

// ---------------------------------------------------------------------------
// Test 14 (Test A): Two leaves proof generation and verification
// ---------------------------------------------------------------------------
{
  const compA = { name: 'AES-GCM', keySize: 256 };
  const compB = { name: 'ChaCha20-Poly1305' };
  const result = buildMerkleTree([compA, compB]);

  // Leaf 0 (compA)
  const proofA = getProof(result.tree, 0);
  assert.strictEqual(proofA.length, 1);
  assert.strictEqual(proofA[0].sibling, result.leaves[1]);
  assert.strictEqual(proofA[0].position, 'right');
  assert.strictEqual(verifyProof(result.leaves[0], proofA, result.root), true);

  // Leaf 1 (compB)
  const proofB = getProof(result.tree, 1);
  assert.strictEqual(proofB.length, 1);
  assert.strictEqual(proofB[0].sibling, result.leaves[0]);
  assert.strictEqual(proofB[0].position, 'left');
  assert.strictEqual(verifyProof(result.leaves[1], proofB, result.root), true);

  console.log('✓ Test 14 Passed: Test A — Two leaves generate correct proofs and verify successfully');
}

// ---------------------------------------------------------------------------
// Test 15 (Test B): Four leaves proof generation and verification
// ---------------------------------------------------------------------------
{
  const comps = [
    { name: 'RSA-2048' },
    { name: 'ECDSA-P384' },
    { name: 'Ed25519' },
    { name: 'ML-DSA-65' },
  ];
  const result = buildMerkleTree(comps);

  assert.strictEqual(result.leaves.length, 4);

  for (let i = 0; i < comps.length; i++) {
    const proof = getProof(result.tree, i);
    assert.strictEqual(proof.length, 2, `Proof for leaf ${i} in 4-leaf tree must have length 2`);
    const valid = verifyProof(result.leaves[i], proof, result.root);
    assert.strictEqual(valid, true, `Proof verification failed for leaf index ${i}`);
  }

  // Specific position checks for 4 leaves:
  // Leaf 0: sibling leaf 1 (right), parent sibling P1 (right)
  const proof0 = getProof(result.tree, 0);
  assert.strictEqual(proof0[0].sibling, result.leaves[1]);
  assert.strictEqual(proof0[0].position, 'right');
  assert.strictEqual(proof0[1].sibling, result.tree[1][1]);
  assert.strictEqual(proof0[1].position, 'right');

  // Leaf 1: sibling leaf 0 (left), parent sibling P1 (right)
  const proof1 = getProof(result.tree, 1);
  assert.strictEqual(proof1[0].sibling, result.leaves[0]);
  assert.strictEqual(proof1[0].position, 'left');
  assert.strictEqual(proof1[1].sibling, result.tree[1][1]);
  assert.strictEqual(proof1[1].position, 'right');

  // Leaf 2: sibling leaf 3 (right), parent sibling P0 (left)
  const proof2 = getProof(result.tree, 2);
  assert.strictEqual(proof2[0].sibling, result.leaves[3]);
  assert.strictEqual(proof2[0].position, 'right');
  assert.strictEqual(proof2[1].sibling, result.tree[1][0]);
  assert.strictEqual(proof2[1].position, 'left');

  // Leaf 3: sibling leaf 2 (left), parent sibling P0 (left)
  const proof3 = getProof(result.tree, 3);
  assert.strictEqual(proof3[0].sibling, result.leaves[2]);
  assert.strictEqual(proof3[0].position, 'left');
  assert.strictEqual(proof3[1].sibling, result.tree[1][0]);
  assert.strictEqual(proof3[1].position, 'left');

  console.log('✓ Test 15 Passed: Test B — Four leaves generate correct proofs and all verify successfully');
}

// ---------------------------------------------------------------------------
// Test 16 (Test C): Three leaves (Odd-node duplicate-last-node handling)
// ---------------------------------------------------------------------------
{
  const comps = [
    { id: 'asset-alpha' },
    { id: 'asset-beta' },
    { id: 'asset-gamma' },
  ];
  const result = buildMerkleTree(comps);

  assert.strictEqual(result.leaves.length, 3);

  for (let i = 0; i < comps.length; i++) {
    const proof = getProof(result.tree, i);
    assert.strictEqual(proof.length, 2, `Proof for leaf ${i} in 3-leaf tree must have length 2`);
    const valid = verifyProof(result.leaves[i], proof, result.root);
    assert.strictEqual(valid, true, `Proof verification failed for leaf index ${i}`);
  }

  // Pay special attention to leaf 2 (the duplicated odd node)
  const proof2 = getProof(result.tree, 2);
  // Sibling at level 0 must be itself (duplicated node) on the right
  assert.strictEqual(proof2[0].sibling, result.leaves[2]);
  assert.strictEqual(proof2[0].position, 'right');
  // Sibling at level 1 must be parent 0 (hashPair(leaves[0], leaves[1])) on the left
  const expectedP0 = hashPair(result.leaves[0], result.leaves[1]);
  assert.strictEqual(proof2[1].sibling, expectedP0);
  assert.strictEqual(proof2[1].position, 'left');

  console.log('✓ Test 16 Passed: Test C — Three leaves handle duplicated odd node and all verify');
}

// ---------------------------------------------------------------------------
// Test 17 (Test D): Five leaves (Odd-node handling at multiple levels)
// ---------------------------------------------------------------------------
{
  const comps = [
    { name: 'C1' },
    { name: 'C2' },
    { name: 'C3' },
    { name: 'C4' },
    { name: 'C5' },
  ];
  const result = buildMerkleTree(comps);

  assert.strictEqual(result.leaves.length, 5);
  // Level 0: 5 leaves (odd)
  // Level 1: 3 parents (odd)
  // Level 2: 2 nodes
  // Level 3: 1 root
  assert.strictEqual(result.tree.length, 4);

  for (let i = 0; i < comps.length; i++) {
    const proof = getProof(result.tree, i);
    assert.strictEqual(proof.length, 3, `Proof for leaf ${i} in 5-leaf tree must have length 3`);
    const valid = verifyProof(result.leaves[i], proof, result.root);
    assert.strictEqual(valid, true, `Proof verification failed for leaf ${i} in 5-leaf tree`);
  }

  // Verify odd node leaf 4 specifically:
  const proof4 = getProof(result.tree, 4);
  // Level 0 sibling: duplicated leaf 4 on the right
  assert.strictEqual(proof4[0].sibling, result.leaves[4]);
  assert.strictEqual(proof4[0].position, 'right');
  // Level 1 sibling: duplicated parent 2 (hashPair(leaf4, leaf4)) on the right
  assert.strictEqual(proof4[1].sibling, result.tree[1][2]);
  assert.strictEqual(proof4[1].position, 'right');
  // Level 2 sibling: node 0 of level 2 on the left
  assert.strictEqual(proof4[2].sibling, result.tree[2][0]);
  assert.strictEqual(proof4[2].position, 'left');

  console.log('✓ Test 17 Passed: Test D — Five leaves with multi-level odd nodes all verify');
}

// ---------------------------------------------------------------------------
// Test 18 (Test E): Single leaf tree
// ---------------------------------------------------------------------------
{
  const comp = { name: 'SingleCryptoAsset' };
  const result = buildMerkleTree([comp]);

  const proof = getProof(result.tree, 0);
  assert.deepStrictEqual(proof, [], 'Proof for a single leaf tree must be an empty array');

  // verifyProof(leaf, [], leaf) === true
  assert.strictEqual(verifyProof(result.leaves[0], [], result.root), true);

  // verifyProof with wrong root returns false
  const fakeRoot = '00'.repeat(32);
  assert.strictEqual(verifyProof(result.leaves[0], [], fakeRoot), false);

  console.log('✓ Test 18 Passed: Test E — Single leaf produces empty proof and verifies successfully');
}

// ---------------------------------------------------------------------------
// Test 19 (Test F): Tampering tests (All 8 scenarios)
// ---------------------------------------------------------------------------
{
  const comps = [
    { name: 'KEM', algo: 'ML-KEM-768' },
    { name: 'Sig', algo: 'ML-DSA-65' },
    { name: 'Enc', algo: 'AES-256-GCM' },
    { name: 'Hash', algo: 'SHA-384' },
  ];
  const result = buildMerkleTree(comps);
  const targetIndex = 1;
  const targetLeaf = result.leaves[targetIndex];
  const targetProof = getProof(result.tree, targetIndex);
  const root = result.root;

  // 1. Valid proof returns true
  assert.strictEqual(verifyProof(targetLeaf, targetProof, root), true, 'Scenario 1: Valid proof must return true');

  // 2. Wrong leaf returns false
  const fakeLeaf = 'ff'.repeat(32);
  assert.strictEqual(verifyProof(fakeLeaf, targetProof, root), false, 'Scenario 2: Wrong leaf must return false');

  // 3. Wrong root returns false
  const fakeRoot = 'ee'.repeat(32);
  assert.strictEqual(verifyProof(targetLeaf, targetProof, fakeRoot), false, 'Scenario 3: Wrong root must return false');

  // 4. Modified sibling hash returns false
  const tamperedProof = targetProof.map((step, idx) => {
    if (idx === 0) {
      // Flip the first character of the sibling hash
      const flipped = (step.sibling[0] === 'a' ? 'b' : 'a') + step.sibling.slice(1);
      return { sibling: flipped, position: step.position };
    }
    return { ...step };
  });
  assert.strictEqual(verifyProof(targetLeaf, tamperedProof, root), false, 'Scenario 4: Modified sibling hash must return false');

  // 5. Removing a proof element returns false
  const shortenedProof = targetProof.slice(0, -1);
  assert.strictEqual(verifyProof(targetLeaf, shortenedProof, root), false, 'Scenario 5: Shortened proof must return false');

  // 6. Adding an extra proof element returns false
  const extendedProof = [...targetProof, { sibling: 'dd'.repeat(32), position: 'right' }];
  assert.strictEqual(verifyProof(targetLeaf, extendedProof, root), false, 'Scenario 6: Extended proof must return false');

  // 7. Proof from one leaf cannot verify a different leaf
  const otherLeaf = result.leaves[2];
  assert.strictEqual(verifyProof(otherLeaf, targetProof, root), false, 'Scenario 7: Cross-leaf verification must return false');

  // 8. Proof from one Merkle tree cannot verify against a different root
  const otherTreeResult = buildMerkleTree([
    { name: 'Completely' },
    { name: 'Different' },
    { name: 'Tree' },
    { name: 'Components' },
  ]);
  assert.strictEqual(
    verifyProof(targetLeaf, targetProof, otherTreeResult.root),
    false,
    'Scenario 8: Proof against different tree root must return false'
  );

  console.log('✓ Test 19 Passed: Test F — All 8 tampering scenarios correctly detected and rejected');
}

// ---------------------------------------------------------------------------
// Test 20: Determinism of proof generation
// ---------------------------------------------------------------------------
{
  const comps = [
    { id: 1, type: 'cipher' },
    { id: 2, type: 'hash' },
    { id: 3, type: 'mac' },
  ];
  const result = buildMerkleTree(comps);

  const proof1 = getProof(result.tree, 1);
  const proof2 = getProof(result.tree, 1);
  const proof3 = getProof(result.tree, 1);

  assert.deepStrictEqual(proof1, proof2, 'Consecutive proof calls must return identical objects');
  assert.deepStrictEqual(proof2, proof3, 'Consecutive proof calls must return identical objects');

  console.log('✓ Test 20 Passed: Proof generation is strictly deterministic');
}

// ---------------------------------------------------------------------------
// Test 21: getProof input validation
// ---------------------------------------------------------------------------
{
  const comps = [{ a: 1 }, { b: 2 }];
  const result = buildMerkleTree(comps);

  // Invalid tree
  assert.throws(() => getProof(null, 0), Error);
  assert.throws(() => getProof([], 0), Error);
  assert.throws(() => getProof([[]], 0), Error);
  assert.throws(() => getProof('not-a-tree', 0), Error);

  // Invalid leafIndex
  assert.throws(() => getProof(result.tree, '0'), TypeError);
  assert.throws(() => getProof(result.tree, null), TypeError);
  assert.throws(() => getProof(result.tree, undefined), TypeError);
  assert.throws(() => getProof(result.tree, 1.5), TypeError);
  assert.throws(() => getProof(result.tree, NaN), TypeError);

  // Out of bounds leafIndex
  assert.throws(() => getProof(result.tree, -1), RangeError);
  assert.throws(() => getProof(result.tree, 2), RangeError);
  assert.throws(() => getProof(result.tree, 100), RangeError);

  console.log('✓ Test 21 Passed: getProof rejects invalid trees and out-of-bounds indexes');
}

// ---------------------------------------------------------------------------
// Test 22: verifyProof input validation
// ---------------------------------------------------------------------------
{
  const validHash = 'aa'.repeat(32);
  const validProof = [{ sibling: validHash, position: 'left' }];

  // Invalid leaf
  assert.throws(() => verifyProof(null, validProof, validHash), TypeError);
  assert.throws(() => verifyProof('short-hash', validProof, validHash), TypeError);
  assert.throws(() => verifyProof(validHash.toUpperCase(), validProof, validHash), TypeError);
  assert.throws(() => verifyProof('zz'.repeat(32), validProof, validHash), TypeError);

  // Invalid root
  assert.throws(() => verifyProof(validHash, validProof, null), TypeError);
  assert.throws(() => verifyProof(validHash, validProof, '1234'), TypeError);
  assert.throws(() => verifyProof(validHash, validProof, validHash.toUpperCase()), TypeError);

  // Invalid proof
  assert.throws(() => verifyProof(validHash, null, validHash), TypeError);
  assert.throws(() => verifyProof(validHash, 'not-an-array', validHash), TypeError);
  assert.throws(() => verifyProof(validHash, [null], validHash), TypeError);
  assert.throws(() => verifyProof(validHash, [{ sibling: 'short', position: 'left' }], validHash), TypeError);
  assert.throws(() => verifyProof(validHash, [{ sibling: validHash, position: 'middle' }], TypeError));

  console.log('✓ Test 22 Passed: verifyProof rejects malformed inputs with TypeError');
}

// ---------------------------------------------------------------------------
// Test 23: Independent verification without buildMerkleTree or CBOM
// ---------------------------------------------------------------------------
{
  // Simulated verification environment: verifier only receives strings and proof
  const leaf = '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945';
  const sibling0 = 'a8f08c352ef89fb09a15a0c3bb20e5414f52636a08ec4f51bc739097e33a652e';
  const sibling1 = '3b18428236d89d4d82a1740fb08594eb2f8c544d67364653db3c647b0e27c15e';

  const expectedParent0 = hashPair(leaf, sibling0);
  const expectedRoot = hashPair(expectedParent0, sibling1);

  const standaloneProof = [
    { sibling: sibling0, position: 'right' },
    { sibling: sibling1, position: 'left' }
  ];

  // verifyProof verifies correctly without buildMerkleTree() or component objects
  const verified = verifyProof(leaf, standaloneProof, expectedRoot);
  assert.strictEqual(verified, true, 'Standalone verification must succeed');

  // Verify that position field alone is not blindly trusted (sorted-pair hashing is respected)
  const flippedPositionProof = [
    { sibling: sibling0, position: 'left' },
    { sibling: sibling1, position: 'right' }
  ];
  const stillVerified = verifyProof(leaf, flippedPositionProof, expectedRoot);
  assert.strictEqual(stillVerified, true, 'Sorted-pair hashing verifies regardless of position metadata');

  console.log('✓ Test 23 Passed: verifyProof works independently without full tree or CBOM');
}

console.log('\nAll 23 tests passed successfully!');
