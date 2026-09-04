'use strict';

const assert = require('assert');
const crypto = require('crypto');
const {
  buildBatchMerkleTree,
  computeScanLeaf,
  getBatchProof,
  verifyBatchProof,
  sortScanBatch,
} = require('./merkle');

function makeScan(id, content, orgId = 'org-default', version = '1.0.0') {
  const root = crypto.createHash('sha256').update(content).digest('hex');
  return {
    scanId: id,
    merkleRoot: root,
    orgId,
    scannerVersion: version,
  };
}

console.log('Running Batch Merkle Tree Test Suite (Person 5 Phase 8)...\n');

// ---------------------------------------------------------------------------
// 1. Single-Item Batch
// ---------------------------------------------------------------------------
{
  const scan = makeScan('scan-single', 'single-cbom-components');
  const batch = buildBatchMerkleTree([scan]);

  assert.strictEqual(batch.scans.length, 1);
  assert.strictEqual(batch.leaves.length, 1);
  assert.strictEqual(typeof batch.batchRoot, 'string');
  assert.strictEqual(batch.batchRoot.length, 64);
  assert.strictEqual(batch.batchRootHex, '0x' + batch.batchRoot);

  // For a single scan, batch root equals its single leaf
  const expectedLeaf = computeScanLeaf(scan);
  assert.strictEqual(batch.batchRoot, expectedLeaf);

  // Single-item proof is empty array and verifies
  const proofResult = getBatchProof(batch, 'scan-single');
  assert.deepStrictEqual(proofResult.proof, []);
  assert.strictEqual(verifyBatchProof(scan, proofResult.proof, batch.batchRoot), true);

  console.log('✓ Test 1 Passed: Single-item batch builds root and verifies with empty proof');
}

// ---------------------------------------------------------------------------
// 2. Multiple Scans (Even & Odd Counts)
// ---------------------------------------------------------------------------
{
  const scans2 = [
    makeScan('scan-02', 'components-b'),
    makeScan('scan-01', 'components-a'),
  ];
  const batch2 = buildBatchMerkleTree(scans2);
  assert.strictEqual(batch2.scans.length, 2);
  assert.strictEqual(batch2.leaves.length, 2);
  assert.strictEqual(batch2.tree.length, 2); // leaves level + root level

  const scans3 = [
    makeScan('scan-03', 'components-c'),
    makeScan('scan-01', 'components-a'),
    makeScan('scan-02', 'components-b'),
  ];
  const batch3 = buildBatchMerkleTree(scans3);
  assert.strictEqual(batch3.scans.length, 3);
  assert.strictEqual(batch3.leaves.length, 3);
  assert.strictEqual(batch3.tree.length, 3); // 3 leaves -> 2 parents -> 1 root

  console.log('✓ Test 2 Passed: Multiple scans (even and odd counts) build valid Merkle trees');
}

// ---------------------------------------------------------------------------
// 3. Deterministic Root Regardless of Input Ordering & Repeated Generation
// ---------------------------------------------------------------------------
{
  const s1 = makeScan('scan-alpha', 'content-1');
  const s2 = makeScan('scan-beta', 'content-2');
  const s3 = makeScan('scan-gamma', 'content-3');
  const s4 = makeScan('scan-delta', 'content-4');

  const orderA = [s1, s2, s3, s4];
  const orderB = [s4, s2, s1, s3];
  const orderC = [s3, s1, s4, s2];

  const batchA = buildBatchMerkleTree(orderA);
  const batchB = buildBatchMerkleTree(orderB);
  const batchC = buildBatchMerkleTree(orderC);

  assert.strictEqual(batchA.batchRoot, batchB.batchRoot);
  assert.strictEqual(batchB.batchRoot, batchC.batchRoot);

  // Repeated runs produce identical roots
  const batchA2 = buildBatchMerkleTree(orderA);
  assert.strictEqual(batchA.batchRoot, batchA2.batchRoot);

  // Scans in result are sorted deterministically
  assert.deepStrictEqual(
    batchA.scans.map((s) => s.scanId),
    ['scan-alpha', 'scan-beta', 'scan-delta', 'scan-gamma']
  );

  console.log('✓ Test 3 Passed: Deterministic batch root regardless of input order or repeat runs');
}

// ---------------------------------------------------------------------------
// 4. Proof Generation for Every Included Scan
// ---------------------------------------------------------------------------
{
  const scans = [
    makeScan('scan-a', 'data-a'),
    makeScan('scan-b', 'data-b'),
    makeScan('scan-c', 'data-c'),
    makeScan('scan-d', 'data-d'),
    makeScan('scan-e', 'data-e'),
  ];
  const batch = buildBatchMerkleTree(scans);

  for (const s of scans) {
    const proofRes = getBatchProof(batch, s.scanId);
    assert.strictEqual(proofRes.scanId, s.scanId);
    assert.strictEqual(proofRes.batchRoot, batch.batchRoot);
    assert.ok(Array.isArray(proofRes.proof));
    assert.ok(proofRes.proof.length > 0);
    assert.strictEqual(proofRes.leaf, computeScanLeaf(s));
  }

  // Non-existent scanId throws
  assert.throws(() => getBatchProof(batch, 'non-existent-scan'), /not found/);

  console.log('✓ Test 4 Passed: Proofs generated correctly for all scans in batch');
}

// ---------------------------------------------------------------------------
// 5. Valid Proof Independent Verification
// ---------------------------------------------------------------------------
{
  const scans = [
    makeScan('scan-10', 'payload-10'),
    makeScan('scan-20', 'payload-20'),
    makeScan('scan-30', 'payload-30'),
    makeScan('scan-40', 'payload-40'),
  ];
  const batch = buildBatchMerkleTree(scans);

  for (const s of scans) {
    const proofRes = getBatchProof(batch, s.scanId);

    // Verify independently with plain hex root and 0x hex root
    const valid1 = verifyBatchProof(s, proofRes.proof, batch.batchRoot);
    const valid2 = verifyBatchProof(s, proofRes.proof, batch.batchRootHex);
    assert.strictEqual(valid1, true);
    assert.strictEqual(valid2, true);
  }

  console.log('✓ Test 5 Passed: Valid proofs verified independently without trusting builder');
}

// ---------------------------------------------------------------------------
// 6. Invalid / Corrupted Proof Rejection
// ---------------------------------------------------------------------------
{
  const scans = [
    makeScan('scan-01', 'payload-01'),
    makeScan('scan-02', 'payload-02'),
    makeScan('scan-03', 'payload-03'),
  ];
  const batch = buildBatchMerkleTree(scans);
  const proofRes = getBatchProof(batch, 'scan-02');

  // Tamper sibling in proof
  const corruptedProof = proofRes.proof.map((step, idx) => {
    if (idx === 0) {
      const tamperedSibling = step.sibling.slice(0, -2) + 'ff';
      return { ...step, sibling: tamperedSibling };
    }
    return step;
  });

  const valid = verifyBatchProof(scans[1], corruptedProof, batch.batchRoot);
  assert.strictEqual(valid, false);

  // Empty/truncated proof for multi-leaf tree fails
  const truncatedProof = proofRes.proof.slice(1);
  assert.strictEqual(verifyBatchProof(scans[1], truncatedProof, batch.batchRoot), false);

  console.log('✓ Test 6 Passed: Corrupted and truncated proofs fail verification');
}

// ---------------------------------------------------------------------------
// 7. Modified Leaf / Root Rejection
// ---------------------------------------------------------------------------
{
  const scans = [
    makeScan('scan-x', 'x-content'),
    makeScan('scan-y', 'y-content'),
  ];
  const batch = buildBatchMerkleTree(scans);
  const proofRes = getBatchProof(batch, 'scan-x');

  // Modified scanId
  const tamperedScanId = { ...scans[0], scanId: 'scan-x-tampered' };
  assert.strictEqual(verifyBatchProof(tamperedScanId, proofRes.proof, batch.batchRoot), false);

  // Modified merkleRoot
  const tamperedRoot = {
    ...scans[0],
    merkleRoot: '0000000000000000000000000000000000000000000000000000000000000000',
  };
  assert.strictEqual(verifyBatchProof(tamperedRoot, proofRes.proof, batch.batchRoot), false);

  // Modified batch root
  const fakeBatchRoot = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
  assert.strictEqual(verifyBatchProof(scans[0], proofRes.proof, fakeBatchRoot), false);

  console.log('✓ Test 7 Passed: Modified scan record, leaf, or root strictly rejected');
}

// ---------------------------------------------------------------------------
// 8. Batch Tampering Detection: Any Change Changes the Entire Batch Root
// ---------------------------------------------------------------------------
{
  const originalScans = [
    makeScan('s1', 'c1'),
    makeScan('s2', 'c2'),
    makeScan('s3', 'c3'),
    makeScan('s4', 'c4'),
  ];
  const originalBatch = buildBatchMerkleTree(originalScans);

  // Modifying even 1 bit in 1 scan's root changes the batch root
  const modifiedScans = [
    makeScan('s1', 'c1'),
    makeScan('s2', 'c2-tampered'),
    makeScan('s3', 'c3'),
    makeScan('s4', 'c4'),
  ];
  const modifiedBatch = buildBatchMerkleTree(modifiedScans);
  assert.notStrictEqual(originalBatch.batchRoot, modifiedBatch.batchRoot);

  // Adding a scan changes the batch root
  const extraScans = [...originalScans, makeScan('s5', 'c5')];
  const extraBatch = buildBatchMerkleTree(extraScans);
  assert.notStrictEqual(originalBatch.batchRoot, extraBatch.batchRoot);

  console.log('✓ Test 8 Passed: Any batch input tampering produces distinct batch root');
}

// ---------------------------------------------------------------------------
// 9. Input Validation & Error Handling
// ---------------------------------------------------------------------------
{
  assert.throws(() => buildBatchMerkleTree([]), /empty scans array/);
  assert.throws(() => buildBatchMerkleTree(null), /must be an array/);
  assert.throws(() => buildBatchMerkleTree([{}]), /TypeError/);
  assert.throws(() => buildBatchMerkleTree([{ scanId: '1', merkleRoot: 'invalid' }]), /invalid merkleRoot/);

  console.log('✓ Test 9 Passed: Invalid batch inputs throw expected TypeErrors');
}

console.log('\nAll 9 Batch Merkle Tree test suites passed successfully!');
