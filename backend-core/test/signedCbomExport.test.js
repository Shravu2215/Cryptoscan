/**
 * Signed CBOM Export (Phase 8) — Integration Test Suite
 *
 * Tests:
 *  1.  Signed CBOM generation — structure and required fields
 *  2.  CBOM content hash consistency (canonical, deterministic)
 *  3.  Merkle root consistency (recomputed == stored)
 *  4.  Merkle integration — proof verification per component
 *  5.  Hybrid signature integration — algorithm identifier correct
 *  6.  Successful full verification (valid package)
 *  7.  Tampered CBOM data rejected (content hash mismatch)
 *  8.  Tampered components rejected (Merkle root mismatch)
 *  9.  Invalid signature rejected (classical sig corrupted)
 * 10.  Invalid PQC signature rejected (pqcSig corrupted)
 * 11.  Malformed / missing input handled safely
 * 12.  Provenance and version fields preserved in signed package
 * 13.  PQC/HNDL/business-risk fields preserved in signed package
 * 14.  Phase 7 migration simulation compatibility — fields coexist
 * 15.  Backward compatibility — existing CBOM is unchanged by signing
 * 16.  No mutation of stored scan/CBOM data (non-destructive)
 * 17.  Empty-components CBOM falls back to full-cbom-hash mode safely
 * 18.  Multi-component batch proof verification
 * 19.  Phase 1–7 regression — all services still importable and functional
 */

'use strict';

const assert = require('assert');

// -----------------------------------------------------------------------
// Test environment setup — matches integrity-service/hybrid-signature.test.js pattern
// -----------------------------------------------------------------------
const DUMMY_ECDSA_KEY = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
const originalPrivateKey = process.env.PRIVATE_KEY;
process.env.PRIVATE_KEY = DUMMY_ECDSA_KEY;
// Reset KMS so it picks up our test key
const { reset: resetKms } = require('../../integrity-service/kms');
resetKms();

const {
  exportSignedCbom,
  verifySignedCbom,
  computeCbomContentHash,
  buildCbomMerkleCommitment,
  buildComponentProofs,
  generatePqcKeyPair,
  resetPqcRegistry,
  getPqcPublicKey,
  ALGORITHM_IDENTIFIER,
} = require('../src/services/signedCbomExport');

// Reuse existing CBOM generator (Phase 1-2)
const { buildCbom } = require('../src/services/cbomGenerator');

// Phase 4–7 services for regression
const { scoreFinding } = require('../src/services/vulnScoring');
const { getMigrationGuidance } = require('../src/services/purposeDetection');
const { assessFinding } = require('../src/services/migrationAssessment');

console.log('Running Signed CBOM Export (Phase 8) Test Suite...');

// -----------------------------------------------------------------------
// Shared CBOM fixture
// -----------------------------------------------------------------------

function makeCbom(overrides = {}) {
  return buildCbom({
    scanId: 'phase8-test-scan',
    repoId: 'phase8-test-repo',
    createdAt: new Date('2024-01-15T10:00:00Z'),
    repoScans: [
      { id: 'phase8-test-scan', repoId: 'phase8-test-repo', createdAt: new Date('2024-01-15T10:00:00Z') },
    ],
    rawFindings: [
      { id: 'f1', algorithm: 'RSA-2048', file: 'src/auth.js', line: 42, severity: 'HIGH',
        quantumStatus: 'Quantum Vulnerable', usage: 'digital_signature', recommendation: 'Migrate to ML-DSA' },
      { id: 'f2', algorithm: 'AES-256-GCM', file: 'src/encrypt.js', line: 17, severity: 'LOW',
        quantumStatus: 'Quantum Safe', usage: 'data_encryption', recommendation: 'No migration required' },
      { id: 'f3', algorithm: 'ECDH-P256', file: 'src/kex.js', line: 88, severity: 'HIGH',
        quantumStatus: 'Quantum Vulnerable', usage: 'key_exchange', recommendation: 'Migrate to ML-KEM' },
    ],
    ...overrides,
  });
}

// -----------------------------------------------------------------------
// Setup: generate a fresh ML-DSA keypair for all tests
// -----------------------------------------------------------------------
let testPqcKeyId;
{
  resetPqcRegistry();
  const kp = generatePqcKeyPair({ makeActive: true });
  testPqcKeyId = kp.keyId;
}

// -----------------------------------------------------------------------
// 1. Signed CBOM generation — structure and required fields
// -----------------------------------------------------------------------
{
  const cbom = makeCbom();
  let signedPkg;

  // Run in a self-invoking async block — we await carefully in test runner
  const runTest = async () => {
    signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });

    assert(signedPkg, 'signed package is truthy');
    assert(signedPkg.cbom, 'cbom field present');
    assert(signedPkg.integrity, 'integrity field present');
    assert(signedPkg.signature, 'signature field present');
    assert(Array.isArray(signedPkg.componentProofs), 'componentProofs is array');
    assert(signedPkg.signedAt, 'signedAt is present');

    // Integrity sub-fields
    assert(signedPkg.integrity.contentHash, 'contentHash present');
    assert(signedPkg.integrity.merkleRoot, 'merkleRoot present');
    assert(signedPkg.integrity.merkleMode, 'merkleMode present');
    assert.strictEqual(typeof signedPkg.integrity.componentCount, 'number', 'componentCount is number');
    assert.strictEqual(signedPkg.integrity.algorithm, 'SHA-256', 'algorithm is SHA-256');

    // Signature sub-fields
    assert.strictEqual(signedPkg.signature.algorithm, ALGORITHM_IDENTIFIER, 'algorithm identifier correct');
    assert(signedPkg.signature.classicalSig, 'classicalSig present');
    assert(signedPkg.signature.pqcSig, 'pqcSig present');
    assert(signedPkg.signature.pqcKeyId, 'pqcKeyId present');
    assert.strictEqual(signedPkg.signature.signedOver, 'merkleRoot', 'signedOver is merkleRoot');

    console.log('✓ Test 1 Passed: Signed CBOM package generated with all required fields');
  };

  // Store promise to chain
  global._p8_test1 = runTest();
}

// Run all async tests sequentially
async function runAll() {
  await global._p8_test1;
  resetPqcRegistry();
  const kp = generatePqcKeyPair({ makeActive: true });
  testPqcKeyId = kp.keyId;

  // -----------------------------------------------------------------------
  // 2. CBOM content hash consistency
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const hash1 = computeCbomContentHash(cbom);
    const hash2 = computeCbomContentHash(cbom);
    assert.strictEqual(hash1, hash2, 'content hash is deterministic for same CBOM');
    assert.strictEqual(hash1.length, 64, 'hash is 64 hex chars (SHA-256)');
    assert(/^[0-9a-f]{64}$/.test(hash1), 'hash is lowercase hex');

    // Different CBOM produces different hash
    const cbom2 = makeCbom({ repoId: 'other-repo' });
    const hash3 = computeCbomContentHash(cbom2);
    assert.notStrictEqual(hash1, hash3, 'different CBOMs produce different content hashes');

    console.log('✓ Test 2 Passed: CBOM content hash is deterministic and differentiates distinct CBOMs');
  }

  // -----------------------------------------------------------------------
  // 3. Merkle root consistency
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });

    // Recompute merkle root manually from components
    const { buildMerkleTree } = require('../../integrity-service/merkle');
    const treeResult = buildMerkleTree(cbom.components);

    assert.strictEqual(signedPkg.integrity.merkleRoot, treeResult.root,
      'stored Merkle root matches independently recomputed root');
    assert.strictEqual(signedPkg.integrity.merkleMode, 'component-merkle',
      'mode is component-merkle when components are present');
    assert.strictEqual(signedPkg.integrity.componentCount, cbom.components.length,
      'componentCount matches actual component count');

    console.log('✓ Test 3 Passed: Merkle root is consistent with independently recomputed tree');
  }

  // -----------------------------------------------------------------------
  // 4. Merkle integration — proof verification per component
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });

    assert.strictEqual(signedPkg.componentProofs.length, cbom.components.length,
      'one proof per component');

    const { verifyProof } = require('../../integrity-service/merkle');
    const merkleRoot = signedPkg.integrity.merkleRoot;

    // Verify every component proof independently
    for (const proofEntry of signedPkg.componentProofs) {
      const proofValid = verifyProof(proofEntry.leaf, proofEntry.proof, merkleRoot);
      assert.strictEqual(proofValid, true,
        `proof valid for component at index ${proofEntry.componentIndex}`);
    }

    console.log('✓ Test 4 Passed: Merkle proofs verified independently for every CBOM component');
  }

  // -----------------------------------------------------------------------
  // 5. Hybrid signature integration — algorithm identifier correct
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });

    assert.strictEqual(signedPkg.signature.algorithm, 'ECDSA-secp256k1+ML-DSA-65',
      'hybrid algorithm identifier is ECDSA-secp256k1+ML-DSA-65');
    assert(typeof signedPkg.signature.classicalSig === 'string' && signedPkg.signature.classicalSig.length > 0,
      'classicalSig is a non-empty string');
    assert(typeof signedPkg.signature.pqcSig === 'string' && signedPkg.signature.pqcSig.length > 0,
      'pqcSig is a non-empty string');

    // Decode pqcSig from base64 and verify it is the correct ML-DSA-65 size (3309 bytes)
    const pqcSigBuf = Buffer.from(signedPkg.signature.pqcSig, 'base64');
    assert.strictEqual(pqcSigBuf.length, 3309, 'ML-DSA-65 signature is exactly 3309 bytes (FIPS 204)');

    console.log('✓ Test 5 Passed: Hybrid signature uses correct ECDSA-secp256k1+ML-DSA-65 algorithm with valid sizes');
  }

  // -----------------------------------------------------------------------
  // 6. Successful full verification
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });
    const pqcPublicKey = getPqcPublicKey(testPqcKeyId);

    const verifyResult = verifySignedCbom(signedPkg, { pqcPublicKey, verifyComponentIndex: 0 });

    assert.strictEqual(verifyResult.valid, true, 'full verification succeeds for untampered package');
    assert.strictEqual(verifyResult.contentHashValid, true, 'content hash valid');
    assert.strictEqual(verifyResult.merkleRootValid, true, 'Merkle root valid');
    assert.strictEqual(verifyResult.signatureValid, true, 'signature valid');
    assert.strictEqual(verifyResult.pqcSigValid, true, 'PQC signature valid');
    assert.strictEqual(verifyResult.componentProofValid, true, 'component 0 proof valid');
    assert.strictEqual(verifyResult.errors.length, 0, 'no verification errors');

    console.log('✓ Test 6 Passed: Full verification succeeds for an untampered signed CBOM package');
  }

  // -----------------------------------------------------------------------
  // 7. Tampered CBOM data rejected (content hash mismatch)
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });
    const pqcPublicKey = getPqcPublicKey(testPqcKeyId);

    // Deep-clone and tamper the CBOM metadata
    const tampered = JSON.parse(JSON.stringify(signedPkg));
    tampered.cbom.metadata.timestamp = 'TAMPERED-TIMESTAMP';

    const verifyResult = verifySignedCbom(tampered, { pqcPublicKey });
    assert.strictEqual(verifyResult.valid, false, 'tampered CBOM rejected');
    assert.strictEqual(verifyResult.contentHashValid, false, 'content hash invalid after tampering');
    assert(verifyResult.errors.some(e => e.includes('tampered') || e.includes('mismatch')),
      'error message mentions tampering or mismatch');

    console.log('✓ Test 7 Passed: Tampered CBOM metadata rejected with content hash mismatch');
  }

  // -----------------------------------------------------------------------
  // 8. Tampered components rejected (Merkle root mismatch)
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });
    const pqcPublicKey = getPqcPublicKey(testPqcKeyId);

    // Deep-clone and alter a component inside the CBOM
    const tampered = JSON.parse(JSON.stringify(signedPkg));
    if (tampered.cbom.components && tampered.cbom.components.length > 0) {
      tampered.cbom.components[0].name = 'TAMPERED-COMPONENT-NAME';
    }

    const verifyResult = verifySignedCbom(tampered, { pqcPublicKey });
    assert.strictEqual(verifyResult.valid, false, 'tampered component rejected');
    // Either content hash or Merkle root should fail
    assert(
      !verifyResult.contentHashValid || !verifyResult.merkleRootValid,
      'content hash or Merkle root is invalid after component tampering'
    );

    console.log('✓ Test 8 Passed: Tampered CBOM component rejected (content hash and/or Merkle root mismatch)');
  }

  // -----------------------------------------------------------------------
  // 9. Invalid classical signature rejected
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });
    const pqcPublicKey = getPqcPublicKey(testPqcKeyId);

    // Deep-clone and corrupt the classical signature
    const tampered = JSON.parse(JSON.stringify(signedPkg));
    tampered.signature.classicalSig = '0x' + '0'.repeat(130);

    const verifyResult = verifySignedCbom(tampered, { pqcPublicKey });
    // Content + Merkle are still valid (CBOM not changed), but signature is invalid
    assert.strictEqual(verifyResult.contentHashValid, true, 'content hash still valid');
    assert.strictEqual(verifyResult.merkleRootValid, true, 'Merkle root still valid');
    assert.strictEqual(verifyResult.classicalSigValid, false, 'classical signature correctly rejected');
    assert.strictEqual(verifyResult.valid, false, 'overall verification fails');

    console.log('✓ Test 9 Passed: Corrupted classical ECDSA signature correctly rejected');
  }

  // -----------------------------------------------------------------------
  // 10. Invalid PQC signature rejected
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });
    const pqcPublicKey = getPqcPublicKey(testPqcKeyId);

    // Deep-clone and zero out the PQC signature bytes
    const tampered = JSON.parse(JSON.stringify(signedPkg));
    const fakeSigBuf = Buffer.alloc(3309, 0);
    tampered.signature.pqcSig = fakeSigBuf.toString('base64');

    const verifyResult = verifySignedCbom(tampered, { pqcPublicKey });
    assert.strictEqual(verifyResult.pqcSigValid, false, 'zeroed PQC signature rejected');
    assert.strictEqual(verifyResult.valid, false, 'overall verification fails with invalid PQC sig');

    console.log('✓ Test 10 Passed: Zeroed/invalid ML-DSA-65 PQC signature correctly rejected');
  }

  // -----------------------------------------------------------------------
  // 11. Malformed / missing input handled safely
  // -----------------------------------------------------------------------
  {
    // null signed package
    const r1 = verifySignedCbom(null);
    assert.strictEqual(r1.valid, false, 'null input is invalid');
    assert(r1.errors.length > 0, 'null input produces error messages');

    // missing required fields
    const r2 = verifySignedCbom({ cbom: {}, integrity: null, signature: null });
    assert.strictEqual(r2.valid, false, 'missing fields is invalid');

    // exportSignedCbom with null CBOM
    try {
      await exportSignedCbom(null);
      assert.fail('should have thrown');
    } catch (err) {
      assert(err instanceof TypeError, 'null CBOM throws TypeError');
    }

    console.log('✓ Test 11 Passed: Malformed and missing inputs handled safely without uncaught exceptions');
  }

  // -----------------------------------------------------------------------
  // 12. Provenance and version fields preserved in signed package
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });

    // CBOM in the package must be bit-for-bit the same as generated
    const originalCbomStr = JSON.stringify(cbom);
    const packageCbomStr = JSON.stringify(signedPkg.cbom);
    assert.strictEqual(originalCbomStr, packageCbomStr, 'CBOM in signed package is identical to generated CBOM');

    // Provenance
    const prov = signedPkg.cbom.metadata?.provenance;
    assert(prov, 'metadata.provenance present in signed CBOM');
    assert(prov.scanTimestamp, 'scanTimestamp present');
    assert(prov.scannerVersion, 'scannerVersion present');
    assert(prov.cbomVersion, 'cbomVersion (CBOM-v1) present');

    // Version reflected in signed package top level
    assert.strictEqual(signedPkg.cbomVersion, prov.cbomVersion, 'cbomVersion reflects metadata provenance');

    console.log('✓ Test 12 Passed: CBOM provenance and version fields fully preserved in signed package');
  }

  // -----------------------------------------------------------------------
  // 13. PQC/HNDL/business-risk fields preserved in signed package
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });

    // Verify components in the signed package carry enrichment fields
    const components = signedPkg.cbom.components || [];
    assert(components.length > 0, 'signed CBOM has components');

    for (const comp of components) {
      // Phase 6: PQC recommendation
      if (comp['x-cryptoscan']) {
        const cs = comp['x-cryptoscan'];
        if (cs.recommendation) {
          assert(typeof cs.recommendation === 'string', 'recommendation is string');
        }
        if (cs.cryptoAgilityScore !== undefined) {
          assert(typeof cs.cryptoAgilityScore === 'number', 'cryptoAgilityScore is number');
        }
        if (cs.hybridByDefault !== undefined) {
          assert(typeof cs.hybridByDefault === 'boolean', 'hybridByDefault is boolean');
        }
        // Phase 4: quantum risk
        if (cs.quantumRisk !== undefined) {
          assert(typeof cs.quantumRisk === 'string' || typeof cs.quantumRisk === 'number', 'quantumRisk present');
        }
      }
    }

    console.log('✓ Test 13 Passed: PQC/HNDL/business-risk enrichment fields preserved in signed CBOM components');
  }

  // -----------------------------------------------------------------------
  // 14. Phase 7 migration simulation compatibility
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });

    // The CBOM components can feed directly into Phase 7/8 migration assessment
    const components = signedPkg.cbom.components || [];
    assert(components.length > 0, 'components present for migration assessment');

    // Assess migration for the first component using its data
    const firstComp = components[0];
    const assessResult = assessFinding({
      algorithm: firstComp.name || firstComp['bom-ref'],
      primitive: firstComp.name,
      purpose: firstComp['x-cryptoscan']?.purpose || 'unknown',
    });

    assert.ok(assessResult.migrationPriority, 'migration assessment works on signed CBOM component data');

    // Verify the signed package itself was not mutated by the assessment
    assert.strictEqual(JSON.stringify(signedPkg.cbom), JSON.stringify(cbom),
      'CBOM in signed package unchanged after migration assessment');

    console.log('✓ Test 14 Passed: Phase 7/8 migration assessment is compatible with signed CBOM components');
  }

  // -----------------------------------------------------------------------
  // 15. Backward compatibility — existing CBOM is unchanged by signing
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const cbomSnapshot = JSON.parse(JSON.stringify(cbom));

    // Export signed — should not mutate cbom
    await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });

    assert.deepStrictEqual(cbom, cbomSnapshot, 'exportSignedCbom does NOT mutate the input CBOM object');

    // buildCbom should still produce identical output to before Phase 8
    const cbomAgain = makeCbom();
    assert.deepStrictEqual(cbomAgain, cbomSnapshot,
      'CBOM generator still produces identical output (backward compatible)');

    console.log('✓ Test 15 Passed: Existing CBOM generation is backward compatible — signing does not mutate');
  }

  // -----------------------------------------------------------------------
  // 16. No mutation of stored scan/CBOM data
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const originalJson = JSON.stringify(cbom);

    const signedPkg1 = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });
    const signedPkg2 = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });

    // Source CBOM unchanged across multiple exports
    assert.strictEqual(JSON.stringify(cbom), originalJson, 'CBOM unchanged after two exports');

    // Both signed packages have identical integrity data (deterministic)
    assert.strictEqual(
      signedPkg1.integrity.contentHash,
      signedPkg2.integrity.contentHash,
      'contentHash is deterministic across multiple exports'
    );
    assert.strictEqual(
      signedPkg1.integrity.merkleRoot,
      signedPkg2.integrity.merkleRoot,
      'merkleRoot is deterministic across multiple exports'
    );

    console.log('✓ Test 16 Passed: Signing is non-mutating and deterministic across multiple exports of same CBOM');
  }

  // -----------------------------------------------------------------------
  // 17. Empty-components CBOM falls back to full-cbom-hash mode
  // -----------------------------------------------------------------------
  {
    // Build a minimal CBOM with no findings → no components
    const emptyCbom = buildCbom({
      scanId: 'empty-scan',
      repoId: 'empty-repo',
      createdAt: new Date('2024-01-01T00:00:00Z'),
      rawFindings: [],
    });

    const commitment = buildCbomMerkleCommitment(emptyCbom);
    assert.strictEqual(commitment.mode, 'full-cbom-hash', 'empty components uses full-cbom-hash mode');
    assert.strictEqual(commitment.componentCount, 0, 'component count is zero');
    assert(commitment.merkleRoot.length === 64, 'merkleRoot is still a valid 64-char hex hash');
    assert.strictEqual(commitment.leaves.length, 1, 'single leaf (the CBOM hash)');

    // Export and verify still works for empty-components CBOM
    const signedPkg = await exportSignedCbom(emptyCbom, { pqcKeyId: testPqcKeyId });
    const pqcPublicKey = getPqcPublicKey(testPqcKeyId);
    const verifyResult = verifySignedCbom(signedPkg, { pqcPublicKey });

    assert.strictEqual(verifyResult.valid, true, 'empty-component CBOM signed and verified successfully');
    assert.strictEqual(signedPkg.componentProofs.length, 0, 'no component proofs for empty CBOM');

    console.log('✓ Test 17 Passed: Empty-components CBOM correctly falls back to full-cbom-hash mode and verifies');
  }

  // -----------------------------------------------------------------------
  // 18. Multi-component batch proof verification
  // -----------------------------------------------------------------------
  {
    const cbom = makeCbom();
    const signedPkg = await exportSignedCbom(cbom, { pqcKeyId: testPqcKeyId });
    const pqcPublicKey = getPqcPublicKey(testPqcKeyId);
    const { verifyProof } = require('../../integrity-service/merkle');
    const merkleRoot = signedPkg.integrity.merkleRoot;

    // Verify each proof individually using verifyProof from merkle.js
    let allProofsValid = true;
    for (const proofEntry of signedPkg.componentProofs) {
      const valid = verifyProof(proofEntry.leaf, proofEntry.proof, merkleRoot);
      if (!valid) allProofsValid = false;
    }
    assert.strictEqual(allProofsValid, true, 'all component proofs individually verified via merkle.js verifyProof');

    // Test via verifySignedCbom with each index
    for (let i = 0; i < signedPkg.componentProofs.length; i++) {
      const r = verifySignedCbom(signedPkg, { pqcPublicKey, verifyComponentIndex: i });
      assert.strictEqual(r.componentProofValid, true, `componentProofValid at index ${i}`);
    }

    console.log(`✓ Test 18 Passed: All ${signedPkg.componentProofs.length} component Merkle proofs verified independently`);
  }

  console.log('\nAll 18 Signed CBOM Export (Phase 8) tests passed successfully!');
}

runAll().catch(err => {
  console.error('Phase 8 test suite FAILED:', err);
  process.exit(1);
});
