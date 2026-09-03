/**
 * CBOM Versioning Test Suite (Person 3 — Phase 2)
 *
 * Requirements:
 *  - First scan of a repository = CBOM-v1
 *  - Second scan of the same repository = CBOM-v2
 *  - Third scan of the same repository = CBOM-v3
 *  - Multiple repositories maintain independent version sequences
 *  - Existing repository/scan data remains valid
 *  - Missing/invalid repository identity handled safely
 *  - Provenance and metadata properties correctly expose CBOM version
 */

const assert = require('assert');
const { buildCbom, resolveCbomVersion } = require('../src/services/cbomGenerator');
const { buildMerkleTree } = require('../../integrity-service/merkle');

console.log('Running CBOM Versioning (Phase 2) Test Suite...');

const sampleFinding = {
  id: 'f-v1',
  file: 'src/crypto.js',
  line: 10,
  algorithm: 'AES-256-GCM',
  severity: 'LOW',
  quantumStatus: 'Quantum Safe',
  usage: 'encryption',
};

// ----------------------------------------------------
// 1. First scan of a repository -> CBOM-v1
// ----------------------------------------------------
{
  const repoScans = [
    { id: 'scan-repo1-1', repoId: 'repo-alpha', createdAt: new Date('2026-09-01T10:00:00Z') },
  ];

  const cbom1 = buildCbom({
    scanId: 'scan-repo1-1',
    repoId: 'repo-alpha',
    createdAt: '2026-09-01T10:00:00Z',
    repoScans,
    rawFindings: [sampleFinding],
  });

  assert.strictEqual(cbom1.version, 1, 'First scan has numeric version 1');
  assert.strictEqual(cbom1.cbomVersion, 'CBOM-v1', 'First scan has label CBOM-v1');
  assert.strictEqual(cbom1.provenance.cbomVersion, 'CBOM-v1', 'provenance has CBOM-v1');
  assert.strictEqual(cbom1.provenance.version, 1, 'provenance has numeric version 1');
  assert.strictEqual(cbom1.metadata.provenance.cbomVersion, 'CBOM-v1', 'metadata.provenance has CBOM-v1');

  const verProp = cbom1.metadata.properties.find(p => p.name === 'cbomVersion');
  assert.ok(verProp && verProp.value === 'CBOM-v1', 'metadata.properties contains cbomVersion = CBOM-v1');

  console.log('✓ Test 1 Passed: First scan of a repository yields CBOM-v1');
}

// ----------------------------------------------------
// 2. Second scan of the same repository -> CBOM-v2
// ----------------------------------------------------
{
  const repoScans = [
    { id: 'scan-repo1-1', repoId: 'repo-alpha', createdAt: new Date('2026-09-01T10:00:00Z') },
    { id: 'scan-repo1-2', repoId: 'repo-alpha', createdAt: new Date('2026-09-01T11:00:00Z') },
  ];

  const cbom2 = buildCbom({
    scanId: 'scan-repo1-2',
    repoId: 'repo-alpha',
    createdAt: '2026-09-01T11:00:00Z',
    repoScans,
    rawFindings: [sampleFinding],
  });

  assert.strictEqual(cbom2.version, 2, 'Second scan has numeric version 2');
  assert.strictEqual(cbom2.cbomVersion, 'CBOM-v2', 'Second scan has label CBOM-v2');
  assert.strictEqual(cbom2.provenance.cbomVersion, 'CBOM-v2', 'provenance has CBOM-v2');
  assert.strictEqual(cbom2.provenance.version, 2, 'provenance has numeric version 2');

  console.log('✓ Test 2 Passed: Second scan of the same repository increments to CBOM-v2');
}

// ----------------------------------------------------
// 3. Third scan of the same repository -> CBOM-v3
// ----------------------------------------------------
{
  const repoScans = [
    { id: 'scan-repo1-1', repoId: 'repo-alpha', createdAt: new Date('2026-09-01T10:00:00Z') },
    { id: 'scan-repo1-2', repoId: 'repo-alpha', createdAt: new Date('2026-09-01T11:00:00Z') },
    { id: 'scan-repo1-3', repoId: 'repo-alpha', createdAt: new Date('2026-09-01T12:00:00Z') },
  ];

  const cbom3 = buildCbom({
    scanId: 'scan-repo1-3',
    repoId: 'repo-alpha',
    createdAt: '2026-09-01T12:00:00Z',
    repoScans,
    rawFindings: [sampleFinding],
  });

  assert.strictEqual(cbom3.version, 3, 'Third scan has numeric version 3');
  assert.strictEqual(cbom3.cbomVersion, 'CBOM-v3', 'Third scan has label CBOM-v3');
  assert.strictEqual(cbom3.provenance.cbomVersion, 'CBOM-v3', 'provenance has CBOM-v3');
  assert.strictEqual(cbom3.provenance.version, 3, 'provenance has numeric version 3');

  console.log('✓ Test 3 Passed: Third scan of the same repository increments to CBOM-v3');
}

// ----------------------------------------------------
// 4. Multiple repositories maintain separate version sequences
// ----------------------------------------------------
{
  // repo-alpha has 3 scans
  const repoAlphaScans = [
    { id: 'scan-a1', repoId: 'repo-alpha', createdAt: new Date('2026-09-01T10:00:00Z') },
    { id: 'scan-a2', repoId: 'repo-alpha', createdAt: new Date('2026-09-01T11:00:00Z') },
    { id: 'scan-a3', repoId: 'repo-alpha', createdAt: new Date('2026-09-01T12:00:00Z') },
  ];

  // repo-beta has 2 scans
  const repoBetaScans = [
    { id: 'scan-b1', repoId: 'repo-beta', createdAt: new Date('2026-09-01T10:30:00Z') },
    { id: 'scan-b2', repoId: 'repo-beta', createdAt: new Date('2026-09-01T11:30:00Z') },
  ];

  // repo-gamma has 1 scan
  const repoGammaScans = [
    { id: 'scan-c1', repoId: 'repo-gamma', createdAt: new Date('2026-09-01T12:30:00Z') },
  ];

  // Check repo-beta scan 1
  const cbomB1 = buildCbom({
    scanId: 'scan-b1',
    repoId: 'repo-beta',
    createdAt: '2026-09-01T10:30:00Z',
    repoScans: repoBetaScans,
    rawFindings: [sampleFinding],
  });
  assert.strictEqual(cbomB1.cbomVersion, 'CBOM-v1', 'repo-beta first scan is CBOM-v1');

  // Check repo-beta scan 2
  const cbomB2 = buildCbom({
    scanId: 'scan-b2',
    repoId: 'repo-beta',
    createdAt: '2026-09-01T11:30:00Z',
    repoScans: repoBetaScans,
    rawFindings: [sampleFinding],
  });
  assert.strictEqual(cbomB2.cbomVersion, 'CBOM-v2', 'repo-beta second scan is CBOM-v2');

  // Check repo-gamma scan 1
  const cbomC1 = buildCbom({
    scanId: 'scan-c1',
    repoId: 'repo-gamma',
    createdAt: '2026-09-01T12:30:00Z',
    repoScans: repoGammaScans,
    rawFindings: [sampleFinding],
  });
  assert.strictEqual(cbomC1.cbomVersion, 'CBOM-v1', 'repo-gamma first scan is CBOM-v1');

  // Check repo-alpha scan 3 is still CBOM-v3
  const cbomA3 = buildCbom({
    scanId: 'scan-a3',
    repoId: 'repo-alpha',
    createdAt: '2026-09-01T12:00:00Z',
    repoScans: repoAlphaScans,
    rawFindings: [sampleFinding],
  });
  assert.strictEqual(cbomA3.cbomVersion, 'CBOM-v3', 'repo-alpha scan 3 remains CBOM-v3 independently');

  console.log('✓ Test 4 Passed: Multiple repositories maintain independent version sequences');
}

// ----------------------------------------------------
// 5. Existing repository / scan data remains valid
// ----------------------------------------------------
{
  const legacyScan = {
    scanId: 'legacy-scan-123',
    repoId: 'legacy-repo-456',
    createdAt: '2026-08-01T00:00:00Z',
    rawFindings: [sampleFinding],
  };

  const cbom = buildCbom(legacyScan);

  assert.strictEqual(cbom.bomFormat, 'CycloneDX');
  assert.strictEqual(cbom.specVersion, '1.6');
  assert.strictEqual(cbom.version, 1);
  assert.strictEqual(cbom.cbomVersion, 'CBOM-v1');
  assert.ok(Array.isArray(cbom.components));
  assert.ok(Array.isArray(cbom.dependencies));
  assert.ok(cbom.summary);

  // Merkle tree compatibility check
  const { root } = buildMerkleTree(cbom.components);
  assert.ok(typeof root === 'string' && root.length === 64, 'Merkle tree generates valid root from versioned CBOM');

  console.log('✓ Test 5 Passed: Existing scan data remains valid with deterministic versioning');
}

// ----------------------------------------------------
// 6. Missing / invalid repository identity handled safely
// ----------------------------------------------------
{
  // 6a. Missing repoId entirely
  const noRepo = buildCbom({ scanId: 'scan-no-repo', rawFindings: [sampleFinding] });
  assert.strictEqual(noRepo.version, 1);
  assert.strictEqual(noRepo.cbomVersion, 'CBOM-v1');

  // 6b. null repoId
  const nullRepo = buildCbom({ scanId: 'scan-null', repoId: null, rawFindings: [sampleFinding] });
  assert.strictEqual(nullRepo.version, 1);
  assert.strictEqual(nullRepo.cbomVersion, 'CBOM-v1');

  // 6c. Non-string repoId
  const nonStrRepo = buildCbom({ scanId: 'scan-num-repo', repoId: 99999, rawFindings: [sampleFinding] });
  assert.strictEqual(nonStrRepo.version, 1);
  assert.strictEqual(nonStrRepo.cbomVersion, 'CBOM-v1');

  // 6d. Empty string repoId
  const emptyRepo = buildCbom({ scanId: 'scan-empty-repo', repoId: '', rawFindings: [sampleFinding] });
  assert.strictEqual(emptyRepo.version, 1);
  assert.strictEqual(emptyRepo.cbomVersion, 'CBOM-v1');

  // 6e. Null scan object
  const nullScan = buildCbom(null);
  assert.strictEqual(nullScan.version, 1);
  assert.strictEqual(nullScan.cbomVersion, 'CBOM-v1');

  console.log('✓ Test 6 Passed: Missing or invalid repository identity handled safely with fallback to CBOM-v1');
}

// ----------------------------------------------------
// 7. Explicit version overrides respected
// ----------------------------------------------------
{
  const explicitNum = buildCbom({ scanId: 'scan-exp-1', version: 4, rawFindings: [sampleFinding] });
  assert.strictEqual(explicitNum.version, 4);
  assert.strictEqual(explicitNum.cbomVersion, 'CBOM-v4');

  const explicitLabel = buildCbom({ scanId: 'scan-exp-2', cbomVersion: 'CBOM-v7', rawFindings: [sampleFinding] });
  assert.strictEqual(explicitLabel.version, 7);
  assert.strictEqual(explicitLabel.cbomVersion, 'CBOM-v7');

  console.log('✓ Test 7 Passed: Explicit version overrides respected cleanly');
}

console.log('\nAll 7 CBOM Versioning tests passed successfully!');
