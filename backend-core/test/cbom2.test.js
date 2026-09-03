/**
 * CBOM 2.0 Provenance & Dependencies Graph Tests
 * Tests: provenance block, CycloneDX dependencies array, buildSignedCbom stub
 */
const path = require('path');

// Use cbom-service services (shared code)
const { buildCbom, buildSignedCbom } = require(
  path.join(__dirname, '../../cbom-service/src/services/cbomGenerator')
);

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    console.log(`  ✓ ${msg}`);
    passed++;
  } else {
    console.error(`  ✗ FAILED: ${msg}`);
    failed++;
  }
}

function makeScan(overrides = {}) {
  return {
    scanId: 'test-scan-cbom2',
    repoId: 'repo-alpha',
    receivedAt: '2026-09-03T10:00:00.000Z',
    commitHash: 'abc123def456',
    scannerVersion: '2.0.0',
    rawFindings: [
      { id: 'f1', primitive: 'RSA', keySize: 2048, file: 'auth.js', line: 10, context: { usageType: 'signature' } },
      { id: 'f2', primitive: 'AES', keySize: 128, file: 'enc.js', line: 20, context: { usageType: 'encryption' } },
    ],
    ...overrides,
  };
}

// --- 1. Provenance block ---
console.log('\n1. CBOM Provenance Block');
{
  const cbom = buildCbom(makeScan());
  assert(typeof cbom.provenance === 'object' && cbom.provenance !== null, 'CBOM has provenance block');
  assert(cbom.provenance.commitHash === 'abc123def456', 'provenance.commitHash matches scan.commitHash');
  assert(cbom.provenance.scanTimestamp === '2026-09-03T10:00:00.000Z', 'provenance.scanTimestamp matches scan.receivedAt');
  assert(cbom.provenance.scannerVersion === '2.0.0', 'provenance.scannerVersion present');
}

// --- 2. Provenance fallback when scan has no commitHash ---
console.log('\n2. Provenance fallback values');
{
  const cbom = buildCbom(makeScan({ commitHash: undefined, scannerVersion: undefined }));
  assert(cbom.provenance.commitHash === 'uncommitted', 'commitHash defaults to "uncommitted"');
  assert(cbom.provenance.scannerVersion === '2.0.0', 'scannerVersion defaults to 2.0.0');
}

// --- 3. CycloneDX dependencies array ---
console.log('\n3. CycloneDX Dependencies Graph');
{
  const cbom = buildCbom(makeScan());
  assert(Array.isArray(cbom.dependencies), 'CBOM has dependencies array');
  assert(cbom.dependencies.length >= 1, 'dependencies has at least 1 entry (repo root)');

  const rootDep = cbom.dependencies.find((d) => d.ref === 'repo-alpha');
  assert(rootDep !== undefined, 'root dependency ref matches repoId');
  assert(Array.isArray(rootDep.dependsOn), 'root dependency has dependsOn array');
  assert(rootDep.dependsOn.length === cbom.components.length, 'root dependsOn lists all component bom-refs');

  // Each component ref should also appear in dependencies
  for (const comp of cbom.components) {
    const compDep = cbom.dependencies.find((d) => d.ref === comp['bom-ref']);
    assert(compDep !== undefined, `component ${comp['bom-ref']} is listed in dependencies`);
    assert(Array.isArray(compDep.dependsOn), `component ${comp['bom-ref']} has dependsOn array`);
  }
}

// --- 4. buildSignedCbom stub ---
console.log('\n4. Signed CBOM Export Stub');
{
  const signed = buildSignedCbom(makeScan());
  assert(signed.bomFormat === 'CycloneDX', 'signed CBOM preserves bomFormat');
  assert(signed.specVersion === '1.6', 'signed CBOM preserves specVersion');
  assert('signature' in signed, 'signed CBOM has signature field');
  assert(signed.signature === null, 'signature is null (stub — pending integrity-service)');
  assert(Array.isArray(signed.components), 'signed CBOM has components');
  assert(typeof signed.provenance === 'object', 'signed CBOM includes provenance');
}

// --- 5. Backward compatibility — existing fields still present ---
console.log('\n5. Backward Compatibility');
{
  const cbom = buildCbom(makeScan());
  assert(cbom.bomFormat === 'CycloneDX', 'bomFormat present');
  assert(cbom.specVersion === '1.6', 'specVersion present');
  assert(typeof cbom.serialNumber === 'string', 'serialNumber present');
  assert(typeof cbom.metadata === 'object', 'metadata present');
  assert(Array.isArray(cbom.components), 'components present');
  assert(typeof cbom.summary === 'object', 'summary present');
  assert(typeof cbom.summary.totalFindings === 'number', 'summary.totalFindings present');
}

console.log(`\n--- cbom2.test.js: ${passed} passed, ${failed} failed ---`);
if (failed > 0) process.exit(1);
