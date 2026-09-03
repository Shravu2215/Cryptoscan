/**
 * CBOM Diff Test Suite
 * Tests: diffCbomVersions — added, removed, changed, and unchanged components
 */
const path = require('path');
const { diffCbomVersions } = require(
  path.join(__dirname, '../../cbom-service/src/services/cbomVersioning')
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

function makeComponent(primitive, keySize, mode, maxSeverity = 'high') {
  return {
    type: 'cryptographic-asset',
    name: primitive,
    'bom-ref': `crypto-asset/${primitive.toLowerCase()}-${keySize || 'none'}-${mode || 'none'}`,
    maxSeverity,
    maxVulnerabilityScore: maxSeverity === 'critical' ? 90 : 60,
    cryptoProperties: {
      assetType: 'algorithm',
      algorithmProperties: {
        primitive,
        parameterSetIdentifier: keySize ? String(keySize) : 'unspecified',
        mode: mode || undefined,
      },
    },
    occurrences: [{ file: 'app.js', line: 10 }],
  };
}

// --- 1. Added components ---
console.log('\n1. Added components in diff');
{
  const v1 = { components: [makeComponent('RSA', 2048, null)] };
  const v2 = { components: [makeComponent('RSA', 2048, null), makeComponent('AES', 256, 'GCM')] };

  const diff = diffCbomVersions(v1, v2);
  assert(diff.added.length === 1, '1 component added');
  assert(diff.added[0].name === 'AES', 'added component is AES');
  assert(diff.removed.length === 0, '0 components removed');
  assert(diff.unchanged === 1, '1 component unchanged');
}

// --- 2. Removed components ---
console.log('\n2. Removed components in diff');
{
  const v1 = { components: [makeComponent('RSA', 2048, null), makeComponent('DES', 56, 'ECB')] };
  const v2 = { components: [makeComponent('RSA', 2048, null)] };

  const diff = diffCbomVersions(v1, v2);
  assert(diff.removed.length === 1, '1 component removed');
  assert(diff.removed[0].name === 'DES', 'removed component is DES');
  assert(diff.added.length === 0, '0 components added');
  assert(diff.unchanged === 1, '1 component unchanged');
}

// --- 3. Changed component properties ---
console.log('\n3. Changed component properties');
{
  const compOld = makeComponent('RSA', 2048, null, 'high');
  const compNew = makeComponent('RSA', 2048, null, 'critical');
  compNew.occurrences.push({ file: 'auth.js', line: 42 }); // line added

  const v1 = { components: [compOld] };
  const v2 = { components: [compNew] };

  const diff = diffCbomVersions(v1, v2);
  assert(diff.changed.length === 1, '1 component changed');
  assert(diff.changed[0].changedFields.includes('maxSeverity'), 'changedFields includes maxSeverity');
  assert(diff.changed[0].changedFields.includes('occurrences'), 'changedFields includes occurrences');
}

// --- 4. Empty CBOM diff ---
console.log('\n4. Null / Empty CBOM diff safety');
{
  const diff = diffCbomVersions(null, null);
  assert(Array.isArray(diff.added) && diff.added.length === 0, 'null old/new yields empty added array');
  assert(Array.isArray(diff.removed) && diff.removed.length === 0, 'null old/new yields empty removed array');
  assert(diff.unchanged === 0, 'unchanged count is 0');
}

console.log(`\n--- cbomDiff.test.js: ${passed} passed, ${failed} failed ---`);
if (failed > 0) process.exit(1);
