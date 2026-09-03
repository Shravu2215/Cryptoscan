/**
 * CBOM Versioning Test Suite
 * Tests: saveCbomVersion, listCbomVersions, getCbomVersion, auto-incrementing version numbers
 */
const path = require('path');
const {
  saveCbomVersion,
  listCbomVersions,
  getCbomVersion,
} = require(path.join(__dirname, '../../cbom-service/src/services/cbomVersioning'));

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

const mockStore = new Map();

// --- 1. First version creation (CBOM-v1) ---
console.log('\n1. Save CBOM-v1');
{
  const cbom1 = { bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ name: 'RSA' }] };
  const v1 = saveCbomVersion('repo-1', 'scan-1', cbom1, mockStore);

  assert(v1.versionNumber === 1, 'v1 versionNumber === 1');
  assert(v1.versionLabel === 'CBOM-v1', 'v1 versionLabel === "CBOM-v1"');
  assert(v1.repoId === 'repo-1', 'v1 repoId === "repo-1"');
  assert(v1.scanId === 'scan-1', 'v1 scanId === "scan-1"');
  assert(typeof v1.createdAt === 'string', 'v1 has createdAt timestamp');
}

// --- 2. Second version creation (CBOM-v2) ---
console.log('\n2. Save CBOM-v2 (Auto-increment)');
{
  const cbom2 = { bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ name: 'RSA' }, { name: 'AES' }] };
  const v2 = saveCbomVersion('repo-1', 'scan-2', cbom2, mockStore);

  assert(v2.versionNumber === 2, 'v2 versionNumber === 2');
  assert(v2.versionLabel === 'CBOM-v2', 'v2 versionLabel === "CBOM-v2"');
}

// --- 3. List versions ---
console.log('\n3. List CBOM versions for repo');
{
  const list = listCbomVersions('repo-1', mockStore);
  assert(Array.isArray(list), 'listCbomVersions returns array');
  assert(list.length === 2, 'repo-1 has 2 versions listed');
  assert(list[0].versionLabel === 'CBOM-v1', 'first listed is CBOM-v1');
  assert(list[1].versionLabel === 'CBOM-v2', 'second listed is CBOM-v2');
}

// --- 4. Get specific version content ---
console.log('\n4. Retrieve CBOM version content');
{
  const content = getCbomVersion('repo-1', 2, mockStore);
  assert(content !== null, 'version 2 content found');
  assert(content.components.length === 2, 'version 2 has 2 components');

  const missing = getCbomVersion('repo-1', 99, mockStore);
  assert(missing === null, 'non-existent version returns null');
}

// --- 5. Error handling on missing params ---
console.log('\n5. Parameter validation');
{
  let threw = false;
  try {
    saveCbomVersion(null, 'scan-1', {}, mockStore);
  } catch (err) {
    threw = true;
  }
  assert(threw, 'saveCbomVersion throws when repoId is missing');
}

console.log(`\n--- cbomVersioning.test.js: ${passed} passed, ${failed} failed ---`);
if (failed > 0) process.exit(1);
