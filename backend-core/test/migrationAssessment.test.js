'use strict';

const assert = require('assert');
const { assessFinding, assessMigration } = require('../src/services/migrationAssessment');
const { normalizeDataLifetime, HNDL_CONFIG } = require('../src/services/vulnScoring');

function runTests() {
  console.log('Running Migration Assessment (Phase 8 Production) Test Suite...');
  let passed = 0;

  // Mock finding data
  const mockScan = { id: 'scan-123', repo: { name: 'test-repo' } };
  
  // Test 1: Classically Broken
  const md5Finding = {
    id: 1,
    algorithm: 'MD5',
    usage: 'password_hashing',
    dataLifetime: '10_YEARS',
    businessContext: 'HIGH_IMPACT'
  };
  const md5Assessment = assessFinding(md5Finding);
  assert.strictEqual(md5Assessment.migrationPriority, 'CRITICAL', 'MD5 should be CRITICAL priority');
  assert.strictEqual(md5Assessment.actionCategory, 'immediateActions', 'MD5 should be immediate action');
  assert.strictEqual(md5Assessment.quantumVulnerabilityStatus, 'Classically Broken');
  passed++;
  console.log('✓ Test 1 Passed: Classically broken correctly prioritized as CRITICAL');

  // Test 2: Already PQC
  const mlkemFinding = {
    id: 2,
    algorithm: 'ML-KEM',
    usage: 'key_exchange'
  };
  const mlkemAssessment = assessFinding(mlkemFinding);
  assert.strictEqual(mlkemAssessment.migrationPriority, 'NONE');
  assert.strictEqual(mlkemAssessment.quantumVulnerabilityStatus, 'Quantum Safe');
  passed++;
  console.log('✓ Test 2 Passed: Already PQC correctly prioritized as NONE');

  // Test 3: Quantum Resistant (AES-256)
  const aes256Finding = {
    id: 3,
    algorithm: 'AES',
    keySize: 256,
    usage: 'encryption'
  };
  const aes256Assessment = assessFinding(aes256Finding);
  assert.strictEqual(aes256Assessment.migrationPriority, 'NONE');
  assert.strictEqual(aes256Assessment.quantumVulnerabilityStatus, 'Quantum Safe');
  passed++;
  console.log('✓ Test 3 Passed: Quantum resistant AES-256 prioritized as NONE');

  // Test 4: Quantum Resistant but insufficient key size (AES-128)
  const aes128Finding = {
    id: 4,
    algorithm: 'AES',
    keySize: 128,
    usage: 'encryption'
  };
  const aes128Assessment = assessFinding(aes128Finding);
  assert.strictEqual(aes128Assessment.migrationPriority, 'HIGH');
  assert.strictEqual(aes128Assessment.actionCategory, 'shortTermActions');
  assert.strictEqual(aes128Assessment.quantumVulnerabilityStatus, 'Quantum Safe');
  passed++;
  console.log('✓ Test 4 Passed: Quantum resistant AES-128 prioritized as HIGH for key upgrade');

  // Test 5: Vulnerable Primitive (RSA-2048 key exchange)
  const rsaFinding = {
    id: 5,
    algorithm: 'RSA',
    keySize: 2048,
    usage: 'key_exchange',
    dataLifetime: '1_YEAR', // Short lived -> lower risk
    businessContext: 'LOW_IMPACT'
  };
  const rsaAssessment = assessFinding(rsaFinding);
  assert.ok(['MEDIUM', 'HIGH', 'CRITICAL'].includes(rsaAssessment.migrationPriority));
  assert.strictEqual(rsaAssessment.quantumVulnerabilityStatus, 'Quantum Vulnerable');
  assert.strictEqual(rsaAssessment.recommendedPqc, 'ML-KEM or ML-DSA (confirm usage first)');
  passed++;
  console.log('✓ Test 5 Passed: RSA correctly mapped to PQC alternative');

  // Test 6: Full Scan Assessment
  const rawFindings = [md5Finding, mlkemFinding, aes256Finding, aes128Finding, rsaFinding];
  const plan = assessMigration(mockScan, rawFindings);
  assert.strictEqual(plan.scanId, 'scan-123');
  assert.strictEqual(plan.immediateActions.length, 1);
  assert.strictEqual(plan.immediateActions[0].algorithm, 'MD5');
  assert.strictEqual(plan.affectedAssets.length, 5);
  passed++;
  console.log('✓ Test 6 Passed: Full migration plan built correctly');

  console.log(`\nAll ${passed} Migration Assessment tests passed successfully!`);
}

if (require.main === module) {
  runTests();
}
