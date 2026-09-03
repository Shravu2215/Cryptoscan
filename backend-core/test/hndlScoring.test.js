/**
 * HNDL Scoring Engine Tests
 * Tests: calculateHndlRisk, PURPOSE_DATA_LIFETIME, quantumExposureWindow
 */
const path = require('path');
const { calculateHndlRisk, PURPOSE_DATA_LIFETIME, DEFAULT_YEARS_TO_QUANTUM_THREAT } = require(
  path.join(__dirname, '../src/services/hndlEngine')
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

// --- 1. Data lifetime defaults ---
console.log('\n1. PURPOSE_DATA_LIFETIME defaults');
assert(PURPOSE_DATA_LIFETIME.data_encryption === 20, 'data_encryption lifetime = 20 yrs');
assert(PURPOSE_DATA_LIFETIME.key_exchange === 10, 'key_exchange lifetime = 10 yrs');
assert(PURPOSE_DATA_LIFETIME.digital_signature === 5, 'digital_signature lifetime = 5 yrs');
assert(PURPOSE_DATA_LIFETIME.password_hashing === 15, 'password_hashing lifetime = 15 yrs');
assert(DEFAULT_YEARS_TO_QUANTUM_THREAT === 7, 'default CRQC threat = 7 years');

// --- 2. Quantum exposure window ---
console.log('\n2. Quantum Exposure Window');
{
  // data_encryption: lifetime=20, threat=7 → window = 13
  const r = calculateHndlRisk('data_encryption', 100);
  assert(r.dataLifetimeYears === 20, 'data_encryption dataLifetimeYears = 20');
  assert(r.yearsToQuantumThreat === DEFAULT_YEARS_TO_QUANTUM_THREAT, 'yearsToQuantumThreat = default');
  assert(r.quantumExposureWindow === 13, 'quantumExposureWindow = 20 - 7 = 13');
  assert(typeof r.hndlRisk === 'number', 'hndlRisk is a number');
  assert(r.hndlRisk >= 0 && r.hndlRisk <= 100, 'hndlRisk is in [0, 100]');
}

// --- 3. Digital signature — short lifetime, no exposure ---
console.log('\n3. Low exposure window (digital_signature)');
{
  // digital_signature: lifetime=5, threat=7 → window = max(0, -2) = 0
  const r = calculateHndlRisk('digital_signature', 100);
  assert(r.quantumExposureWindow === 0, 'digital_signature has no quantum exposure window');
  assert(r.hndlRisk >= 60, 'still high risk despite no window (imminent threat)');
}

// --- 4. Low quantum vulnerability (SHA-256) ---
console.log('\n4. Low quantum vulnerability (SHA-256)');
{
  const r = calculateHndlRisk('integrity_hashing', 15); // SHA-256 score ~15
  assert(r.hndlRisk < 30, 'SHA-256 HNDL risk is low');
}

// --- 5. Override options ---
console.log('\n5. Override options');
{
  const r = calculateHndlRisk('data_encryption', 100, { dataLifetimeYears: 30, yearsToQuantumThreat: 10 });
  assert(r.dataLifetimeYears === 30, 'dataLifetimeYears override respected');
  assert(r.yearsToQuantumThreat === 10, 'yearsToQuantumThreat override respected');
  assert(r.quantumExposureWindow === 20, 'quantumExposureWindow = 30 - 10 = 20');
}

// --- 6. HNDL integrated in vulnScoring ---
console.log('\n6. HNDL integrated in vulnScoring');
{
  const { scoreFinding, WEIGHTS } = require(path.join(__dirname, '../src/services/vulnScoring'));
  const result = scoreFinding({ primitive: 'RSA', keySize: 2048 }, 'key_exchange');
  assert(typeof result.breakdown.hndlRisk === 'number', 'breakdown includes hndlRisk');
  assert(typeof result.breakdown.dataLifetimeYears === 'number', 'breakdown includes dataLifetimeYears');
  assert(typeof result.breakdown.yearsToQuantumThreat === 'number', 'breakdown includes yearsToQuantumThreat');
  assert(typeof result.breakdown.quantumExposureWindow === 'number', 'breakdown includes quantumExposureWindow');
  // Weights must sum to 1.0
  const weightSum = Object.values(WEIGHTS).reduce((a, b) => a + b, 0);
  assert(Math.abs(weightSum - 1.0) < 0.0001, `5-factor weights sum to 1.0 (got ${weightSum.toFixed(4)})`);
  assert('hndlRisk' in WEIGHTS, 'WEIGHTS includes hndlRisk key');
}

console.log(`\n--- hndlScoring.test.js: ${passed} passed, ${failed} failed ---`);
if (failed > 0) process.exit(1);
