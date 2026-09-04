/**
 * Unit Test Suite for Migration Simulation Service (Person 3 — Phase 7)
 *
 * Verifies non-mutation, correct PQC recommendations (from Phase 6),
 * risk/exposure integration (from Phase 4), business-context sensitivity,
 * and batch behavior.
 *
 * Run: node test/migrationSimulation.test.js
 */

'use strict';

const assert = require('assert');
const {
  simulateMigration,
  simulateMigrationBatch,
} = require('../src/services/migrationSimulation');

const {
  getMigrationGuidance,
  calculateCryptoAgilityScore,
  detectPurpose,
} = require('../src/services/purposeDetection');
const { normalizeDataLifetime, scoreFinding } = require('../src/services/vulnScoring');
const { buildCbom } = require('../src/services/cbomGenerator');

console.log('Running Migration Simulation Unit Test Suite...\n');

// -----------------------------------------------------------------------
// 1. Quantum-vulnerable asymmetric primitive (RSA-2048 key exchange)
// -----------------------------------------------------------------------
{
  const result = simulateMigration({
    primitive: 'RSA',
    algorithm: 'RSA-2048',
    purpose: 'key_exchange',
    keySize: 2048,
  });

  assert.strictEqual(result.simulationValid, true, 'simulation should be valid');
  assert.strictEqual(result.simulationOnly, true, 'must be marked simulationOnly');
  assert.strictEqual(result.supportStatus, 'quantum-vulnerable');
  assert.strictEqual(result.isAlreadyPQC, false);
  assert.strictEqual(result.isClassicallyBroken, false);
  assert.strictEqual(result.isQuantumResistant, false);

  assert.strictEqual(
    result.pqcRecommendation.algorithm,
    'ML-KEM (Kyber)',
    'RSA key_exchange maps to ML-KEM'
  );
  assert.strictEqual(result.pqcRecommendation.standard, 'FIPS 203');
  assert.strictEqual(result.pqcRecommendation.hybridRecommended, true, 'hybrid recommended by default for RSA key_exchange');
  assert.strictEqual(typeof result.cryptoAgilityScore, 'number', 'agility score present');

  console.log('✓ Test 1 Passed: RSA-2048 key exchange correctly simulated');
}

// -----------------------------------------------------------------------
// 2. RSA used for signature vs key_exchange (2D purpose lookup test)
// -----------------------------------------------------------------------
{
  const keyExchangeResult = simulateMigration({
    primitive: 'RSA',
    algorithm: 'RSA-2048',
    purpose: 'key_exchange',
    keySize: 2048,
  });

  const signatureResult = simulateMigration({
    primitive: 'RSA',
    algorithm: 'RSA-2048',
    purpose: 'digital_signature',
    keySize: 2048,
  });

  assert.notStrictEqual(
    keyExchangeResult.pqcRecommendation.algorithm,
    signatureResult.pqcRecommendation.algorithm,
    'RSA PQC target MUST differ based on purpose'
  );
  assert.strictEqual(keyExchangeResult.pqcRecommendation.algorithm, 'ML-KEM (Kyber)');
  assert.strictEqual(signatureResult.pqcRecommendation.algorithm, 'ML-DSA (Dilithium)');

  console.log('✓ Test 2 Passed: 2D purpose lookup differentiates RSA key_exchange vs signature');
}

// -----------------------------------------------------------------------
// 3. Quantum-resistant symmetric cipher (AES-256)
// -----------------------------------------------------------------------
{
  const result = simulateMigration({
    primitive: 'AES',
    algorithm: 'AES-256-GCM',
    purpose: 'data_encryption',
    keySize: 256,
    mode: 'GCM',
  });

  assert.strictEqual(result.simulationValid, true);
  assert.strictEqual(result.supportStatus, 'quantum-resistant');
  assert.strictEqual(result.isQuantumResistant, true);
  assert.strictEqual(result.pqcRecommendation.hybridRecommended, false, 'no hybrid for symmetric ciphers');
  assert(result.summary.includes('no PQC migration required'), 'summary reflects adequate key size');

  console.log('✓ Test 3 Passed: AES-256-GCM correctly recognized as quantum-resistant');
}

// -----------------------------------------------------------------------
// 4. Quantum-weakened symmetric cipher (AES-128)
// -----------------------------------------------------------------------
{
  const result = simulateMigration({
    primitive: 'AES',
    algorithm: 'AES-128-CBC',
    purpose: 'data_encryption',
    keySize: 128,
    mode: 'CBC',
  });

  assert.strictEqual(result.simulationValid, true);
  assert.strictEqual(result.supportStatus, 'quantum-weakened');
  assert(result.summary.includes('quantum-weakened'), 'summary reflects weakened status');

  console.log('✓ Test 4 Passed: AES-128 correctly flagged as quantum-weakened');
}

// -----------------------------------------------------------------------
// 5. Already PQC primitive (ML-KEM-768)
// -----------------------------------------------------------------------
{
  const result = simulateMigration({
    primitive: 'ML-KEM',
    algorithm: 'ML-KEM-768',
    purpose: 'key_exchange',
  });

  assert.strictEqual(result.simulationValid, true);
  assert.strictEqual(result.supportStatus, 'already-pqc');
  assert.strictEqual(result.isAlreadyPQC, true);
  assert(result.summary.includes('already a post-quantum algorithm'), 'summary notes no migration required');

  console.log('✓ Test 5 Passed: Already-PQC algorithm correctly identified');
}

// -----------------------------------------------------------------------
// 6. Context-based purpose inference
// -----------------------------------------------------------------------
{
  const result = simulateMigration({
    algorithm: 'ECDSA-P256',
    primitive: 'ECC',
    keySize: 256,
    context: {
      functionName: 'signJwtToken',
      surroundingCode: 'const signature = crypto.sign("sha256", payload, key);',
    },
  });

  assert.strictEqual(result.input.purpose, 'digital_signature', 'inferred purpose should be digital_signature');
  assert.strictEqual(result.input.purposeConfidence, 'inferred');
  assert.strictEqual(result.pqcRecommendation.algorithm, 'ML-DSA (Dilithium)');

  console.log('✓ Test 6 Passed: Context-based purpose detection successfully inferred digital_signature');
}

// -----------------------------------------------------------------------
// 7. Batch simulation
// -----------------------------------------------------------------------
{
  const components = [
    { primitive: 'RSA', algorithm: 'RSA-2048', purpose: 'key_exchange', keySize: 2048 },
    { primitive: 'AES', algorithm: 'AES-256-GCM', purpose: 'data_encryption', keySize: 256 },
    { primitive: 'MD5', algorithm: 'MD5', purpose: 'integrity_hashing' },
  ];

  const batchResult = simulateMigrationBatch(components);

  assert.strictEqual(batchResult.simulationValid, true);
  assert.strictEqual(batchResult.simulationOnly, true);
  assert.strictEqual(batchResult.totalComponents, 3);
  assert.strictEqual(batchResult.results.length, 3);
  assert.strictEqual(batchResult.counts['quantum-vulnerable'], 1);
  assert.strictEqual(batchResult.counts['quantum-resistant'], 1);
  assert.strictEqual(batchResult.counts['classically-broken'], 1);
  assert(batchResult.summary.includes('Batch migration simulation of 3 component(s)'), 'batch summary populated');

  console.log('✓ Test 7 Passed: Batch migration simulation executed cleanly');
}

// -----------------------------------------------------------------------
// 8. Crypto-agility score propagation from Phase 6
// -----------------------------------------------------------------------
{
  // ECC-256 key_exchange: 40 + 30 + 30 = 100
  const eccResult = simulateMigration({
    primitive: 'ECC',
    algorithm: 'ECDH-P256',
    purpose: 'key_exchange',
    keySize: 256,
  });

  assert.strictEqual(eccResult.cryptoAgilityScore, 100, 'ECC-256 key_exchange achieves 100 agility');

  // RSA-2048 digital_signature: 30 + 30 + 25 = 85
  const rsaResult = simulateMigration({
    primitive: 'RSA',
    algorithm: 'RSA-2048',
    purpose: 'digital_signature',
    keySize: 2048,
  });

  assert.strictEqual(rsaResult.cryptoAgilityScore, 85, 'RSA-2048 digital_signature achieves 85 agility');
  assert(rsaResult.cryptoAgilityScore >= 0 && rsaResult.cryptoAgilityScore <= 100, 'agility score within bounds');

  console.log('✓ Test 8 Passed: Crypto-agility scores propagated correctly from Phase 6 engine');
}

// -----------------------------------------------------------------------
// 9. Risk/exposure calculation (HNDL integration from Phase 4)
// -----------------------------------------------------------------------
{
  // Long-lived RSA key with 10-year data lifetime
  const longLivedResult = simulateMigration({
    primitive: 'RSA',
    algorithm: 'RSA-2048',
    purpose: 'digital_signature',
    keySize: 2048,
    dataLifetime: 10,
  });

  assert(longLivedResult.riskExposure.preBusinessRiskScore !== null, 'risk score is computed');
  assert(longLivedResult.riskExposure.preBusinessRiskScore > 0, 'risk score is positive for quantum-vulnerable');
  assert.strictEqual(longLivedResult.riskExposure.dataLifetimeYears, 10, 'data lifetime 10 years');
  assert(longLivedResult.riskExposure.quantumExposureWindow >= 0, 'exposure window is non-negative');

  // Short-lived key — exposure window should be minimal/zero
  const shortLivedResult = simulateMigration({
    primitive: 'RSA',
    algorithm: 'RSA-2048',
    purpose: 'digital_signature',
    keySize: 2048,
    dataLifetime: 2,
  });

  // 2 + 3 - 7 = -2, clamped to 0
  assert.strictEqual(shortLivedResult.riskExposure.quantumExposureWindow, 0, 'short lifetime yields zero exposure window');

  // Missing data lifetime uses safe default
  const defaultLtResult = simulateMigration({
    primitive: 'RSA',
    algorithm: 'RSA-2048',
    purpose: 'digital_signature',
    keySize: 2048,
  });

  assert.strictEqual(defaultLtResult.riskExposure.isDefaultLifetime, true, 'missing lifetime uses safe default');

  console.log('✓ Test 9 Passed: Risk/exposure calculations correctly use HNDL model from Phase 4');
}

// -----------------------------------------------------------------------
// 10. Non-mutation behavior
// -----------------------------------------------------------------------
{
  const originalComponent = {
    primitive: 'RSA',
    algorithm: 'RSA-2048',
    purpose: 'digital_signature',
    keySize: 2048,
    customField: 'should-not-be-modified',
  };
  const componentCopy = JSON.parse(JSON.stringify(originalComponent));

  simulateMigration(originalComponent);

  // Component must be unchanged
  assert.deepStrictEqual(originalComponent, componentCopy, 'simulateMigration does NOT mutate input');

  const batchComponents = [
    { primitive: 'RSA', algorithm: 'RSA-1024', purpose: 'key_exchange', keySize: 1024 },
    { primitive: 'AES', algorithm: 'AES-128', purpose: 'data_encryption', keySize: 128 },
  ];
  const batchCopy = JSON.parse(JSON.stringify(batchComponents));
  simulateMigrationBatch(batchComponents);
  assert.deepStrictEqual(batchComponents, batchCopy, 'simulateMigrationBatch does NOT mutate inputs');

  // Verify simulationOnly flag is always present
  const result = simulateMigration({ primitive: 'RSA', purpose: 'key_exchange' });
  assert.strictEqual(result.simulationOnly, true, 'simulationOnly flag always set to true');

  console.log('✓ Test 10 Passed: Simulation is strictly non-mutating — inputs and stored data are never modified');
}

// -----------------------------------------------------------------------
// 11. Classically-broken algorithms
// -----------------------------------------------------------------------
{
  const md5Result = simulateMigration({
    primitive: 'MD5',
    algorithm: 'MD5',
    purpose: 'integrity_hashing',
  });

  assert.strictEqual(md5Result.simulationValid, true);
  assert.strictEqual(md5Result.isClassicallyBroken, true, 'MD5 is classically broken');
  assert.strictEqual(md5Result.supportStatus, 'classically-broken');
  assert(md5Result.summary.includes('IMMEDIATE'), 'summary includes urgency');
  assert.strictEqual(md5Result.pqcRecommendation.hybridRecommended, false, 'no hybrid for classically-broken');

  const desResult = simulateMigration({
    primitive: 'DES',
    algorithm: 'DES-ECB',
    purpose: 'data_encryption',
    keySize: 56,
    mode: 'ECB',
  });

  assert.strictEqual(desResult.isClassicallyBroken, true, 'DES is classically broken');
  assert.strictEqual(desResult.supportStatus, 'classically-broken');
  assert(desResult.migrationSteps.some(s => s.includes('URGENT')), 'DES steps include urgency marker');

  console.log('✓ Test 11 Passed: Classically broken algorithms (MD5, DES) correctly identified and flagged as urgent');
}

// -----------------------------------------------------------------------
// 12. Migration steps populated and structured
// -----------------------------------------------------------------------
{
  const result = simulateMigration({
    primitive: 'ECC',
    algorithm: 'ECDSA-P256',
    purpose: 'digital_signature',
    keySize: 256,
  });

  assert(Array.isArray(result.migrationSteps), 'migrationSteps is an array');
  assert(result.migrationSteps.length > 1, 'multiple migration steps generated for quantum-vulnerable ECC');
  assert(result.migrationSteps.every(s => typeof s === 'string' && s.length > 0), 'all steps are non-empty strings');
  assert(result.migrationSteps.some(s => s.includes('ML-DSA')), 'steps reference the PQC target algorithm');

  console.log('✓ Test 12 Passed: Migration steps populated, structured, and reference the correct PQC target');
}

// -----------------------------------------------------------------------
// 13. Phase 1–6 regression — services still importable and functional
// -----------------------------------------------------------------------
{
  // Phase 4: HNDL scoring
  const normLifetime = normalizeDataLifetime(5);
  assert.strictEqual(normLifetime.value, 5, 'Phase 4: normalizeDataLifetime works');

  // Phase 5: Business context
  const scored = scoreFinding(
    { primitive: 'RSA', keySize: 2048 },
    'digital_signature',
    { businessImportance: 'Critical' }
  );
  assert.strictEqual(scored.appliedMultiplier, 1.25, 'Phase 5: business context multiplier applied');

  // Phase 6: PQC recommendation engine
  const guidance = getMigrationGuidance('RSA', 'digital_signature', { keySize: 2048 });
  assert.strictEqual(guidance.hybridByDefault, true, 'Phase 6: hybridByDefault present');
  assert.strictEqual(typeof guidance.cryptoAgilityScore, 'number', 'Phase 6: cryptoAgilityScore numeric');

  const agility = calculateCryptoAgilityScore('ECC', 'key_exchange', { keySize: 256 });
  assert.strictEqual(agility, 100, 'Phase 6: ECC-256 key_exchange agility is 100');

  // Phase 3: Purpose detection
  const detected = detectPurpose({ context: { usageType: 'signature' } });
  assert.strictEqual(detected.purpose, 'digital_signature', 'Phase 3: purpose detection works');

  // Phase 1–2: CBOM generation
  const cbom = buildCbom({
    scanId: 'regression-scan',
    repoId: 'regression-repo',
    version: 1,
    rawFindings: [{ id: 'r1', algorithm: 'RSA-2048', primitive: 'RSA', keySize: 2048, file: 'app.js' }],
  });
  assert.strictEqual(cbom.bomFormat, 'CycloneDX', 'Phase 1–2: CBOM generation intact');

  console.log('✓ Test 13 Passed: All Phase 1–6 services remain functional — full regression compatibility confirmed');
}

console.log('\nAll 13 Migration Simulation tests passed successfully!');
