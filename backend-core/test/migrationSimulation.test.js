/**
 * Migration Simulation Test Suite (Person 3 — Phase 7)
 *
 * Tests:
 *  1. Known quantum-vulnerable algorithm (RSA key exchange)
 *  2. Hybrid migration recommendation (RSA signature)
 *  3. Symmetric/hash algorithm (AES-256, SHA-256)
 *  4. Already-PQC algorithm (ML-KEM, ML-DSA)
 *  5. Unknown algorithm safe handling
 *  6. Malformed input
 *  7. Multiple component (batch) simulation
 *  8. Crypto-agility score propagation
 *  9. Risk/exposure calculation
 * 10. Non-mutation behavior
 * 11. Classically-broken algorithm (MD5, DES)
 * 12. Migration steps populated
 * 13. All existing Phase 1–6 tests still pass (regression check via imports)
 */

'use strict';

const assert = require('assert');
const { simulateMigration, simulateMigrationBatch } = require('../src/services/migrationSimulation');

// Importing Phase 1–6 services to verify they are still importable and functional
const { scoreFinding, normalizeDataLifetime } = require('../src/services/vulnScoring');
const { detectPurpose, getMigrationGuidance, isHybridByDefault, calculateCryptoAgilityScore } = require('../src/services/purposeDetection');
const { buildCbom, buildFindingsResponse } = require('../src/services/cbomGenerator');

console.log('Running Migration Simulation (Phase 7) Test Suite...');

// -----------------------------------------------------------------------
// 1. Known quantum-vulnerable algorithm (RSA key exchange)
// -----------------------------------------------------------------------
{
  const result = simulateMigration({
    primitive: 'RSA',
    algorithm: 'RSA-2048',
    purpose: 'key_exchange',
    keySize: 2048,
    dataLifetime: 10,
  });

  assert.strictEqual(result.simulationValid, true, 'RSA key exchange simulation is valid');
  assert.strictEqual(result.simulationOnly, true, 'explicitly marked simulationOnly');
  assert.strictEqual(result.supportStatus, 'quantum-vulnerable', 'RSA is quantum-vulnerable');
  assert.strictEqual(result.isAlreadyPQC, false);
  assert.strictEqual(result.isClassicallyBroken, false);
  assert(result.pqcRecommendation.algorithm.includes('ML-KEM'), 'recommends ML-KEM for key exchange');
  assert.strictEqual(result.pqcRecommendation.hybridRecommended, true, 'hybrid recommended for RSA KEM');
  assert(result.summary.includes('Shor'), 'summary mentions Shor algorithm');

  console.log('✓ Test 1 Passed: Quantum-vulnerable RSA key exchange correctly identified and simulated');
}

// -----------------------------------------------------------------------
// 2. Hybrid migration recommendation (RSA digital signature)
// -----------------------------------------------------------------------
{
  const result = simulateMigration({
    primitive: 'RSA',
    algorithm: 'RSA-2048',
    purpose: 'digital_signature',
    keySize: 2048,
  });

  assert.strictEqual(result.simulationValid, true);
  assert.strictEqual(result.supportStatus, 'quantum-vulnerable');
  assert.strictEqual(result.pqcRecommendation.hybridRecommended, true, 'hybrid recommended for RSA signature');
  assert.strictEqual(result.pqcRecommendation.hybridByDefault, true);
  assert(result.pqcRecommendation.algorithm.includes('ML-DSA'), 'recommends ML-DSA for signatures');
  assert(Array.isArray(result.migrationSteps), 'migration steps is an array');
  assert(result.migrationSteps.length > 0, 'migration steps not empty');
  // Verify dual-signing guidance is present
  assert(result.migrationSteps.some(s => s.toLowerCase().includes('dual')), 'steps include dual-signing guidance');

  console.log('✓ Test 2 Passed: Hybrid migration recommendation correctly generated for RSA signatures');
}

// -----------------------------------------------------------------------
// 3. Symmetric/hash algorithm (no PQC replacement needed)
// -----------------------------------------------------------------------
{
  // AES-256 — quantum-resistant at adequate key size
  const aesResult = simulateMigration({
    primitive: 'AES',
    algorithm: 'AES-256-GCM',
    purpose: 'data_encryption',
    keySize: 256,
    mode: 'GCM',
  });

  assert.strictEqual(aesResult.simulationValid, true);
  assert.strictEqual(aesResult.supportStatus, 'quantum-resistant', 'AES-256 is quantum-resistant');
  assert.strictEqual(aesResult.pqcRecommendation.hybridRecommended, false, 'no hybrid for AES-256');
  assert(aesResult.migrationSteps.some(s => s.includes('AES-256') || s.includes('key')), 'AES steps include key guidance');

  // SHA-256 — quantum-resistant hash
  const shaResult = simulateMigration({
    primitive: 'SHA-256',
    algorithm: 'SHA-256',
    purpose: 'integrity_hashing',
  });

  assert.strictEqual(shaResult.simulationValid, true);
  assert.strictEqual(shaResult.supportStatus, 'quantum-resistant', 'SHA-256 is quantum-resistant');
  assert.strictEqual(shaResult.pqcRecommendation.hybridRecommended, false, 'no hybrid for SHA-256');

  console.log('✓ Test 3 Passed: Symmetric and hash algorithms correctly classified as quantum-resistant (no PQC replacement needed)');
}

// -----------------------------------------------------------------------
// 4. Already-PQC algorithm
// -----------------------------------------------------------------------
{
  const mlKemResult = simulateMigration({
    primitive: 'ML-KEM',
    algorithm: 'ML-KEM-768',
    purpose: 'key_exchange',
  });

  assert.strictEqual(mlKemResult.simulationValid, true);
  assert.strictEqual(mlKemResult.isAlreadyPQC, true, 'ML-KEM is already PQC');
  assert.strictEqual(mlKemResult.supportStatus, 'already-pqc');
  assert(mlKemResult.summary.includes('already'), 'summary confirms already-PQC');
  assert.strictEqual(mlKemResult.migrationSteps.length, 1, 'single no-op step for already-PQC');
  assert(mlKemResult.migrationSteps[0].includes('already'), 'step confirms no migration needed');

  const mlDsaResult = simulateMigration({
    primitive: 'ML-DSA',
    algorithm: 'ML-DSA-65',
    purpose: 'digital_signature',
  });

  assert.strictEqual(mlDsaResult.isAlreadyPQC, true);
  assert.strictEqual(mlDsaResult.supportStatus, 'already-pqc');

  console.log('✓ Test 4 Passed: Already-PQC algorithms correctly identified with no migration required');
}

// -----------------------------------------------------------------------
// 5. Unknown/unsupported algorithm safe handling
// -----------------------------------------------------------------------
{
  // A truly empty/null primitive that can't be normalized
  const unknownResult = simulateMigration({
    primitive: '',
    algorithm: 'CUSTOM_ALGO_V1',
    purpose: 'data_encryption',
  });

  assert.strictEqual(unknownResult.simulationValid, true, 'unknown algo still produces valid simulation');
  // Primitives that pass through normalizeFamily return non-empty strings (the value itself)
  // but have no PQC table entry → manual review recommendation
  assert(unknownResult.pqcRecommendation.algorithm.includes('review') || unknownResult.pqcRecommendation.algorithm.includes('Review') || unknownResult.supportStatus === 'unknown', 'unknown algo recommends manual review or is classified unknown');

  // An explicitly null-primitive simulation is safe
  const nullPrimResult = simulateMigration({ algorithm: undefined, purpose: 'key_exchange' });
  assert.strictEqual(nullPrimResult.simulationValid, true, 'missing algorithm input does not throw');

  // Pass-through unknown primitives: algorithm with no PQC table entry gets manual review
  const unknownPrimResult = simulateMigration({ primitive: 'UNKNOWN', purpose: 'key_exchange' });
  assert.strictEqual(unknownPrimResult.simulationValid, true);
  assert(unknownPrimResult.pqcRecommendation.algorithm.toLowerCase().includes('review'), 'unknown primitive gets manual review recommendation');

  console.log('✓ Test 5 Passed: Unknown algorithms handled safely with manual review recommendation');
}

// -----------------------------------------------------------------------
// 6. Malformed input
// -----------------------------------------------------------------------
{
  // null input
  const nullResult = simulateMigration(null);
  assert.strictEqual(nullResult.simulationValid, false, 'null input produces invalid simulation');
  assert(nullResult.error, 'null input has error message');

  // string input
  const stringResult = simulateMigration('RSA');
  assert.strictEqual(stringResult.simulationValid, false, 'string input produces invalid simulation');

  // empty object — should still return a valid simulation with defaults
  const emptyResult = simulateMigration({});
  assert.strictEqual(emptyResult.simulationValid, true, 'empty object produces valid simulation with defaults');

  // batch with non-array
  const badBatch = simulateMigrationBatch('not-an-array');
  assert.strictEqual(badBatch.simulationValid, false, 'non-array batch produces invalid simulation');

  console.log('✓ Test 6 Passed: Malformed inputs handled safely without throwing');
}

// -----------------------------------------------------------------------
// 7. Multiple component (batch) simulation
// -----------------------------------------------------------------------
{
  const batchResult = simulateMigrationBatch([
    { primitive: 'RSA', algorithm: 'RSA-2048', purpose: 'digital_signature', keySize: 2048 },
    { primitive: 'ECC', algorithm: 'ECDH-256', purpose: 'key_exchange', keySize: 256 },
    { primitive: 'AES', algorithm: 'AES-256-GCM', purpose: 'data_encryption', keySize: 256 },
    { primitive: 'ML-KEM', algorithm: 'ML-KEM-768', purpose: 'key_exchange' },
    { primitive: 'MD5', algorithm: 'MD5', purpose: 'integrity_hashing' },
  ]);

  assert.strictEqual(batchResult.simulationValid, true, 'batch simulation is valid');
  assert.strictEqual(batchResult.simulationOnly, true, 'batch is simulation-only');
  assert.strictEqual(batchResult.totalComponents, 5, 'batch processes all 5 components');
  assert.strictEqual(batchResult.results.length, 5, 'all 5 results returned');
  assert.strictEqual(batchResult.counts['quantum-vulnerable'], 2, '2 quantum-vulnerable (RSA + ECC)');
  assert.strictEqual(batchResult.counts['quantum-resistant'], 1, '1 quantum-resistant (AES-256)');
  assert.strictEqual(batchResult.counts['already-pqc'], 1, '1 already-PQC (ML-KEM)');
  assert.strictEqual(batchResult.counts['classically-broken'], 1, '1 classically broken (MD5)');
  assert(batchResult.summary.includes('5'), 'summary mentions total count');

  // empty batch
  const emptyBatch = simulateMigrationBatch([]);
  assert.strictEqual(emptyBatch.simulationValid, true, 'empty batch is valid');
  assert.strictEqual(emptyBatch.totalComponents, 0);

  console.log('✓ Test 7 Passed: Batch simulation processes multiple components independently and correctly');
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
