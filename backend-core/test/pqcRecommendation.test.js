/**
 * PQC Recommendation Engine Test Suite (Person 3 — Phase 6)
 *
 * Requirements:
 *  - Recommendations based on detected purpose, primitive, key strength, quantum vulnerability
 *  - hybridByDefault identifies where hybrid classical + PQC is recommended default
 *  - cryptoAgilityScore is deterministic, bounded [0, 100], and explainable
 *  - Preserves all existing recommendation fields and behaviors
 *  - Safely handles unknown/unsupported algorithms
 *  - Compatible with CBOM generation and downstream consumers
 */

const assert = require('assert');
const {
  detectPurpose,
  getMigrationGuidance,
  isHybridByDefault,
  calculateCryptoAgilityScore,
} = require('../src/services/purposeDetection');
const { buildCbom, buildFindingsResponse } = require('../src/services/cbomGenerator');

console.log('Running PQC Recommendation Engine (Phase 6) Test Suite...');

// ----------------------------------------------------
// 1. Hybrid recommendation for quantum-vulnerable cryptography
// ----------------------------------------------------
{
  const rsaSign = getMigrationGuidance('RSA', 'digital_signature', { keySize: 2048 });
  assert.strictEqual(rsaSign.hybridByDefault, true, 'RSA digital signatures recommend hybrid by default');
  assert(rsaSign.recommendation.includes('ML-DSA'), 'RSA signature recommends ML-DSA');

  const rsaKex = getMigrationGuidance('RSA', 'key_exchange', { keySize: 2048 });
  assert.strictEqual(rsaKex.hybridByDefault, true, 'RSA key exchange recommends hybrid by default');
  assert(rsaKex.recommendation.includes('ML-KEM'), 'RSA key exchange recommends ML-KEM');

  const ecdhKex = getMigrationGuidance('ECC', 'key_exchange', { keySize: 256 });
  assert.strictEqual(ecdhKex.hybridByDefault, true, 'ECDH key exchange recommends hybrid by default');
  assert(ecdhKex.recommendation.includes('ML-KEM'), 'ECDH recommends ML-KEM');

  const ecdsaSign = getMigrationGuidance('ECC', 'digital_signature', { keySize: 256 });
  assert.strictEqual(ecdsaSign.hybridByDefault, true, 'ECDSA signatures recommend hybrid by default');
  assert(ecdsaSign.recommendation.includes('ML-DSA'), 'ECDSA recommends ML-DSA');

  const dhKex = getMigrationGuidance('DH', 'key_exchange', { keySize: 2048 });
  assert.strictEqual(dhKex.hybridByDefault, true, 'DH key exchange recommends hybrid by default');

  console.log('✓ Test 1 Passed: Quantum-vulnerable public-key algorithms recommend hybrid by default');
}

// ----------------------------------------------------
// 2. Non-hybrid recommendation where appropriate
// ----------------------------------------------------
{
  // Symmetric encryption: quantum-safe at 256-bit without hybrid wrapping
  const aes = getMigrationGuidance('AES', 'data_encryption', { keySize: 256 });
  assert.strictEqual(aes.hybridByDefault, false, 'AES symmetric encryption does not use hybrid');
  assert(aes.recommendation.includes('AES-256'), 'recommends keeping AES-256');

  const chacha = getMigrationGuidance('ChaCha20', 'data_encryption', { keySize: 256 });
  assert.strictEqual(chacha.hybridByDefault, false, 'ChaCha20 does not use hybrid');

  // Hashing: quantum-safe preimage resistance at 256-bit
  const sha256 = getMigrationGuidance('SHA-256', 'integrity_hashing');
  assert.strictEqual(sha256.hybridByDefault, false, 'SHA-256 hashing does not use hybrid');

  // Classically broken: requires immediate replacement, not hybrid transition
  const des = getMigrationGuidance('DES', 'data_encryption', { keySize: 56, mode: 'ECB' });
  assert.strictEqual(des.hybridByDefault, false, 'DES requires direct replacement, not hybrid');
  assert(des.recommendation.includes('Replace'), 'DES recommends immediate replacement');

  const md5 = getMigrationGuidance('MD5', 'integrity_hashing');
  assert.strictEqual(md5.hybridByDefault, false, 'MD5 requires direct replacement, not hybrid');
  assert(md5.recommendation.includes('Replace'), 'MD5 recommends immediate replacement');

  console.log('✓ Test 2 Passed: Symmetric, hashing, and broken ciphers correctly evaluate hybridByDefault: false');
}

// ----------------------------------------------------
// 3. Crypto-agility score calculation
// ----------------------------------------------------
{
  // ECDH with 256-bit key in key_exchange (curve modularity 40 + key 30 + protocol negotiation 30 = 100)
  const scoreEcdh = calculateCryptoAgilityScore('ECC', 'key_exchange', { keySize: 256 });
  assert.strictEqual(scoreEcdh, 100, 'Modern curve key exchange achieves max agility (100)');

  // RSA-2048 in digital_signature (modularity 30 + standard key 30 + X.509 format 25 = 85)
  const scoreRsa = calculateCryptoAgilityScore('RSA', 'digital_signature', { keySize: 2048 });
  assert.strictEqual(scoreRsa, 85, 'RSA-2048 digital signature achieves 85 agility score');

  // AES-128 in data_encryption (modularity 35 + key 20 + storage 20 = 75)
  const scoreAes = calculateCryptoAgilityScore('AES', 'data_encryption', { keySize: 128 });
  assert.strictEqual(scoreAes, 75, 'AES-128 data encryption achieves 75 agility score');

  // DES-56 in ECB mode (modularity 10 + small key 5 + rigid ECB 5 = 20)
  const scoreDes = calculateCryptoAgilityScore('DES', 'data_encryption', { keySize: 56, mode: 'ECB' });
  assert.strictEqual(scoreDes, 20, 'DES in ECB mode exhibits low agility (20)');

  // MD5 in password_hashing (modularity 10 + fixed 5 + stored hashes 10 = 25)
  const scoreMd5 = calculateCryptoAgilityScore('MD5', 'password_hashing');
  assert.strictEqual(scoreMd5, 25, 'MD5 in password hashing exhibits low agility (25)');

  console.log('✓ Test 3 Passed: Crypto-agility scores computed deterministically from crypto characteristics');
}

// ----------------------------------------------------
// 4. Score bounds (strictly within [0, 100])
// ----------------------------------------------------
{
  const cases = [
    { family: 'ECC', purpose: 'key_exchange', opts: { keySize: 521 } },
    { family: 'RSA', purpose: 'digital_signature', opts: { keySize: 4096 } },
    { family: 'DES', purpose: 'data_encryption', opts: { keySize: 56, mode: 'ECB' } },
    { family: 'UNKNOWN', purpose: 'unknown', opts: {} },
    { family: null, purpose: null, opts: {} },
  ];

  for (const c of cases) {
    const score = calculateCryptoAgilityScore(c.family, c.purpose, c.opts);
    assert(typeof score === 'number', 'score is a number');
    assert(Number.isInteger(score), 'score is an integer');
    assert(score >= 0 && score <= 100, `score ${score} is strictly within [0, 100]`);
  }

  console.log('✓ Test 4 Passed: Crypto-agility scores strictly bounded within [0, 100]');
}

// ----------------------------------------------------
// 5. Unknown algorithms and unmapped purposes
// ----------------------------------------------------
{
  // Unknown primitive family
  const unknownGuidance = getMigrationGuidance('CUSTOM_PRIMITIVE_XYZ', 'encryption');
  assert.strictEqual(unknownGuidance.recommendation, 'Manual review required');
  assert.strictEqual(unknownGuidance.hybridByDefault, false, 'unknown primitives default hybridByDefault: false');
  assert.strictEqual(unknownGuidance.cryptoAgilityScore, 30, 'unknown primitives assign conservative baseline (30)');

  // Known primitive with unknown purpose
  const rsaUnknown = getMigrationGuidance('RSA', 'unknown_purpose_999');
  assert(rsaUnknown.recommendation.includes('ML-KEM or ML-DSA'), 'falls back gracefully to family unknown mapping');
  assert.strictEqual(rsaUnknown.hybridByDefault, false, 'unmapped purpose does not assume hybrid');

  console.log('✓ Test 5 Passed: Unknown algorithms and purposes handled safely with manual review triggers');
}

// ----------------------------------------------------
// 6. Existing purpose detection mappings preserved
// ----------------------------------------------------
{
  const declaredFinding = { context: { usageType: 'signature' } };
  const detectedDeclared = detectPurpose(declaredFinding);
  assert.strictEqual(detectedDeclared.purpose, 'digital_signature');
  assert.strictEqual(detectedDeclared.confidence, 'declared');

  const inferredFinding = { context: { functionName: 'performHandshakeAndDeriveSessionKey' } };
  const detectedInferred = detectPurpose(inferredFinding);
  assert.strictEqual(detectedInferred.purpose, 'key_exchange');
  assert.strictEqual(detectedInferred.confidence, 'inferred');

  const emptyFinding = { context: {} };
  const detectedEmpty = detectPurpose(emptyFinding);
  assert.strictEqual(detectedEmpty.purpose, 'unknown');
  assert.strictEqual(detectedEmpty.confidence, 'unresolved');

  console.log('✓ Test 6 Passed: Existing declared and keyword-inferred purpose detection preserved');
}

// ----------------------------------------------------
// 7. Existing recommendation fields compatibility
// ----------------------------------------------------
{
  const guidance = getMigrationGuidance('RSA', 'digital_signature', { keySize: 2048 });
  assert(guidance.recommendation, 'has recommendation');
  assert(guidance.standard, 'has standard');
  assert(guidance.rationale, 'has rationale');
  assert.strictEqual(typeof guidance.hybridByDefault, 'boolean', 'has boolean hybridByDefault');
  assert.strictEqual(typeof guidance.cryptoAgilityScore, 'number', 'has numeric cryptoAgilityScore');

  console.log('✓ Test 7 Passed: All existing recommendation fields and structures fully backward compatible');
}

// ----------------------------------------------------
// 8. CBOM output compatibility
// ----------------------------------------------------
{
  const scan = {
    scanId: 'scan-pqc-test',
    repoId: 'repo-pqc',
    version: 1,
    rawFindings: [
      {
        id: 'f1',
        algorithm: 'RSA-2048',
        primitive: 'RSA',
        keySize: 2048,
        context: { usageType: 'signature' },
        file: 'auth.js',
        line: 12,
      },
      {
        id: 'f2',
        algorithm: 'AES-256',
        primitive: 'AES',
        keySize: 256,
        context: { usageType: 'encryption' },
        file: 'db.js',
        line: 45,
      },
    ],
  };

  const findingsResponse = buildFindingsResponse(scan);
  assert.strictEqual(findingsResponse.findings.length, 2);

  const f1 = findingsResponse.findings[0];
  assert.strictEqual(f1.pqcMigration.hybridByDefault, true);
  assert.strictEqual(f1.pqcMigration.cryptoAgilityScore, 85);

  const f2 = findingsResponse.findings[1];
  assert.strictEqual(f2.pqcMigration.hybridByDefault, false);
  assert.strictEqual(f2.pqcMigration.cryptoAgilityScore, 85); // AES-256 (35 + 30 + 20)

  const cbom = buildCbom(scan);
  assert.strictEqual(cbom.bomFormat, 'CycloneDX');
  assert.strictEqual(cbom.components.length, 2);

  console.log('✓ Test 8 Passed: Enriched recommendation output flows seamlessly into CBOM and findings payloads');
}

console.log('\nAll 8 PQC Recommendation Engine tests passed successfully!');
