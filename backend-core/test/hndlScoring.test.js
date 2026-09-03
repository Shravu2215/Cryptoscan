/**
 * HNDL / Quantum Risk Modeling Test Suite (Person 3 — Phase 4)
 *
 * Requirements:
 *  - 5-factor weighted risk score model with deterministic weights summing to 1.0
 *  - Data lifetime input support (via finding property or function argument)
 *  - Quantum Exposure Window calculation based on Mosca's Theorem (X + Y > Z)
 *  - Short vs long data lifetime behavior (long lifetime increases exposure and risk)
 *  - Missing data lifetime backward compatibility using safe default
 *  - Zero, negative, invalid, and extreme data lifetime values handled safely
 *  - Exposes dataLifetime, quantumExposureWindow, quantumRiskFactor, finalWeightedRiskScore
 *  - Preserves existing vulnerability scoring behavior for critical/low primitives
 */

const assert = require('assert');
const {
  scoreFinding,
  calculateQuantumExposureWindow,
  quantumExposureScore,
  normalizeDataLifetime,
  HNDL_CONFIG,
  WEIGHTS,
} = require('../src/services/vulnScoring');

console.log('Running HNDL / Quantum Risk Modeling (Phase 4) Test Suite...');

// ----------------------------------------------------
// 1. Valid data-lifetime inputs and exposed properties
// ----------------------------------------------------
{
  const finding = { primitive: 'RSA', keySize: 2048, mode: null };
  const res = scoreFinding(finding, 'digital_signature', 15);

  assert.strictEqual(typeof res.score, 'number', 'score is a number');
  assert.strictEqual(res.finalWeightedRiskScore, res.score, 'finalWeightedRiskScore matches score');
  assert.strictEqual(res.dataLifetime, 15, 'dataLifetime is 15');
  assert.strictEqual(res.dataLifetimeYears, 15, 'dataLifetimeYears is 15');
  assert.strictEqual(typeof res.quantumExposureWindow, 'number', 'quantumExposureWindow is a number');
  assert.strictEqual(typeof res.quantumRiskFactor, 'number', 'quantumRiskFactor is a number');
  assert.ok(res.breakdown && res.breakdown.quantumExposure !== undefined, 'breakdown includes quantumExposure');
  assert.ok(res.hndl && res.hndl.crqcHorizonYears === 7, 'hndl block includes CRQC horizon');

  console.log('✓ Test 1 Passed: Valid data-lifetime inputs and all required properties exposed');
}

// ----------------------------------------------------
// 2. Quantum exposure window calculation (Mosca's Theorem)
// ----------------------------------------------------
{
  // Window = max(0, (lifetime + migrationTime - crqcHorizon)) = max(0, lifetime + 3 - 7)
  assert.strictEqual(calculateQuantumExposureWindow(1), 0, '1 year lifetime -> 0 window (expires before CRQC)');
  assert.strictEqual(calculateQuantumExposureWindow(4), 0, '4 years lifetime -> 0 window');
  assert.strictEqual(calculateQuantumExposureWindow(5), 1, '5 years lifetime -> 1 year window');
  assert.strictEqual(calculateQuantumExposureWindow(10), 6, '10 years lifetime -> 6 years window');
  assert.strictEqual(calculateQuantumExposureWindow(25), 21, '25 years lifetime -> 21 years window');

  console.log('✓ Test 2 Passed: Quantum exposure window accurately follows Mosca theorem');
}

// ----------------------------------------------------
// 3. Short vs long data lifetime behavior
// ----------------------------------------------------
{
  const rsaFinding = { primitive: 'RSA', keySize: 2048 };

  // Short lifetime (1 year): expires before quantum computer arrives -> zero quantum exposure
  const shortRes = scoreFinding(rsaFinding, 'digital_signature', 1);
  assert.strictEqual(shortRes.quantumExposureWindow, 0, 'short lifetime has 0 exposure window');
  assert.strictEqual(shortRes.quantumRiskFactor, 0, 'short lifetime has 0 quantum risk factor');

  // Long lifetime (25 years): persisted far past CRQC horizon -> maximum quantum exposure
  const longRes = scoreFinding(rsaFinding, 'digital_signature', 25);
  assert.strictEqual(longRes.quantumExposureWindow, 21, 'long lifetime has 21-year exposure window');
  assert.strictEqual(longRes.quantumRiskFactor, 100, 'long lifetime has 100 quantum risk factor');

  // Long data lifetime must result in a strictly higher risk score
  assert.ok(
    longRes.score > shortRes.score,
    `Long lifetime score (${longRes.score}) must exceed short lifetime score (${shortRes.score})`
  );
  assert.strictEqual(longRes.score - shortRes.score, 15, '15-point difference aligns with 0.15 weight');

  console.log('✓ Test 3 Passed: Long data lifetime correctly elevates quantum exposure and risk score');
}

// ----------------------------------------------------
// 4. 5-factor weighted risk score verification
// ----------------------------------------------------
{
  // Verify weights sum to 1.00
  const weightSum =
    WEIGHTS.quantumVulnerability +
    WEIGHTS.keyStrength +
    WEIGHTS.classicalDeprecation +
    WEIGHTS.usageCriticality +
    WEIGHTS.quantumExposure;
  assert.strictEqual(Math.round(weightSum * 1000) / 1000, 1.0, 'Weights sum strictly to 1.0');

  const finding = { primitive: 'AES', keySize: 128, mode: 'CBC', dataLifetime: 10 };
  const res = scoreFinding(finding, 'data_encryption');

  const expectedRaw =
    res.breakdown.quantumVulnerability * WEIGHTS.quantumVulnerability +
    res.breakdown.keyStrength * WEIGHTS.keyStrength +
    res.breakdown.classicalDeprecation * WEIGHTS.classicalDeprecation +
    res.breakdown.usageCriticality * WEIGHTS.usageCriticality +
    res.breakdown.quantumExposure * WEIGHTS.quantumExposure;

  assert.strictEqual(res.score, Math.round(expectedRaw), 'Score exactly matches 5-factor weighted sum');

  console.log('✓ Test 4 Passed: 5-factor weighted risk score matches formula exactly');
}

// ----------------------------------------------------
// 5. Missing data-lifetime backward compatibility
// ----------------------------------------------------
{
  const findingNoLifetime = { primitive: 'RSA', keySize: 2048 };
  const res = scoreFinding(findingNoLifetime, 'digital_signature');

  assert.strictEqual(res.dataLifetime, HNDL_CONFIG.defaultDataLifetimeYears, 'uses default 10-year lifetime');
  assert.strictEqual(res.hndl.isDefaultLifetime, true, 'identifies that default lifetime was applied');
  assert.ok(res.score > 0, 'produces valid non-zero score with default lifetime');

  console.log('✓ Test 5 Passed: Missing data lifetime falls back safely to backward-compatible default');
}

// ----------------------------------------------------
// 6. Zero, negative, and invalid inputs handled safely
// ----------------------------------------------------
{
  const finding = { primitive: 'RSA', keySize: 2048 };

  // Zero lifetime
  const zeroRes = scoreFinding(finding, 'digital_signature', 0);
  assert.strictEqual(zeroRes.dataLifetime, 0, 'zero lifetime accepted');
  assert.strictEqual(zeroRes.quantumExposureWindow, 0, 'zero lifetime yields 0 exposure window');
  assert.strictEqual(zeroRes.quantumRiskFactor, 0, 'zero lifetime yields 0 risk factor');

  // Negative lifetime
  const negRes = scoreFinding(finding, 'digital_signature', -5);
  assert.strictEqual(negRes.dataLifetime, 0, 'negative lifetime normalized to 0');
  assert.strictEqual(negRes.quantumExposureWindow, 0);

  // Invalid string
  const strRes = scoreFinding(finding, 'digital_signature', 'not-a-number');
  assert.strictEqual(strRes.dataLifetime, 0, 'invalid string normalized to 0');

  // NaN / null options
  const nanRes = scoreFinding(finding, 'digital_signature', NaN);
  assert.strictEqual(nanRes.dataLifetime, 0, 'NaN normalized to 0');

  console.log('✓ Test 6 Passed: Zero, negative, and invalid lifetime inputs handled safely');
}

// ----------------------------------------------------
// 7. Extreme lifetime values handled safely
// ----------------------------------------------------
{
  const finding = { primitive: 'RSA', keySize: 2048 };
  const extremeRes = scoreFinding(finding, 'digital_signature', 1000);

  assert.strictEqual(extremeRes.dataLifetime, 1000, 'extreme lifetime accepted');
  assert.strictEqual(extremeRes.quantumExposureWindow, 996, 'exposure window computed without crash');
  assert.strictEqual(extremeRes.quantumRiskFactor, 100, 'quantum risk factor capped at 100');
  assert.ok(extremeRes.score <= 100, 'final risk score never exceeds 100');

  console.log('✓ Test 7 Passed: Extreme lifetime values handled without overflow or uncapped scores');
}

// ----------------------------------------------------
// 8. Existing vulnerability scoring behavior preserved
// ----------------------------------------------------
{
  // MD5 password hashing must remain CRITICAL (>= 80)
  const md5Res = scoreFinding({ primitive: 'MD5', keySize: null }, 'password_hashing');
  assert.ok(md5Res.score >= 80, `MD5 password hashing score (${md5Res.score}) is >= 80`);
  assert.strictEqual(md5Res.severity, 'critical', 'MD5 severity is critical');

  // DES/ECB must remain CRITICAL (>= 80)
  const desRes = scoreFinding({ primitive: 'DES', keySize: 56, mode: 'ECB' }, 'data_encryption');
  assert.ok(desRes.score >= 80, `DES/ECB score (${desRes.score}) is >= 80`);
  assert.strictEqual(desRes.severity, 'critical', 'DES severity is critical');

  // SHA-256 integrity hashing must remain LOW/INFO (<= 40)
  const shaRes = scoreFinding({ primitive: 'SHA-256', keySize: null }, 'integrity_hashing');
  assert.ok(shaRes.score <= 40, `SHA-256 score (${shaRes.score}) is <= 40`);
  assert.ok(shaRes.severity === 'low' || shaRes.severity === 'info', 'SHA-256 is low or info');

  // Quantum-safe / resistant primitive (e.g. SHA-256) maintains near-zero quantum risk factor even with long lifetime
  const shaLong = scoreFinding({ primitive: 'SHA-256' }, 'integrity_hashing', 50);
  assert.ok(shaLong.quantumRiskFactor <= 20, 'quantum-resistant primitive maintains low quantum risk factor');

  console.log('✓ Test 8 Passed: Existing vulnerability scoring behavior perfectly preserved');
}

console.log('\nAll 8 HNDL / Quantum Risk Modeling tests passed successfully!');
