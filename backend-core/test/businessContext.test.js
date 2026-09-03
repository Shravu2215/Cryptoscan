/**
 * Business Context Weighting Test Suite (Person 3 — Phase 5)
 *
 * Requirements:
 *  - Business importance classification: Critical, Important, Standard
 *  - Deterministic business-context multipliers applied to 5-factor risk score
 *  - Configurable/extendable multipliers
 *  - Preserves underlying 5-factor HNDL scoring
 *  - Missing and invalid business context safely defaults to Standard (1.0x)
 *  - Exposes businessImportance, appliedMultiplier, preBusinessRiskScore, finalRiskScore
 *  - Score boundary clamping strictly within [0, 100]
 *  - Repository business context persists consistently across future scans
 */

const assert = require('assert');
const {
  scoreFinding,
  applyBusinessContext,
  normalizeBusinessImportance,
  DEFAULT_BUSINESS_MULTIPLIERS,
} = require('../src/services/vulnScoring');
const {
  setRepoBusinessImportance,
  getRepoBusinessImportance,
  clearRepoBusinessImportance,
} = require('../src/services/repoContext');
const { buildCbom } = require('../src/services/cbomGenerator');

console.log('Running Business Context Weighting (Phase 5) Test Suite...');

const sampleFinding = {
  primitive: 'RSA',
  keySize: 2048,
  dataLifetime: 1, // Short lifetime: pre-business score is 53
};

// ----------------------------------------------------
// 1. Critical multiplier (1.25x)
// ----------------------------------------------------
{
  const res = scoreFinding(sampleFinding, 'digital_signature', { businessImportance: 'Critical' });

  assert.strictEqual(res.businessImportance, 'Critical', 'identifies Critical importance');
  assert.strictEqual(res.appliedMultiplier, 1.25, 'applies 1.25 multiplier for Critical');
  assert.strictEqual(res.preBusinessRiskScore, 53, 'preBusinessRiskScore is 53');
  assert.strictEqual(res.finalRiskScore, 66, 'finalRiskScore is round(53 * 1.25) = 66');
  assert.strictEqual(res.score, 66, 'top-level score matches finalRiskScore');
  assert.strictEqual(res.businessContext.appliedMultiplier, 1.25);

  console.log('✓ Test 1 Passed: Critical business importance correctly applies 1.25x multiplier');
}

// ----------------------------------------------------
// 2. Important multiplier (1.10x)
// ----------------------------------------------------
{
  const res = scoreFinding(sampleFinding, 'digital_signature', { businessImportance: 'Important' });

  assert.strictEqual(res.businessImportance, 'Important', 'identifies Important importance');
  assert.strictEqual(res.appliedMultiplier, 1.10, 'applies 1.10 multiplier for Important');
  assert.strictEqual(res.preBusinessRiskScore, 53, 'preBusinessRiskScore is 53');
  assert.strictEqual(res.finalRiskScore, 58, 'finalRiskScore is round(53 * 1.10) = 58');
  assert.strictEqual(res.score, 58);

  console.log('✓ Test 2 Passed: Important business importance correctly applies 1.10x multiplier');
}

// ----------------------------------------------------
// 3. Standard multiplier (1.00x)
// ----------------------------------------------------
{
  const res = scoreFinding(sampleFinding, 'digital_signature', { businessImportance: 'Standard' });

  assert.strictEqual(res.businessImportance, 'Standard', 'identifies Standard importance');
  assert.strictEqual(res.appliedMultiplier, 1.00, 'applies 1.00 multiplier for Standard');
  assert.strictEqual(res.preBusinessRiskScore, 53);
  assert.strictEqual(res.finalRiskScore, 53, 'finalRiskScore matches preBusinessRiskScore under 1.0x');
  assert.strictEqual(res.score, 53);

  console.log('✓ Test 3 Passed: Standard business importance maintains baseline 1.00x multiplier');
}

// ----------------------------------------------------
// 4. Missing context -> safely defaults to Standard
// ----------------------------------------------------
{
  // 4a. Undefined businessImportance
  const resUndefined = scoreFinding(sampleFinding, 'digital_signature');
  assert.strictEqual(resUndefined.businessImportance, 'Standard');
  assert.strictEqual(resUndefined.appliedMultiplier, 1.00);
  assert.strictEqual(resUndefined.finalRiskScore, resUndefined.preBusinessRiskScore);

  // 4b. null businessImportance
  const resNull = scoreFinding(sampleFinding, 'digital_signature', { businessImportance: null });
  assert.strictEqual(resNull.businessImportance, 'Standard');
  assert.strictEqual(resNull.appliedMultiplier, 1.00);

  console.log('✓ Test 4 Passed: Missing business context safely defaults to Standard (1.0x)');
}

// ----------------------------------------------------
// 5. Invalid context -> safely defaults to Standard
// ----------------------------------------------------
{
  // 5a. Unrecognized string
  const resUnknown = scoreFinding(sampleFinding, 'digital_signature', { businessImportance: 'Tier-1-Enterprise' });
  assert.strictEqual(resUnknown.businessImportance, 'Standard');
  assert.strictEqual(resUnknown.appliedMultiplier, 1.00);

  // 5b. Non-string input (number)
  const resNum = scoreFinding(sampleFinding, 'digital_signature', { businessImportance: 999 });
  assert.strictEqual(resNum.businessImportance, 'Standard');
  assert.strictEqual(resNum.appliedMultiplier, 1.00);

  // 5c. Case-insensitivity support ('critical' -> 'Critical')
  const resLower = scoreFinding(sampleFinding, 'digital_signature', { businessImportance: 'critical' });
  assert.strictEqual(resLower.businessImportance, 'Critical');
  assert.strictEqual(resLower.appliedMultiplier, 1.25);

  console.log('✓ Test 5 Passed: Invalid context defaults to Standard, case variations normalized');
}

// ----------------------------------------------------
// 6. Score boundary handling (strictly [0, 100])
// ----------------------------------------------------
{
  // High pre-business score (95) multiplied by 1.25 would be 118.75 -> must clamp to 100
  const highBoundary = applyBusinessContext(95, 'Critical');
  assert.strictEqual(highBoundary.preBusinessRiskScore, 95);
  assert.strictEqual(highBoundary.finalRiskScore, 100, 'Score is clamped at 100 maximum');

  // Zero score multiplied by 1.25 is 0 -> never negative
  const zeroBoundary = applyBusinessContext(0, 'Critical');
  assert.strictEqual(zeroBoundary.finalRiskScore, 0, 'Zero score remains 0');

  console.log('✓ Test 6 Passed: Score boundary clamping strictly enforces [0, 100] range');
}

// ----------------------------------------------------
// 7. Existing 5-factor HNDL scoring remains unchanged
// ----------------------------------------------------
{
  const resCritical = scoreFinding(sampleFinding, 'digital_signature', { businessImportance: 'Critical' });
  const resStandard = scoreFinding(sampleFinding, 'digital_signature', { businessImportance: 'Standard' });

  // Pre-business risk scores and 5-factor breakdowns must be identical
  assert.strictEqual(resCritical.preBusinessRiskScore, resStandard.preBusinessRiskScore);
  assert.deepStrictEqual(resCritical.breakdown, resStandard.breakdown);
  assert.strictEqual(resCritical.quantumExposureWindow, resStandard.quantumExposureWindow);
  assert.strictEqual(resCritical.quantumRiskFactor, resStandard.quantumRiskFactor);

  console.log('✓ Test 7 Passed: 5-factor HNDL scoring calculations remain perfectly preserved');
}

// ----------------------------------------------------
// 8. Repository context persists across future scans
// ----------------------------------------------------
{
  clearRepoBusinessImportance();

  const targetRepoId = 'repo-payments-engine';
  setRepoBusinessImportance(targetRepoId, 'Critical');

  assert.strictEqual(getRepoBusinessImportance(targetRepoId), 'Critical');

  // Future scan 1 inherits Critical importance
  const cbomScan1 = buildCbom({
    scanId: 'scan-pay-1',
    repoId: targetRepoId,
    version: 1,
    rawFindings: [{ id: 'f1', algorithm: 'RSA-2048', file: 'pay.js', usage: 'signing' }],
  });
  assert.strictEqual(cbomScan1.businessImportance, 'Critical');

  // Future scan 2 (subsequent scan) of the same repo inherits Critical importance
  const cbomScan2 = buildCbom({
    scanId: 'scan-pay-2',
    repoId: targetRepoId,
    version: 2,
    rawFindings: [{ id: 'f2', algorithm: 'RSA-2048', file: 'pay.js', usage: 'signing' }],
  });
  assert.strictEqual(cbomScan2.businessImportance, 'Critical');

  // Another repo without set importance defaults to Standard
  const cbomOther = buildCbom({
    scanId: 'scan-other-1',
    repoId: 'repo-internal-docs',
    version: 1,
    rawFindings: [{ id: 'f3', algorithm: 'RSA-2048', file: 'doc.js', usage: 'signing' }],
  });
  assert.strictEqual(cbomOther.businessImportance, 'Standard');

  console.log('✓ Test 8 Passed: Repository business context persists consistently across future scans');
}

// ----------------------------------------------------
// 9. Configurable / extendable multipliers
// ----------------------------------------------------
{
  const customConfig = { Critical: 1.50 };
  const customRes = applyBusinessContext(50, 'Critical', customConfig);
  assert.strictEqual(customRes.appliedMultiplier, 1.50, 'uses customized multiplier');
  assert.strictEqual(customRes.finalRiskScore, 75, 'applies custom 1.50x multiplier (50 -> 75)');

  console.log('✓ Test 9 Passed: Multipliers are fully configurable and extendable');
}

console.log('\nAll 9 Business Context Weighting tests passed successfully!');
