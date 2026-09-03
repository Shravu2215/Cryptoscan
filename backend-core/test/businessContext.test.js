/**
 * Business Context Weighting Tests
 * Tests: CRITICAL/IMPORTANT/STANDARD multipliers, score capping at 100
 */
const path = require('path');
const { scoreFinding, getBusinessContextMultiplier } = require(
  path.join(__dirname, '../src/services/vulnScoring')
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

// --- 1. Multiplier values ---
console.log('\n1. Business Context Multiplier values');
assert(getBusinessContextMultiplier('CRITICAL') === 1.3, 'CRITICAL multiplier = 1.3');
assert(getBusinessContextMultiplier('IMPORTANT') === 1.15, 'IMPORTANT multiplier = 1.15');
assert(getBusinessContextMultiplier('STANDARD') === 1.0, 'STANDARD multiplier = 1.0');
assert(getBusinessContextMultiplier(undefined) === 1.0, 'undefined context defaults to 1.0');
assert(getBusinessContextMultiplier(null) === 1.0, 'null context defaults to 1.0');
assert(getBusinessContextMultiplier('critical') === 1.3, 'lowercase "critical" works (case-insensitive)');
assert(getBusinessContextMultiplier('UNKNOWN_TAG') === 1.0, 'unknown tag defaults to 1.0');

// --- 2. Score is higher for CRITICAL context ---
console.log('\n2. Score increases with business context criticality');
{
  const finding = { primitive: 'RSA', keySize: 1024 };
  const standard = scoreFinding(finding, 'key_exchange', { businessContext: 'STANDARD' });
  const important = scoreFinding(finding, 'key_exchange', { businessContext: 'IMPORTANT' });
  const critical = scoreFinding(finding, 'key_exchange', { businessContext: 'CRITICAL' });

  assert(critical.score >= important.score, 'CRITICAL score >= IMPORTANT score');
  assert(important.score >= standard.score, 'IMPORTANT score >= STANDARD score');
  assert(critical.breakdown.businessContextMultiplier === 1.3, 'CRITICAL multiplier in breakdown');
  assert(important.breakdown.businessContextMultiplier === 1.15, 'IMPORTANT multiplier in breakdown');
  assert(standard.breakdown.businessContextMultiplier === 1.0, 'STANDARD multiplier in breakdown');
}

// --- 3. Score is capped at 100 ---
console.log('\n3. Score capped at 100');
{
  // RSA-1024 is already extremely high risk; CRITICAL context should not push above 100
  const result = scoreFinding({ primitive: 'RSA', keySize: 512 }, 'digital_signature', { businessContext: 'CRITICAL' });
  assert(result.score <= 100, 'score is capped at 100 even with CRITICAL context');
  assert(result.score >= 0, 'score is never negative');
}

// --- 4. businessContext in breakdown ---
console.log('\n4. businessContext field in breakdown');
{
  const result = scoreFinding({ primitive: 'AES', keySize: 128 }, 'data_encryption', { businessContext: 'IMPORTANT' });
  assert(result.breakdown.businessContext === 'IMPORTANT', 'businessContext present in breakdown');
  assert(typeof result.breakdown.businessContextMultiplier === 'number', 'businessContextMultiplier is a number');
}

// --- 5. businessContext via finding.businessContext fallback ---
console.log('\n5. businessContext on finding object (fallback)');
{
  const finding = { primitive: 'RSA', keySize: 2048, businessContext: 'CRITICAL' };
  const r1 = scoreFinding(finding, 'digital_signature');
  const r2 = scoreFinding({ primitive: 'RSA', keySize: 2048 }, 'digital_signature', { businessContext: 'CRITICAL' });
  assert(r1.score === r2.score, 'businessContext on finding === businessContext in options');
}

console.log(`\n--- businessContext.test.js: ${passed} passed, ${failed} failed ---`);
if (failed > 0) process.exit(1);
