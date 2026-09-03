/**
 * PQC Engine Upgrades Tests
 * Tests: hybridRecommended flag, cryptoAgilityScore, getMigrationGuidance returns hybridRecommended
 */
const path = require('path');
const { getMigrationGuidance, isHybridRecommended, cryptoAgilityScore } = require(
  path.join(__dirname, '../src/services/purposeDetection')
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

// --- 1. hybridRecommended on quantum-vulnerable primitives ---
console.log('\n1. hybridRecommended for quantum-vulnerable primitives');
assert(isHybridRecommended('RSA', 'key_exchange') === true, 'RSA key_exchange → hybridRecommended=true');
assert(isHybridRecommended('ECC', 'digital_signature') === true, 'ECC digital_signature → hybridRecommended=true');
assert(isHybridRecommended('DH', 'key_exchange') === true, 'DH key_exchange → hybridRecommended=true');
assert(isHybridRecommended('DSA', 'digital_signature') === true, 'DSA digital_signature → hybridRecommended=true');

// --- 2. hybridRecommended false for symmetric/hash with "keep as-is" guidance ---
console.log('\n2. hybridRecommended=false for adequate symmetric/hash primitives');
assert(isHybridRecommended('AES', 'data_encryption') === false, 'AES → hybridRecommended=false');
assert(isHybridRecommended('ChaCha20', 'data_encryption') === false, 'ChaCha20 → hybridRecommended=false');
assert(isHybridRecommended('SHA-256', 'integrity_hashing') === false, 'SHA-256 → hybridRecommended=false');

// --- 3. hybridRecommended false for classically broken primitives ---
console.log('\n3. hybridRecommended=false for classically broken primitives');
assert(isHybridRecommended('MD5', 'integrity_hashing') === false, 'MD5 → hybridRecommended=false (classically broken)');
assert(isHybridRecommended('DES', 'data_encryption') === false, 'DES → hybridRecommended=false');

// --- 4. getMigrationGuidance includes hybridRecommended ---
console.log('\n4. getMigrationGuidance includes hybridRecommended field');
{
  const g = getMigrationGuidance('RSA', 'digital_signature');
  assert('hybridRecommended' in g, 'getMigrationGuidance result has hybridRecommended field');
  assert(g.hybridRecommended === true, 'RSA → hybridRecommended=true in guidance');
  assert(g.recommendation.includes('ML-DSA'), 'RSA digital_signature still recommends ML-DSA');
}
{
  const g = getMigrationGuidance('AES', 'data_encryption');
  assert(g.hybridRecommended === false, 'AES data_encryption → hybridRecommended=false');
}

// --- 5. cryptoAgilityScore — baseline (neutral context) ---
console.log('\n5. cryptoAgilityScore baseline');
{
  const score = cryptoAgilityScore({ primitive: 'RSA', keySize: 2048, context: {} });
  assert(typeof score === 'number', 'cryptoAgilityScore returns a number');
  assert(score >= 0 && score <= 100, 'cryptoAgilityScore in [0, 100]');
  assert(score === 50, 'neutral context → score = 50 (baseline)');
}

// --- 6. cryptoAgilityScore — hardcoded key reduces score ---
console.log('\n6. cryptoAgilityScore — rigidity penalties');
{
  const score = cryptoAgilityScore({
    primitive: 'RSA',
    keySize: 2048,
    context: { surroundingCode: 'hardcoded key 0xdeadbeef1234abcd', functionName: 'encrypt' },
  });
  assert(score < 50, `hardcoded key reduces agility score (got ${score})`);
}

// --- 7. cryptoAgilityScore — factory pattern increases score ---
console.log('\n7. cryptoAgilityScore — agility bonuses');
{
  const score = cryptoAgilityScore({
    primitive: 'AES',
    context: { functionName: 'getCipherFromFactory', surroundingCode: 'const key = process.env.AES_KEY' },
  });
  assert(score > 50, `factory + env-config boosts agility score (got ${score})`);
}

// --- 8. getMigrationGuidance for unknown primitive includes hybridRecommended ---
console.log('\n8. Unknown primitive guidance includes hybridRecommended');
{
  const g = getMigrationGuidance('UNKNOWN_ALGO', 'data_encryption');
  assert('hybridRecommended' in g, 'unknown primitive guidance has hybridRecommended');
  assert(g.hybridRecommended === true, 'unknown primitive defaults to hybridRecommended=true (conservative)');
}

console.log(`\n--- pqcRecommendation.test.js: ${passed} passed, ${failed} failed ---`);
if (failed > 0) process.exit(1);
