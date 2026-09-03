/**
 * CBOM Diff Test Suite (Person 3 — Phase 3)
 *
 * Requirements:
 *  - First scan -> no previous CBOM (hasPrevious: false)
 *  - v1 -> v2 with added component detected
 *  - v1 -> v2 with removed component detected
 *  - v1 -> v2 with changed component detected with specific change details
 *  - Unchanged CBOM -> identical: true, empty added/removed/changed
 *  - Multiple repositories remain isolated
 *  - Malformed / missing previous CBOM handled safely
 *  - Existing CBOM 2.0 provenance and CycloneDX dependencies remain intact
 */

const assert = require('assert');
const { buildCbom } = require('../src/services/cbomGenerator');
const { computeCbomDiff } = require('../src/services/cbomDiff');

console.log('Running CBOM Diff (Phase 3) Test Suite...');

const findingRsa = {
  id: 'f-rsa',
  file: 'src/auth.js',
  line: 20,
  algorithm: 'RSA-2048',
  severity: 'MEDIUM',
  usage: 'digital_signature',
};

const findingSha = {
  id: 'f-sha',
  file: 'src/hash.js',
  line: 15,
  algorithm: 'SHA-256',
  severity: 'LOW',
  usage: 'hash',
};

const findingMd5 = {
  id: 'f-md5',
  file: 'src/legacy.js',
  line: 42,
  algorithm: 'MD5',
  severity: 'CRITICAL',
  usage: 'password_hashing',
};

const findingAes = {
  id: 'f-aes',
  file: 'src/vault.js',
  line: 99,
  algorithm: 'AES-256-GCM',
  severity: 'LOW',
  usage: 'encryption',
};

// ----------------------------------------------------
// 1. First scan -> no previous CBOM
// ----------------------------------------------------
{
  const cbom1 = buildCbom({
    scanId: 'diff-scan-1',
    repoId: 'repo-diff-test',
    version: 1,
    rawFindings: [findingRsa, findingSha],
  });

  const diff = computeCbomDiff(cbom1, null);

  assert.strictEqual(diff.hasPrevious, false, 'hasPrevious is false for first scan');
  assert.strictEqual(diff.previousVersion, null, 'previousVersion is null');
  assert.strictEqual(diff.currentVersion, 'CBOM-v1', 'currentVersion is CBOM-v1');
  assert.strictEqual(diff.identical, false, 'identical is false');
  assert.strictEqual(diff.summary.addedCount, 2, 'all components marked as added in initial scan');
  assert.strictEqual(diff.summary.removedCount, 0, 'zero removed');
  assert.strictEqual(diff.summary.changedCount, 0, 'zero changed');
  assert.strictEqual(diff.added.length, 2, 'added array contains both components');
  assert.deepStrictEqual(diff.removed, [], 'removed is empty');
  assert.deepStrictEqual(diff.changed, [], 'changed is empty');

  console.log('✓ Test 1 Passed: First scan with no previous CBOM handled cleanly');
}

// ----------------------------------------------------
// 2. v1 -> v2 with added component
// ----------------------------------------------------
{
  const cbom1 = buildCbom({
    scanId: 'scan-add-v1',
    repoId: 'repo-diff-test',
    version: 1,
    rawFindings: [findingRsa],
  });

  const cbom2 = buildCbom({
    scanId: 'scan-add-v2',
    repoId: 'repo-diff-test',
    version: 2,
    rawFindings: [findingRsa, findingAes],
  });

  const diff = computeCbomDiff(cbom2, cbom1);

  assert.strictEqual(diff.hasPrevious, true, 'hasPrevious is true');
  assert.strictEqual(diff.previousVersion, 'CBOM-v1');
  assert.strictEqual(diff.currentVersion, 'CBOM-v2');
  assert.strictEqual(diff.identical, false);
  assert.strictEqual(diff.summary.addedCount, 1, 'detects 1 added component');
  assert.strictEqual(diff.summary.removedCount, 0);
  assert.strictEqual(diff.summary.changedCount, 0);
  assert.strictEqual(diff.summary.unchangedCount, 1);
  assert.strictEqual(diff.added[0].name, 'AES-256-GCM', 'identifies added component as AES-256-GCM');
  assert.strictEqual(diff.unchanged[0].name, 'RSA-2048', 'identifies unchanged component as RSA-2048');

  console.log('✓ Test 2 Passed: Added component correctly detected between v1 and v2');
}

// ----------------------------------------------------
// 3. v1 -> v2 with removed component
// ----------------------------------------------------
{
  const cbom1 = buildCbom({
    scanId: 'scan-rem-v1',
    repoId: 'repo-diff-test',
    version: 1,
    rawFindings: [findingRsa, findingMd5],
  });

  const cbom2 = buildCbom({
    scanId: 'scan-rem-v2',
    repoId: 'repo-diff-test',
    version: 2,
    rawFindings: [findingRsa], // MD5 was eradicated
  });

  const diff = computeCbomDiff(cbom2, cbom1);

  assert.strictEqual(diff.hasPrevious, true);
  assert.strictEqual(diff.summary.addedCount, 0, 'zero added');
  assert.strictEqual(diff.summary.removedCount, 1, 'detects 1 removed component');
  assert.strictEqual(diff.summary.changedCount, 0);
  assert.strictEqual(diff.summary.unchangedCount, 1);
  assert.strictEqual(diff.removed[0].name, 'MD5', 'identifies removed component as MD5');

  console.log('✓ Test 3 Passed: Removed component correctly detected between v1 and v2');
}

// ----------------------------------------------------
// 4. v1 -> v2 with changed component
// ----------------------------------------------------
{
  const v1Findings = [
    {
      id: 'f-rsa-1',
      file: 'src/auth.js',
      line: 20,
      algorithm: 'RSA-2048',
      severity: 'MEDIUM',
      usage: 'digital_signature',
    },
  ];

  const v2Findings = [
    {
      id: 'f-rsa-1',
      file: 'src/auth.js',
      line: 20,
      algorithm: 'RSA-2048',
      severity: 'HIGH', // escalated severity
      usage: 'digital_signature',
    },
    {
      id: 'f-rsa-2',
      file: 'src/gateway.js',
      line: 88,
      algorithm: 'RSA-2048', // new occurrence
      severity: 'HIGH',
      usage: 'digital_signature',
    },
  ];

  const cbom1 = buildCbom({
    scanId: 'scan-chg-v1',
    repoId: 'repo-diff-test',
    version: 1,
    rawFindings: v1Findings,
  });

  const cbom2 = buildCbom({
    scanId: 'scan-chg-v2',
    repoId: 'repo-diff-test',
    version: 2,
    rawFindings: v2Findings,
  });

  const diff = computeCbomDiff(cbom2, cbom1);

  assert.strictEqual(diff.hasPrevious, true);
  assert.strictEqual(diff.summary.addedCount, 0);
  assert.strictEqual(diff.summary.removedCount, 0);
  assert.strictEqual(diff.summary.changedCount, 1, 'detects 1 changed component');
  assert.strictEqual(diff.changed.length, 1);

  const changedItem = diff.changed[0];
  assert.strictEqual(changedItem.name, 'RSA-2048');
  assert.strictEqual(changedItem.changes.maxSeverity.previous, 'MEDIUM');
  assert.strictEqual(changedItem.changes.maxSeverity.current, 'HIGH');
  assert.strictEqual(changedItem.changes.maxVulnerabilityScore.previous, 50);
  assert.strictEqual(changedItem.changes.maxVulnerabilityScore.current, 75);
  assert.strictEqual(changedItem.changes.occurrences.previousCount, 1);
  assert.strictEqual(changedItem.changes.occurrences.currentCount, 2);
  assert.strictEqual(changedItem.changes.occurrences.addedCount, 1);

  console.log('✓ Test 4 Passed: Changed component and specific modifications clearly detected');
}

// ----------------------------------------------------
// 5. Unchanged CBOM -> identical diff
// ----------------------------------------------------
{
  const cbom1 = buildCbom({
    scanId: 'scan-eq-v1',
    repoId: 'repo-diff-test',
    version: 1,
    rawFindings: [findingRsa, findingSha],
  });

  const cbom2 = buildCbom({
    scanId: 'scan-eq-v2',
    repoId: 'repo-diff-test',
    version: 2,
    rawFindings: [findingRsa, findingSha],
  });

  const diff = computeCbomDiff(cbom2, cbom1);

  assert.strictEqual(diff.hasPrevious, true);
  assert.strictEqual(diff.identical, true, 'identical is true');
  assert.strictEqual(diff.summary.addedCount, 0);
  assert.strictEqual(diff.summary.removedCount, 0);
  assert.strictEqual(diff.summary.changedCount, 0);
  assert.strictEqual(diff.summary.unchangedCount, 2, 'both components unchanged');
  assert.deepStrictEqual(diff.added, []);
  assert.deepStrictEqual(diff.removed, []);
  assert.deepStrictEqual(diff.changed, []);

  console.log('✓ Test 5 Passed: Unchanged consecutive scans yield identical: true and empty diff');
}

// ----------------------------------------------------
// 6. Multiple repositories remain isolated
// ----------------------------------------------------
{
  // Repo A: RSA -> RSA + AES
  const repoACbom1 = buildCbom({ scanId: 'a1', repoId: 'repo-alpha', version: 1, rawFindings: [findingRsa] });
  const repoACbom2 = buildCbom({ scanId: 'a2', repoId: 'repo-alpha', version: 2, rawFindings: [findingRsa, findingAes] });

  // Repo B: MD5 -> SHA-256
  const repoBCbom1 = buildCbom({ scanId: 'b1', repoId: 'repo-beta', version: 1, rawFindings: [findingMd5] });
  const repoBCbom2 = buildCbom({ scanId: 'b2', repoId: 'repo-beta', version: 2, rawFindings: [findingSha] });

  const diffA = computeCbomDiff(repoACbom2, repoACbom1);
  const diffB = computeCbomDiff(repoBCbom2, repoBCbom1);

  assert.strictEqual(diffA.repoId, 'repo-alpha');
  assert.strictEqual(diffA.summary.addedCount, 1);
  assert.strictEqual(diffA.summary.removedCount, 0);
  assert.strictEqual(diffA.added[0].name, 'AES-256-GCM');

  assert.strictEqual(diffB.repoId, 'repo-beta');
  assert.strictEqual(diffB.summary.addedCount, 1);
  assert.strictEqual(diffB.summary.removedCount, 1);
  assert.strictEqual(diffB.added[0].name, 'SHA-256');
  assert.strictEqual(diffB.removed[0].name, 'MD5');

  console.log('✓ Test 6 Passed: Multiple repositories diffed independently without state cross-contamination');
}

// ----------------------------------------------------
// 7. Malformed / missing previous CBOM handled safely
// ----------------------------------------------------
{
  const validCbom = buildCbom({ scanId: 'valid-scan', version: 1, rawFindings: [findingRsa] });

  // 7a. undefined previous
  const diff1 = computeCbomDiff(validCbom, undefined);
  assert.strictEqual(diff1.hasPrevious, false);

  // 7b. empty object previous
  const diff2 = computeCbomDiff(validCbom, {});
  assert.strictEqual(diff2.hasPrevious, false);

  // 7c. components is not an array
  const diff3 = computeCbomDiff(validCbom, { components: 'invalid-string' });
  assert.strictEqual(diff3.hasPrevious, false);

  // 7d. null current and null previous
  const diff4 = computeCbomDiff(null, null);
  assert.strictEqual(diff4.hasPrevious, false);
  assert.strictEqual(diff4.summary.addedCount, 0);

  console.log('✓ Test 7 Passed: Malformed and missing CBOM inputs handled safely without throwing');
}

console.log('\nAll 7 CBOM Diff tests passed successfully!');
