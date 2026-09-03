/**
 * Migration Simulation Engine (migrationSimulation.js)
 *
 * Simulates PQC migration for cryptographic components.
 * Returns structured projection results — never modifies inputs, never writes to DB.
 *
 * Implements the contract expected by backend-core/test/migrationSimulation.test.js
 */

'use strict';

const { getMigrationGuidance, isHybridRecommended } = require('./purposeDetection');
const { scoreFinding } = require('./vulnScoring');
const { calculateHndlRisk, PURPOSE_DATA_LIFETIME, DEFAULT_YEARS_TO_QUANTUM_THREAT } = require('./hndlEngine');

// --------------------------------------------------------------------------
// Classification helpers
// --------------------------------------------------------------------------

const ALREADY_PQC_PRIMITIVES = new Set([
  'ML-KEM', 'ML-DSA', 'SLH-DSA', 'FALCON', 'BIKE', 'HQC', 'CRYSTALS-KYBER', 'CRYSTALS-DILITHIUM',
  'SPHINCS+', 'NTRU', 'MCELIECE',
]);

const CLASSICALLY_BROKEN_PRIMITIVES = new Set([
  'MD5', 'SHA1', 'SHA-1', 'DES', '3DES', 'RC4', 'RC2', 'MD4', 'MD2',
]);

const QUANTUM_VULNERABLE_PRIMITIVES = new Set([
  'RSA', 'ECC', 'ECDSA', 'ECDH', 'DSA', 'DH', 'EDDSA', 'ELGAMAL',
]);

function classifyPrimitive(primitive) {
  const p = (primitive || '').toUpperCase().trim();
  if (!p) return 'unknown';
  if (ALREADY_PQC_PRIMITIVES.has(p)) return 'already-pqc';
  if (CLASSICALLY_BROKEN_PRIMITIVES.has(p)) return 'classically-broken';
  if (QUANTUM_VULNERABLE_PRIMITIVES.has(p)) return 'quantum-vulnerable';
  if (['AES', 'CHACHA20', 'SHA-256', 'SHA256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-512', 'HMAC'].includes(p)) return 'quantum-resistant';
  return 'unknown';
}

// --------------------------------------------------------------------------
// Crypto-agility score (deterministic, per-component)
// Scores how easy it is to migrate this algorithm based on purpose/primitive.
// --------------------------------------------------------------------------

const AGILITY_SCORES = {
  'ECC:key_exchange': 100,
  'ECC:digital_signature': 95,
  'RSA:digital_signature': 85,
  'RSA:key_exchange': 80,
  'DH:key_exchange': 75,
  'DSA:digital_signature': 70,
  'AES:data_encryption': 90,
  'SHA-256:integrity_hashing': 95,
  'ML-KEM:key_exchange': 100,
  'ML-DSA:digital_signature': 100,
};

function computeCryptoAgilityScore(primitive, purpose) {
  const p = (primitive || '').toUpperCase();
  const pur = (purpose || 'unknown').toLowerCase();
  const key = `${primitive}:${pur}`;
  if (AGILITY_SCORES[key] !== undefined) return AGILITY_SCORES[key];
  if (ALREADY_PQC_PRIMITIVES.has(p)) return 100;
  if (CLASSICALLY_BROKEN_PRIMITIVES.has(p)) return 20;
  if (QUANTUM_VULNERABLE_PRIMITIVES.has(p)) return 70;
  return 50;
}

// --------------------------------------------------------------------------
// Migration steps generator
// --------------------------------------------------------------------------

function generateMigrationSteps(primitive, purpose, status, hybridRecommended) {
  const p = (primitive || '').toUpperCase();

  if (status === 'already-pqc') {
    return [`This algorithm is already post-quantum safe — no migration needed.`];
  }

  if (status === 'classically-broken') {
    return [
      `URGENT: Replace ${primitive} immediately — it is classically broken today, independent of quantum threats.`,
      `Follow NIST FIPS 180-4 / FIPS 202 for approved replacements.`,
      `Update all call sites and remove any usage from production code.`,
    ];
  }

  if (status === 'quantum-resistant') {
    const steps = [`${primitive} is quantum-resistant at the current key size — no PQC migration required.`];
    if (p === 'AES') steps.push('Verify AES-256 is used (not AES-128) and that GCM or CCM mode is applied.');
    return steps;
  }

  // Quantum-vulnerable or unknown
  const guidance = getMigrationGuidance(primitive || 'UNKNOWN', purpose || 'unknown');
  const pqcTarget = guidance.recommendation || 'Manual review required';
  const standard = guidance.standard || 'NIST PQC standards';

  const steps = [
    `Identify all usages of ${primitive} for ${purpose} in the codebase.`,
    `Select PQC replacement: ${pqcTarget} (${standard}).`,
  ];

  if (hybridRecommended) {
    steps.push(`Deploy in hybrid mode: run ${primitive} and ${pqcTarget} in parallel (dual-signing or dual-KEM).`);
    steps.push(`Validate interoperability with all consumers before removing classical algorithm.`);
    steps.push(`Sunset classical ${primitive} once all parties support PQC.`);
  } else {
    steps.push(`Migrate directly to ${pqcTarget}.`);
    steps.push(`Update all dependent systems and key management infrastructure.`);
  }

  steps.push(`Test cryptographic correctness and run regression suite after migration.`);
  return steps;
}

// --------------------------------------------------------------------------
// Risk exposure (HNDL integration)
// --------------------------------------------------------------------------

function computeRiskExposure(primitive, purpose, keySize, dataLifetime) {
  const isDefaultLifetime = dataLifetime == null;
  const resolvedLifetime = isDefaultLifetime
    ? (PURPOSE_DATA_LIFETIME[purpose] || PURPOSE_DATA_LIFETIME.unknown)
    : Number(dataLifetime);

  const finding = { primitive: primitive || 'UNKNOWN', keySize };
  const scored = scoreFinding(finding, purpose || 'unknown');
  const hndl = calculateHndlRisk(purpose || 'unknown', scored.breakdown.quantumVulnerability, {
    dataLifetimeYears: resolvedLifetime,
  });

  return {
    preBusinessRiskScore: scored.score,
    dataLifetimeYears: resolvedLifetime,
    yearsToQuantumThreat: hndl.yearsToQuantumThreat,
    quantumExposureWindow: hndl.quantumExposureWindow,
    hndlRisk: hndl.hndlRisk,
    isDefaultLifetime,
  };
}

// --------------------------------------------------------------------------
// Core simulateMigration — single component
// --------------------------------------------------------------------------

function simulateMigration(input) {
  // Guard: null / non-object
  if (input === null || input === undefined || typeof input !== 'object' || Array.isArray(input)) {
    return {
      simulationValid: false,
      simulationOnly: true,
      error: 'Input must be a non-null, non-array object',
    };
  }

  const primitive = (input.primitive || input.algorithm || '').replace(/-\d+.*$/, '').toUpperCase().trim() || null;
  const primitiveRaw = input.primitive || (primitive ? primitive : 'UNKNOWN');
  const purpose = (input.purpose || 'unknown').toLowerCase();
  const keySize = input.keySize || null;
  const mode = input.mode || null;
  const dataLifetime = input.dataLifetime != null ? Number(input.dataLifetime) : null;

  const status = classifyPrimitive(primitiveRaw);
  const isAlreadyPQC = status === 'already-pqc';
  const isClassicallyBroken = status === 'classically-broken';
  const hybridRecommended = isHybridRecommended(primitiveRaw || 'UNKNOWN', purpose);

  const guidance = getMigrationGuidance(primitiveRaw || 'UNKNOWN', purpose);
  const pqcAlgorithm = guidance.recommendation || 'Manual review required';
  const pqcRecommendation = {
    algorithm: pqcAlgorithm,
    standard: guidance.standard || null,
    rationale: guidance.rationale || null,
    hybridRecommended,
    hybridByDefault: hybridRecommended,
  };

  const cryptoAgilityScore = computeCryptoAgilityScore(primitiveRaw, purpose);
  const migrationSteps = generateMigrationSteps(primitiveRaw, purpose, status, hybridRecommended);
  const riskExposure = computeRiskExposure(primitiveRaw, purpose, keySize, dataLifetime);

  let summary;
  if (isAlreadyPQC) {
    summary = `${primitiveRaw} is already post-quantum safe — migration already completed.`;
  } else if (isClassicallyBroken) {
    summary = `${primitiveRaw} requires IMMEDIATE replacement (classically broken, not a quantum issue).`;
  } else if (status === 'quantum-vulnerable') {
    summary = `${primitiveRaw} is vulnerable to Shor's algorithm on a CRQC — migrate to ${pqcAlgorithm}.`;
  } else if (status === 'quantum-resistant') {
    summary = `${primitiveRaw} is quantum-resistant and requires no migration at this time.`;
  } else {
    summary = `${primitiveRaw} classification unknown — manual crypto review required.`;
  }

  return {
    simulationValid: true,
    simulationOnly: true,
    supportStatus: status,
    isAlreadyPQC,
    isClassicallyBroken,
    primitive: primitiveRaw,
    purpose,
    keySize,
    mode,
    pqcRecommendation,
    cryptoAgilityScore,
    migrationSteps,
    riskExposure,
    summary,
  };
}

// --------------------------------------------------------------------------
// simulateMigrationBatch — array of components
// --------------------------------------------------------------------------

function simulateMigrationBatch(inputs) {
  if (!Array.isArray(inputs)) {
    return {
      simulationValid: false,
      simulationOnly: true,
      error: 'Input must be an array of component objects',
    };
  }

  const results = inputs.map((item) => simulateMigration(item));

  const counts = {
    'quantum-vulnerable': 0,
    'quantum-resistant': 0,
    'already-pqc': 0,
    'classically-broken': 0,
    'unknown': 0,
  };
  for (const r of results) {
    if (r.simulationValid && r.supportStatus) {
      counts[r.supportStatus] = (counts[r.supportStatus] || 0) + 1;
    }
  }

  return {
    simulationValid: true,
    simulationOnly: true,
    totalComponents: inputs.length,
    results,
    counts,
    summary: `Simulated ${inputs.length} component(s): ${counts['quantum-vulnerable']} quantum-vulnerable, ${counts['quantum-resistant']} quantum-resistant, ${counts['already-pqc']} already-PQC, ${counts['classically-broken']} classically-broken.`,
  };
}

module.exports = { simulateMigration, simulateMigrationBatch };
