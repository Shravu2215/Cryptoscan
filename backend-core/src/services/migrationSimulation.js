/**
 * Migration Simulation Service (Person 3 — Phase 7)
 *
 * Non-mutating service that evaluates how a detected cryptographic component
 * could migrate to post-quantum cryptography.
 *
 * This module NEVER mutates:
 *   - source code
 *   - database records
 *   - scan state
 *   - CBOM data
 *   - blockchain/IPFS data
 *
 * It reuses the Phase 6 PQC recommendation engine and crypto-agility logic
 * as its single source of truth for recommendations.
 */

'use strict';

const { detectPurpose, getMigrationGuidance, calculateCryptoAgilityScore } = require('./purposeDetection');
const { normalizeFamily } = require('./primitiveFamily');
const { normalizeDataLifetime, calculateQuantumExposureWindow, quantumExposureScore, scoreFinding } = require('./vulnScoring');

// -----------------------------------------------------------------------
// Classification helpers
// -----------------------------------------------------------------------

/**
 * Primitives that are already PQC algorithms (NIST standardized or candidates).
 * No further migration needed — report as already-PQC.
 */
const ALREADY_PQC_PRIMITIVES = new Set([
  'ML-KEM', 'MLKEM', 'KYBER',
  'ML-DSA', 'MLDSA', 'DILITHIUM',
  'SLH-DSA', 'SLHDSA', 'SPHINCS',
  'FALCON',
  'BIKE', 'HQC', 'NTRU', 'FRODO',
  'XMSS', 'LMS',
  'CRYSTALS-KYBER', 'CRYSTALS-DILITHIUM',
]);

/**
 * Primitives that are quantum-resistant by nature and need no PQC migration.
 * (Symmetric and strong hash — only halved by Grover, still adequate at 256-bit.)
 */
const QUANTUM_RESISTANT_PRIMITIVES = {
  'AES': { adequateKeySize: 192 },
  'CHACHA20': { adequateKeySize: 0 },
  'SHA-256': { adequateKeySize: 0 },
  'SHA-384': { adequateKeySize: 0 },
  'SHA-512': { adequateKeySize: 0 },
  'SHA3-256': { adequateKeySize: 0 },
  'SHA3-512': { adequateKeySize: 0 },
  'HMAC': { adequateKeySize: 0 },
};

/**
 * Classically-broken primitives that require IMMEDIATE direct replacement
 * (not a PQC migration — they are broken TODAY regardless of quantum).
 */
const CLASSICALLY_BROKEN = new Set(['MD5', 'SHA1', 'SHA-1', 'DES', '3DES', 'RC4', 'RC2']);

// -----------------------------------------------------------------------
// Migration step generation
// -----------------------------------------------------------------------

const MIGRATION_STEPS_TABLE = {
  key_exchange: {
    RSA: [
      'Audit all RSA key-transport usages in scope (TLS, PKCS#7, CMS, etc.)',
      'Inventory all consumers that must validate the key exchange',
      'Select ML-KEM-768 (NIST FIPS 203) as the PQC KEM replacement',
      'Deploy hybrid mode: X25519/RSA alongside ML-KEM-768 during transition',
      'Update server-side TLS configuration to advertise hybrid KEM groups',
      'Verify client library support for hybrid KEM in all target environments',
      'Migrate to ML-KEM-768 exclusively after all consumers are updated',
      'Remove classical RSA key-exchange cipher suites from supported list',
      'Validate with PQC compliance test suite',
    ],
    ECC: [
      'Audit all ECDH usages (TLS handshake, ECIES, SSH ECDH, etc.)',
      'Inventory all consumers relying on this key agreement',
      'Select ML-KEM-768 (NIST FIPS 203) as the PQC KEM replacement',
      'Deploy hybrid mode: ECDH alongside ML-KEM-768 during transition',
      'Update TLS/SSH configurations to advertise hybrid KEM groups',
      'Verify PQC library support in all target runtime environments',
      'Transition exclusively to ML-KEM-768 after consumer readiness is confirmed',
      'Remove classical ECDH cipher suites from the supported configuration',
      'Validate with PQC compliance test suite',
    ],
    DH: [
      'Identify all finite-field DH usages in scope',
      'Select ML-KEM-768 (NIST FIPS 203) as the PQC KEM replacement',
      'Deploy hybrid mode: classic DH alongside ML-KEM during transition',
      'Update library and protocol configurations to negotiate hybrid KEM',
      'Migrate exclusively to ML-KEM after validation',
    ],
    DEFAULT: [
      'Audit the key-exchange mechanism and identify all dependents',
      'Evaluate ML-KEM (NIST FIPS 203) as the PQC replacement KEM',
      'Plan and execute a hybrid classical + PQC transition',
      'Validate before removing the classical mechanism',
    ],
  },
  digital_signature: {
    RSA: [
      'Audit all RSA signature usages (JWT, TLS certificates, code signing, etc.)',
      'Inventory all verifiers that must accept the new signature scheme',
      'Select ML-DSA-65 (NIST FIPS 204) as the primary PQC signature replacement',
      'Consider SLH-DSA-SHA2-128s as a conservative hash-based alternative',
      'Deploy dual-signing: sign with both RSA and ML-DSA during transition',
      'Update certificate authority to issue dual-algorithm certificates',
      'Update verifier code to accept either classical or PQC signatures',
      'Issue new certificates signed with ML-DSA exclusively after full roll-out',
      'Revoke legacy RSA-only certificates on completion',
      'Validate with a PQC compliance test suite and certificate transparency log',
    ],
    ECC: [
      'Audit all ECDSA/EdDSA signature usages in scope',
      'Inventory all verifiers',
      'Select ML-DSA-65 (NIST FIPS 204) as the PQC signature replacement',
      'Deploy dual-signing: ECDSA alongside ML-DSA during transition',
      'Update verifiers to accept ML-DSA signatures',
      'Transition exclusively to ML-DSA after verifier readiness is confirmed',
      'Remove ECDSA from signing path on completion',
      'Validate with a PQC compliance test suite',
    ],
    DSA: [
      'DSA is already deprecated — replace with ML-DSA (NIST FIPS 204) directly',
      'Audit all DSA signature usages and affected verifiers',
      'Deploy ML-DSA-65 in parallel with legacy DSA during transition',
      'Update verifiers to accept ML-DSA exclusively and remove DSA support',
    ],
    DEFAULT: [
      'Audit the signature scheme and identify all signers and verifiers',
      'Evaluate ML-DSA (NIST FIPS 204) as the primary PQC replacement',
      'Consider SLH-DSA (NIST FIPS 205) for conservative hash-based fallback',
      'Deploy dual-signing during transition and migrate verifiers first',
      'Remove the classical signature scheme after full validation',
    ],
  },
  data_encryption: {
    symmetric: [
      'Verify current key size meets the post-quantum minimum (AES-256 / ChaCha20-256)',
      'If key size is below 192-bit, upgrade to AES-256-GCM immediately',
      'Ensure an authenticated encryption mode (GCM, CCM) is used — not ECB/CBC',
      'Rotate encryption keys as part of normal key-management lifecycle',
      'No structural PQC algorithm migration required for AES-256 or ChaCha20-256',
    ],
    broken: [
      'DES/3DES is cryptographically broken — replace immediately',
      'Migrate to AES-256-GCM (NIST SP 800-38D) as the replacement cipher',
      'Audit all data encrypted under the broken cipher — re-encrypt with AES-256',
      'Remove the broken cipher from all supported configurations',
      'This is an URGENT classical security issue, not just a quantum migration',
    ],
  },
  password_hashing: [
    'MD5/SHA-1 password hashes are broken classically — replace immediately',
    'Migrate to Argon2id (RFC 9106) as the preferred password hashing function',
    'Alternatively use bcrypt (cost ≥ 12) or scrypt (N ≥ 2^17) as a fallback',
    'Force password reset for all affected users after hash migration',
    'This is an URGENT classical security issue independent of quantum risk',
  ],
  integrity_hashing: {
    broken: [
      'MD5/SHA-1 are broken for collision resistance — replace immediately',
      'Migrate to SHA-256 or SHA3-256 (FIPS 180-4 / FIPS 202)',
      'Re-hash all stored integrity digests using the new function',
    ],
    adequate: [
      'SHA-256 retains ~128-bit post-quantum preimage security under Grover\'s algorithm',
      'No structural algorithm migration needed; continue to use SHA-256 or upgrade to SHA-512',
      'Consider SHA3-256 for new implementations to improve agility',
    ],
  },
};

function buildMigrationSteps(primitiveFamily, purpose, finding = {}) {
  const pf = (primitiveFamily || '').toUpperCase();
  const p = (purpose || '').toLowerCase();
  const keySize = finding.keySize;

  if (ALREADY_PQC_PRIMITIVES.has(pf)) {
    return ['No migration required — this is already a post-quantum algorithm.'];
  }

  if (CLASSICALLY_BROKEN.has(pf)) {
    if (p === 'password_hashing') return MIGRATION_STEPS_TABLE.password_hashing;
    if (p === 'integrity_hashing') return MIGRATION_STEPS_TABLE.integrity_hashing.broken;
    return MIGRATION_STEPS_TABLE.data_encryption.broken;
  }

  const resistantInfo = QUANTUM_RESISTANT_PRIMITIVES[primitiveFamily] || QUANTUM_RESISTANT_PRIMITIVES[pf];
  if (resistantInfo !== undefined) {
    const isAdequate = !keySize || keySize >= (resistantInfo.adequateKeySize || 0);
    if (isAdequate) {
      if (p === 'integrity_hashing') return MIGRATION_STEPS_TABLE.integrity_hashing.adequate;
      return MIGRATION_STEPS_TABLE.data_encryption.symmetric;
    }
    return [
      `Key size ${keySize}-bit is below the post-quantum minimum for ${primitiveFamily}`,
      ...MIGRATION_STEPS_TABLE.data_encryption.symmetric,
    ];
  }

  // Quantum-vulnerable asymmetric
  const purposeTable = MIGRATION_STEPS_TABLE[p];
  if (purposeTable) {
    if (typeof purposeTable === 'object' && !Array.isArray(purposeTable)) {
      return purposeTable[pf] || purposeTable.DEFAULT || ['Review migration path with a cryptography specialist.'];
    }
    return purposeTable;
  }

  return [
    'Identify the precise usage of this cryptographic primitive',
    'Consult NIST PQC standards (FIPS 203, 204, 205) for the appropriate PQC replacement',
    'Plan a hybrid classical + PQC transition strategy',
    'Validate the migration with a PQC compliance test suite',
  ];
}

// -----------------------------------------------------------------------
// Core simulation function
// -----------------------------------------------------------------------

/**
 * Simulates a PQC migration plan for a single cryptographic component.
 *
 * @param {object} component - The crypto component to simulate migration for
 * @param {string} [component.algorithm] - Algorithm string (e.g. 'RSA-2048', 'AES-256')
 * @param {string} [component.primitive] - Primitive name (e.g. 'RSA', 'AES')
 * @param {string} [component.purpose] - Detected/declared purpose
 * @param {number} [component.keySize] - Key size in bits
 * @param {string} [component.mode] - Block cipher mode
 * @param {object} [component.context] - Scanner context for purpose detection
 * @param {number} [component.dataLifetime] - Data lifetime in years (for HNDL)
 * @param {string} [component.businessImportance] - Business context
 *
 * @returns {object} Structured migration simulation plan (read-only)
 */
function simulateMigration(component) {
  if (!component || typeof component !== 'object') {
    return {
      error: 'Invalid input: component must be a non-null object',
      simulationValid: false,
    };
  }

  const algorithm = component.algorithm || component.primitive || 'UNKNOWN';
  const primitiveFamily = component.primitive
    ? normalizeFamily(component.primitive)
    : normalizeFamily(algorithm);

  // Determine purpose
  let purpose = component.purpose;
  let purposeConfidence = 'provided';
  let purposeSource = 'caller input';

  if (!purpose || purpose === 'unknown') {
    if (component.context) {
      const detected = detectPurpose(component);
      purpose = detected.purpose;
      purposeConfidence = detected.confidence;
      purposeSource = detected.source;
    } else {
      purpose = 'unknown';
      purposeConfidence = 'unresolved';
      purposeSource = 'no context provided';
    }
  }

  const normalizedPrimitive = (primitiveFamily || algorithm).toUpperCase();
  const keySize = component.keySize;
  const mode = component.mode;

  // ---- Classification ----
  const isAlreadyPQC = ALREADY_PQC_PRIMITIVES.has(normalizedPrimitive) ||
    ALREADY_PQC_PRIMITIVES.has((component.primitive || '').toUpperCase());

  const isClassicallyBroken = CLASSICALLY_BROKEN.has(normalizedPrimitive) ||
    CLASSICALLY_BROKEN.has((component.primitive || '').toUpperCase());

  const quantumResistantInfo = QUANTUM_RESISTANT_PRIMITIVES[primitiveFamily] ||
    QUANTUM_RESISTANT_PRIMITIVES[normalizedPrimitive];
  const isQuantumResistant = quantumResistantInfo !== undefined && !isClassicallyBroken;

  const isUnknown = !primitiveFamily || primitiveFamily === 'UNKNOWN';

  // ---- PQC recommendation from Phase 6 engine ----
  const pqcGuidance = getMigrationGuidance(primitiveFamily, purpose, component);

  // ---- Crypto-agility score from Phase 6 engine ----
  const cryptoAgilityScore = calculateCryptoAgilityScore(primitiveFamily, purpose, component);

  // ---- Risk/exposure from Phase 4 HNDL model ----
  const normLifetime = normalizeDataLifetime(component.dataLifetime);
  const quantumExposureWindow = calculateQuantumExposureWindow(normLifetime);

  let riskScore = null;
  let riskSeverity = null;
  try {
    const scored = scoreFinding(
      { ...component, primitive: primitiveFamily || algorithm },
      purpose,
      {
        dataLifetime: component.dataLifetime,
        businessImportance: component.businessImportance,
      }
    );
    riskScore = scored.preBusinessRiskScore;
    riskSeverity = scored.severity;
  } catch (_) {
    // If scoring fails, leave null — simulation is still valid
  }

  // ---- Migration steps ----
  const migrationSteps = buildMigrationSteps(primitiveFamily, purpose, component);

  // ---- Support/status ----
  let supportStatus;
  if (isAlreadyPQC) {
    supportStatus = 'already-pqc';
  } else if (isClassicallyBroken) {
    supportStatus = 'classically-broken';
  } else if (isQuantumResistant) {
    const adequate = !keySize || keySize >= (quantumResistantInfo.adequateKeySize || 0);
    supportStatus = adequate ? 'quantum-resistant' : 'quantum-weakened';
  } else if (isUnknown) {
    supportStatus = 'unknown';
  } else {
    supportStatus = 'quantum-vulnerable';
  }

  // ---- Hybrid recommendation ----
  const hybridRecommended = pqcGuidance.hybridByDefault === true;

  // ---- Build the simulation plan ----
  return {
    simulationValid: true,
    simulationOnly: true, // explicit non-mutation marker
    input: {
      algorithm,
      primitive: primitiveFamily || algorithm,
      purpose,
      purposeConfidence,
      purposeSource,
      keySize: keySize ?? null,
      mode: mode ?? null,
    },
    supportStatus,
    isAlreadyPQC,
    isClassicallyBroken,
    isQuantumResistant,
    pqcRecommendation: {
      algorithm: pqcGuidance.recommendation,
      standard: pqcGuidance.standard,
      rationale: pqcGuidance.rationale,
      hybridRecommended,
      hybridByDefault: pqcGuidance.hybridByDefault,
    },
    cryptoAgilityScore,
    riskExposure: {
      preBusinessRiskScore: riskScore,
      severity: riskSeverity,
      dataLifetimeYears: normLifetime.value,
      isDefaultLifetime: normLifetime.isDefault,
      quantumExposureWindow,
    },
    migrationSteps,
    summary: buildSummary(supportStatus, algorithm, pqcGuidance, hybridRecommended),
  };
}

function buildSummary(supportStatus, algorithm, pqcGuidance, hybridRecommended) {
  switch (supportStatus) {
    case 'already-pqc':
      return `${algorithm} is already a post-quantum algorithm — no migration required.`;
    case 'classically-broken':
      return `${algorithm} is classically broken and requires IMMEDIATE replacement independent of quantum risk.`;
    case 'quantum-resistant':
      return `${algorithm} is quantum-resistant at the current key size — no PQC migration required; focus on key hygiene.`;
    case 'quantum-weakened':
      return `${algorithm} is quantum-weakened (insufficient key size) — increase key size to meet post-quantum minimums.`;
    case 'quantum-vulnerable':
      return `${algorithm} is broken by Shor's algorithm — migrate to ${pqcGuidance.recommendation}${hybridRecommended ? ' using a hybrid classical+PQC transition' : ''}.`;
    case 'unknown':
      return `${algorithm} is an unrecognized primitive — flag for manual cryptographic review before planning any migration.`;
    default:
      return `Migration simulation completed for ${algorithm}.`;
  }
}

// -----------------------------------------------------------------------
// Multi-component simulation
// -----------------------------------------------------------------------

/**
 * Simulates migration for multiple components simultaneously.
 * Strictly non-mutating — does not alter any stored data.
 *
 * @param {object[]} components - Array of crypto components
 * @returns {object} Batch simulation result
 */
function simulateMigrationBatch(components) {
  if (!Array.isArray(components)) {
    return {
      error: 'Invalid input: components must be an array',
      simulationValid: false,
    };
  }
  if (components.length === 0) {
    return {
      simulationValid: true,
      simulationOnly: true,
      totalComponents: 0,
      results: [],
      summary: 'No components provided for simulation.',
    };
  }

  const results = components.map((c, idx) => {
    try {
      return { index: idx, ...simulateMigration(c) };
    } catch (err) {
      return {
        index: idx,
        simulationValid: false,
        error: `Simulation failed for component at index ${idx}: ${err.message}`,
      };
    }
  });

  const counts = results.reduce((acc, r) => {
    acc[r.supportStatus || 'error'] = (acc[r.supportStatus || 'error'] || 0) + 1;
    return acc;
  }, {});

  return {
    simulationValid: true,
    simulationOnly: true,
    totalComponents: components.length,
    counts,
    results,
    summary: buildBatchSummary(counts, components.length),
  };
}

function buildBatchSummary(counts, total) {
  const parts = [];
  if (counts['quantum-vulnerable']) parts.push(`${counts['quantum-vulnerable']} quantum-vulnerable`);
  if (counts['classically-broken']) parts.push(`${counts['classically-broken']} classically broken`);
  if (counts['quantum-weakened']) parts.push(`${counts['quantum-weakened']} quantum-weakened`);
  if (counts['quantum-resistant']) parts.push(`${counts['quantum-resistant']} quantum-resistant`);
  if (counts['already-pqc']) parts.push(`${counts['already-pqc']} already PQC`);
  if (counts['unknown']) parts.push(`${counts['unknown']} unknown`);
  return `Batch migration simulation of ${total} component(s): ${parts.join(', ') || 'no classifications'}.`;
}

module.exports = {
  simulateMigration,
  simulateMigrationBatch,
};
