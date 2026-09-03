/**
 * Migration Assessment Service (Person 3)
 *
 * Production-grade service that evaluates how cryptographic findings
 * in a real scan migrate to post-quantum cryptography.
 *
 * This module:
 *   - Reuses existing purpose detection and scoring logic.
 *   - Evaluates real scan findings.
 *   - Outputs a deterministic migration plan.
 */

'use strict';

const { detectPurpose, getMigrationGuidance, calculateCryptoAgilityScore } = require('./purposeDetection');
const { normalizeFamily } = require('./primitiveFamily');
const { normalizeDataLifetime, scoreFinding } = require('./vulnScoring');

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
 */
const CLASSICALLY_BROKEN = new Set(['MD5', 'SHA1', 'SHA-1', 'DES', '3DES', 'RC4', 'RC2']);

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
      'Deploy a hybrid scheme combining the classical algorithm with ML-KEM',
      'Transition exclusively to ML-KEM after successful hybrid validation',
    ],
  },
  digital_signature: {
    RSA: [
      'Audit all RSA signature usages (JWT, X.509, CMS, documents)',
      'Assess impact of increased signature sizes on the protocol/storage',
      'Select ML-DSA (NIST FIPS 204) as the primary replacement',
      'For firmware/bootloaders, consider SLH-DSA (FIPS 205) or LMS/XMSS',
      'Deploy hybrid signatures during the transition period',
      'Migrate roots of trust and intermediate CAs to PQC',
      'Transition exclusively to ML-DSA/SLH-DSA after all verifiers are updated',
    ],
    ECC: [
      'Audit all ECDSA/EdDSA signature usages',
      'Evaluate ML-DSA (NIST FIPS 204) as the PQC replacement',
      'Assess impact of increased signature sizes on network packets/storage',
      'Deploy hybrid signatures (ECDSA + ML-DSA) during transition',
      'Transition exclusively to ML-DSA once ecosystem supports it',
    ],
    DEFAULT: [
      'Audit signature mechanism usages',
      'Evaluate ML-DSA (NIST FIPS 204) or SLH-DSA (NIST FIPS 205)',
      'Implement hybrid signing during the transition',
      'Transition exclusively to PQC after ecosystem validation',
    ],
  },
  DEFAULT: [
    'Audit primitive usages and determine specific application constraints',
    'Consult NIST PQC standards (FIPS 203, 204, 205) for replacements',
    'Plan a hybrid deployment approach',
    'Validate with test vectors before full migration',
  ],
};

function generateMigrationSteps(primitiveFamily, purpose) {
  const purposeTable = MIGRATION_STEPS_TABLE[purpose] || MIGRATION_STEPS_TABLE.DEFAULT;
  return purposeTable[primitiveFamily] || purposeTable.DEFAULT || MIGRATION_STEPS_TABLE.DEFAULT;
}

/**
 * Assess a single finding for migration.
 * @param {object} finding
 * @returns {object} assessment
 */
function assessFinding(finding) {
  if (!finding || typeof finding !== 'object') {
    return { error: 'Invalid finding' };
  }

  const rawAlgorithm = finding.algorithm || 'UNKNOWN';
  const family = normalizeFamily(rawAlgorithm);
  const purpose = detectPurpose(family, finding.usage);
  
  // Scoring
  const lifetimeInfo = normalizeDataLifetime(finding.dataLifetime);
  const scoreResult = scoreFinding(finding, purpose, finding.businessContext, lifetimeInfo.value);
  const cryptoAgilityScore = calculateCryptoAgilityScore(family, purpose, finding.keySize, finding);

  // Default values
  let recommendedPqc = null;
  let hybridRequired = true;
  let migrationPriority = 'LOW';
  let steps = [];
  let blockers = [];
  let riskBefore = scoreResult.hndlScore;
  let riskAfter = null;
  let actionCategory = 'longTermActions'; // immediateActions, shortTermActions, longTermActions
  
  const isClassicallyBroken = CLASSICALLY_BROKEN.has(family);
  const isAlreadyPqc = ALREADY_PQC_PRIMITIVES.has(family);
  
  const resResistant = QUANTUM_RESISTANT_PRIMITIVES[family];
  const isQuantumResistant = !!resResistant;

  if (isClassicallyBroken) {
    migrationPriority = 'CRITICAL';
    actionCategory = 'immediateActions';
    blockers.push('Classically broken primitive in use; bypass PQC planning and replace immediately.');
    steps = [
      `Replace ${rawAlgorithm} immediately with a modern standard (e.g., SHA-256 or AES-GCM)`,
      'Audit all systems for compromise',
    ];
    riskAfter = 15; // baseline after immediate fix
  } else if (isAlreadyPqc) {
    migrationPriority = 'NONE';
    hybridRequired = false;
    recommendedPqc = family;
    steps = ['Algorithm is already PQC. Monitor for implementation updates.'];
    riskAfter = scoreResult.hndlScore;
  } else if (isQuantumResistant) {
    if (finding.keySize && resResistant.adequateKeySize && finding.keySize < resResistant.adequateKeySize) {
      migrationPriority = 'HIGH';
      actionCategory = 'shortTermActions';
      hybridRequired = false;
      recommendedPqc = `${family}-${resResistant.adequateKeySize}`;
      steps = [`Upgrade key size to at least ${resResistant.adequateKeySize} bits to ensure quantum resistance.`];
      riskAfter = 15;
    } else {
      migrationPriority = 'NONE';
      hybridRequired = false;
      recommendedPqc = family;
      steps = ['Algorithm is symmetric/hash and quantum-resistant. No immediate PQC migration needed.'];
      riskAfter = scoreResult.hndlScore;
    }
  } else if (family === 'UNKNOWN') {
    migrationPriority = 'UNKNOWN';
    actionCategory = 'blockers';
    blockers.push('Cannot determine primitive family for ' + rawAlgorithm);
  } else {
    // Normal vulnerable primitive (RSA, ECC, etc.)
    const guidance = getMigrationGuidance(family, purpose, finding);
    recommendedPqc = guidance.recommendation;
    hybridRequired = guidance.hybridByDefault !== undefined ? guidance.hybridByDefault : true;
    steps = generateMigrationSteps(family, purpose);
    
    if (scoreResult.hndlScore >= 70) {
      migrationPriority = 'CRITICAL';
      actionCategory = 'shortTermActions';
    } else if (scoreResult.hndlScore >= 40) {
      migrationPriority = 'HIGH';
      actionCategory = 'shortTermActions';
    } else {
      migrationPriority = 'MEDIUM';
      actionCategory = 'longTermActions';
    }
    
    // Once migrated to PQC, quantum risk goes away
    riskAfter = Math.max(15, scoreResult.hndlScore - 50);
  }

  return {
    findingId: finding.id || null,
    file: finding.file || finding.filePath || null,
    algorithm: rawAlgorithm,
    purpose,
    keySize: finding.keySize,
    quantumVulnerabilityStatus: isClassicallyBroken ? 'Classically Broken' : (isAlreadyPqc || isQuantumResistant ? 'Quantum Safe' : 'Quantum Vulnerable'),
    recommendedPqc,
    hybridMigrationRequired: hybridRequired,
    migrationPriority,
    businessImportance: scoreResult.businessImportance,
    hndlRiskScore: scoreResult.hndlScore,
    cryptoAgilityScore,
    steps,
    blockers,
    riskBefore,
    riskAfter,
    actionCategory,
  };
}

/**
 * Assesses an entire scan's findings and generates a migration plan.
 * @param {object} scan
 * @param {Array} rawFindings
 */
function assessMigration(scan, rawFindings) {
  const plan = {
    scanId: scan.id || scan.scanId,
    repository: scan.repo?.name || scan.repoId || 'unknown',
    assessedAt: (() => { try { const d = new Date(scan.createdAt || scan.receivedAt || 0); return isNaN(d.getTime()) ? new Date(0).toISOString() : d.toISOString(); } catch(e) { return new Date(0).toISOString(); } })(),
    immediateActions: [],
    shortTermActions: [],
    longTermActions: [],
    blockers: [],
    affectedAssets: [],
    overallRiskBefore: 0,
    overallRiskAfter: 0,
    averageCryptoAgility: 0,
  };

  if (!rawFindings || !Array.isArray(rawFindings)) {
    return plan;
  }

  let totalAgility = 0;
  
  rawFindings.forEach(f => {
    const assessment = assessFinding(f);
    
    if (assessment.error) return;

    plan.affectedAssets.push(assessment);
    
    // Categorize
    const actionItem = {
      findingId: assessment.findingId,
      file: assessment.file,
      algorithm: assessment.algorithm,
      priority: assessment.migrationPriority,
      recommendation: assessment.recommendedPqc,
      steps: assessment.steps,
    };

    if (assessment.actionCategory === 'immediateActions') {
      plan.immediateActions.push(actionItem);
    } else if (assessment.actionCategory === 'shortTermActions') {
      plan.shortTermActions.push(actionItem);
    } else if (assessment.actionCategory === 'longTermActions') {
      plan.longTermActions.push(actionItem);
    }
    
    if (assessment.blockers.length > 0) {
      plan.blockers.push({ findingId: assessment.findingId, file: assessment.file, blockers: assessment.blockers });
    }

    if (assessment.riskBefore > plan.overallRiskBefore) plan.overallRiskBefore = assessment.riskBefore;
    if (assessment.riskAfter > plan.overallRiskAfter && assessment.riskAfter !== null) {
      plan.overallRiskAfter = assessment.riskAfter;
    }
    
    totalAgility += assessment.cryptoAgilityScore || 0;
  });

  if (rawFindings.length > 0) {
    plan.averageCryptoAgility = Math.round(totalAgility / rawFindings.length);
  }

  // Deduplicate and sort actions
  plan.immediateActions.sort((a, b) => b.priority.localeCompare(a.priority));
  plan.shortTermActions.sort((a, b) => b.priority.localeCompare(a.priority));

  return plan;
}

module.exports = {
  assessMigration,
  assessFinding,
};
