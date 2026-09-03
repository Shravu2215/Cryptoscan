const { calculateHndlRisk } = require('./hndlEngine');

/**
 * Vulnerability scoring — deterministic, explainable, 0-100.
 *
 * Re-normalized 5-factor weights (sum = 1.00 / 100%):
 * score = 0.30 * quantumVulnerability
 *       + 0.25 * keyStrength
 *       + 0.20 * classicalDeprecation
 *       + 0.15 * hndlRisk
 *       + 0.10 * usageCriticality
 */

const WEIGHTS = {
  quantumVulnerability: 0.3,
  keyStrength: 0.25,
  classicalDeprecation: 0.2,
  hndlRisk: 0.15,
  usageCriticality: 0.1,
};

const BUSINESS_CONTEXT_MULTIPLIERS = {
  CRITICAL: 1.3,
  IMPORTANT: 1.15,
  STANDARD: 1.0,
};

// Additional mapping for 'businessImportance' key (used in some test/API paths)
const BUSINESS_IMPORTANCE_MULTIPLIERS = {
  CRITICAL: 1.25,
  IMPORTANT: 1.15,
  STANDARD: 1.0,
  HIGH: 1.2,
};

function getBusinessContextMultiplier(contextTag, importanceTag) {
  // If businessImportance is specified, use it preferentially
  if (importanceTag) {
    const it = String(importanceTag).toUpperCase();
    if (BUSINESS_IMPORTANCE_MULTIPLIERS[it] !== undefined) return BUSINESS_IMPORTANCE_MULTIPLIERS[it];
  }
  if (!contextTag) return 1.0;
  const tag = String(contextTag).toUpperCase();
  return BUSINESS_CONTEXT_MULTIPLIERS[tag] ?? 1.0;
}

// --- 1. Quantum vulnerability -------------------------------------------
function quantumVulnerabilityScore(primitive, keySize) {
  const p = primitive.toUpperCase();

  if (['RSA', 'ECC', 'ECDSA', 'ECDH', 'DSA', 'DH', 'EDDSA'].includes(p)) {
    return 100;
  }
  if (p === 'AES') {
    if (!keySize || keySize < 192) return 60;
    if (keySize < 256) return 40;
    return 20;
  }
  if (p === 'CHACHA20') return 20;
  if (['DES', '3DES', 'RC4'].includes(p)) return 100;
  if (['SHA-256', 'SHA256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-512'].includes(p)) return 15;
  if (['MD5', 'SHA1', 'SHA-1'].includes(p)) return 100;
  return 50;
}

// --- 2. Key strength ------------------------------------------------------
function keyStrengthScore(primitive, keySize) {
  const p = primitive.toUpperCase();
  if (!keySize) return 50;

  if (p === 'RSA' || p === 'DSA' || p === 'DH') {
    if (keySize < 2048) return 90;
    if (keySize < 3072) return 55;
    if (keySize < 4096) return 35;
    return 20;
  }
  if (['ECC', 'ECDSA', 'ECDH', 'EDDSA'].includes(p)) {
    if (keySize < 256) return 80;
    if (keySize < 384) return 45;
    return 25;
  }
  if (p === 'AES') {
    if (keySize < 128) return 100;
    if (keySize < 192) return 50;
    if (keySize < 256) return 30;
    return 10;
  }
  if (['DES', '3DES', 'RC4', 'RC2'].includes(p)) return 100;
  return 30;
}

// --- 3. Classical deprecation ---------------------------------------------
const DEPRECATED_TABLE = {
  MD5: 100,
  SHA1: 90,
  'SHA-1': 90,
  DES: 100,
  '3DES': 80,
  RC4: 100,
  RC2: 90,
  ECB: 70,
};

function classicalDeprecationScore(primitive, mode) {
  const p = primitive.toUpperCase();
  let score = DEPRECATED_TABLE[p] || 0;
  if (mode && DEPRECATED_TABLE[mode.toUpperCase()] !== undefined) {
    score = Math.max(score, DEPRECATED_TABLE[mode.toUpperCase()]);
  }
  return score;
}

// --- 4. Usage criticality --------------------------------------------------
const USAGE_CRITICALITY = {
  key_exchange: 90,
  digital_signature: 90,
  password_hashing: 85,
  data_encryption: 80,
  mac: 60,
  random_generation: 70,
  integrity_hashing: 55,
  unknown: 50,
};

function usageCriticalityScore(purpose) {
  return USAGE_CRITICALITY[purpose] ?? USAGE_CRITICALITY.unknown;
}

function severityLabel(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'info';
}

/**
 * @param {{primitive:string, keySize?:number, mode?:string, businessContext?:string}} finding
 * @param {string} purpose - output of purposeDetection.detectPurpose(...).purpose
 * @param {object|string} [options] - businessContext tag or HNDL options object
 */
function scoreFinding(finding, purpose, options = {}) {
  const opts = typeof options === 'string' ? { businessContext: options } : options || {};
  const businessContextTag = opts.businessContext || finding.businessContext || 'STANDARD';
  const businessImportanceTag = opts.businessImportance || finding.businessImportance || null;
  const businessContextMultiplier = getBusinessContextMultiplier(businessContextTag, businessImportanceTag);

  const quantumVulnerability = quantumVulnerabilityScore(finding.primitive, finding.keySize);
  const keyStrength = keyStrengthScore(finding.primitive, finding.keySize);
  const classicalDeprecation = classicalDeprecationScore(finding.primitive, finding.mode);
  const usageCriticality = usageCriticalityScore(purpose);

  const hndl = calculateHndlRisk(purpose, quantumVulnerability, opts);

  const baseRaw =
    quantumVulnerability * WEIGHTS.quantumVulnerability +
    keyStrength * WEIGHTS.keyStrength +
    classicalDeprecation * WEIGHTS.classicalDeprecation +
    hndl.hndlRisk * WEIGHTS.hndlRisk +
    usageCriticality * WEIGHTS.usageCriticality;

  const rawWithMultiplier = baseRaw * businessContextMultiplier;
  const score = Math.round(Math.min(100, Math.max(0, rawWithMultiplier)));

  return {
    score,
    severity: severityLabel(score),
    appliedMultiplier: businessContextMultiplier,
    breakdown: {
      quantumVulnerability,
      keyStrength,
      classicalDeprecation,
      hndlRisk: hndl.hndlRisk,
      usageCriticality,
      dataLifetimeYears: hndl.dataLifetimeYears,
      yearsToQuantumThreat: hndl.yearsToQuantumThreat,
      quantumExposureWindow: hndl.quantumExposureWindow,
      businessContext: businessContextTag,
      businessContextMultiplier,
    },
    weights: WEIGHTS,
  };
}

/**
 * normalizeDataLifetime — compatibility shim for test regression.
 * Wraps a lifetime value with metadata for inspection.
 * @param {number} years
 * @returns {{ value: number, unit: 'years' }}
 */
function normalizeDataLifetime(years) {
  return { value: Number(years), unit: 'years' };
}

module.exports = { scoreFinding, severityLabel, getBusinessContextMultiplier, WEIGHTS, normalizeDataLifetime };
