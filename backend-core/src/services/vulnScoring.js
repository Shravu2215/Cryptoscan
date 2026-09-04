/**
 * Vulnerability scoring — deterministic, explainable, 0-100.
 *
 * score = 0.40 * quantumVulnerability
 *       + 0.30 * keyStrength
 *       + 0.20 * classicalDeprecation
 *       + 0.10 * usageCriticality
 *
 * Every sub-score is a documented lookup/formula below — nothing here is
 * Math.random(). Weights are tunable in WEIGHTS if the team wants to
 * re-balance during the hackathon; keep them summing to 1.0.
 */

const WEIGHTS = {
  quantumVulnerability: 0.4,
  keyStrength: 0.3,
  classicalDeprecation: 0.2,
  usageCriticality: 0.1,
};

// --- 1. Quantum vulnerability -------------------------------------------
// Asymmetric primitives broken outright by Shor's algorithm score highest.
// Symmetric/hash primitives are only weakened by Grover's algorithm
// (quadratic speed-up => effective security roughly halved), so their
// score depends on whether the *remaining* effective strength is still
// adequate.
function quantumVulnerabilityScore(primitive, keySize) {
  const p = primitive.toUpperCase();

  if (['RSA', 'ECC', 'ECDSA', 'ECDH', 'DSA', 'DH', 'EDDSA'].includes(p)) {
    return 100; // fully broken given a cryptographically relevant quantum computer
  }
  if (p === 'AES') {
    if (!keySize || keySize < 192) return 60; // effective ~64-bit under Grover: weak
    if (keySize < 256) return 40; // effective ~96-bit: marginal
    return 20; // AES-256 -> effective ~128-bit: adequate
  }
  if (p === 'CHACHA20') return 20; // 256-bit key, same margin as AES-256
  if (['DES', '3DES', 'RC4'].includes(p)) return 100; // broken classically; quantum is moot
  if (['SHA-256', 'SHA256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-512'].includes(p)) return 15;
  if (['MD5', 'SHA1', 'SHA-1'].includes(p)) return 100; // classically broken already
  return 50; // unrecognized primitive: assume moderate risk pending manual review
}

// --- 2. Key strength ------------------------------------------------------
// How far below current NIST-recommended minimums the observed key/curve
// size is. 0 = meets or exceeds long-term recommendation.
function keyStrengthScore(primitive, keySize) {
  const p = primitive.toUpperCase();
  if (!keySize) return 50; // unknown key size can't be verified as safe

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
  if (['DES', '3DES', 'RC4', 'RC2'].includes(p)) return 100; // any key size here is already inadequate
  return 30; // primitive without a defined key-size policy here
}

// --- 3. Classical deprecation ---------------------------------------------
// Algorithms/modes that are unsafe today, independent of quantum computing.
const DEPRECATED_TABLE = {
  MD5: 100,
  SHA1: 90,
  'SHA-1': 90,
  DES: 100,
  '3DES': 80,
  RC4: 100,
  RC2: 90,
  ECB: 70, // mode, not primitive; scanner may report mode separately
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
// The same weak algorithm is worse if it protects authentication/signing
// than if it's used somewhere low-stakes.
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

// --- 5. HNDL ("Harvest Now, Decrypt Later") exposure model ----------------
// A finding protecting long-lived data is riskier than the same finding
// protecting ephemeral data: an attacker can record ciphertext today and
// decrypt it once a cryptographically-relevant quantum computer exists.
//
// - MIGRATION_TIME_YEARS: realistic time to plan + execute a migration once
//   started (audit, dual-run, cutover).
// - QUANTUM_THREAT_HORIZON_YEARS: conservative industry estimate of when a
//   cryptographically-relevant quantum computer could arrive.
// If (dataLifetime + migrationTime) still exceeds the threat horizon, the
// data is exposed for that many years after the threat materializes.
const DEFAULT_DATA_LIFETIME_YEARS = 10;
const MIGRATION_TIME_YEARS = 3;
const QUANTUM_THREAT_HORIZON_YEARS = 7;

/**
 * Normalizes a caller-supplied data lifetime (years) to a safe numeric value.
 * Missing/invalid input falls back to a conservative default so risk is
 * never silently underestimated.
 *
 * @param {number|undefined} years
 * @returns {{ value: number, isDefault: boolean }}
 */
function normalizeDataLifetime(years) {
  if (typeof years !== 'number' || Number.isNaN(years) || years < 0) {
    return { value: DEFAULT_DATA_LIFETIME_YEARS, isDefault: true };
  }
  return { value: years, isDefault: false };
}

/**
 * How many years past the projected quantum-threat horizon this data
 * remains exposed, given how long it lives and how long migration takes.
 * Clamped to 0 — data that's rotated/expired well before the threat
 * horizon has no HNDL exposure window.
 *
 * @param {{value:number}|number} normalizedLifetime - result of normalizeDataLifetime(), or a raw year count
 * @returns {number} exposure window in years (>= 0)
 */
function calculateQuantumExposureWindow(normalizedLifetime) {
  const years = (normalizedLifetime && typeof normalizedLifetime === 'object')
    ? normalizedLifetime.value
    : normalizedLifetime;
  const window = (years ?? DEFAULT_DATA_LIFETIME_YEARS) + MIGRATION_TIME_YEARS - QUANTUM_THREAT_HORIZON_YEARS;
  return Math.max(0, window);
}

/**
 * Scales a primitive's base quantum-vulnerability score by how long its
 * exposure window is, so two equally-broken primitives are differentiated
 * by how much HNDL risk they actually carry.
 *
 * @param {number} baseQuantumVulnerability - 0-100, from quantumVulnerabilityScore()
 * @param {number} exposureWindowYears - from calculateQuantumExposureWindow()
 * @returns {number} 0-100 HNDL exposure score
 */
function quantumExposureScore(baseQuantumVulnerability, exposureWindowYears) {
  if (!baseQuantumVulnerability || baseQuantumVulnerability <= 0) return 0;
  const scaled = Math.min(100, Math.max(0, exposureWindowYears) * 10);
  return Math.round((scaled * baseQuantumVulnerability) / 100);
}

// --- 6. Business-context multiplier ----------------------------------------
// The same technical risk matters more against critical business assets.
const BUSINESS_IMPORTANCE_MULTIPLIERS = {
  Critical: 1.25,
  High: 1.15,
  Medium: 1.0,
  Low: 0.9,
};
const DEFAULT_BUSINESS_MULTIPLIER = 1.0;

/**
 * @param {{primitive:string, keySize?:number, mode?:string}} finding
 * @param {string} purpose - output of purposeDetection.detectPurpose(...).purpose
 * @param {object} [options={}]
 * @param {number} [options.dataLifetime] - expected data lifetime in years (HNDL)
 * @param {string} [options.businessImportance] - e.g. 'Critical' | 'High' | 'Medium' | 'Low'
 */
function scoreFinding(finding, purpose, options = {}) {
  const quantumVulnerability = quantumVulnerabilityScore(finding.primitive, finding.keySize);
  const keyStrength = keyStrengthScore(finding.primitive, finding.keySize);
  const classicalDeprecation = classicalDeprecationScore(finding.primitive, finding.mode);
  const usageCriticality = usageCriticalityScore(purpose);

  const raw =
    quantumVulnerability * WEIGHTS.quantumVulnerability +
    keyStrength * WEIGHTS.keyStrength +
    classicalDeprecation * WEIGHTS.classicalDeprecation +
    usageCriticality * WEIGHTS.usageCriticality;

  const score = Math.round(Math.min(100, Math.max(0, raw)));

  // HNDL exposure folded into a pre-business-context risk score.
  const normLifetime = normalizeDataLifetime(options.dataLifetime);
  const exposureWindow = calculateQuantumExposureWindow(normLifetime);
  const exposureBonus = quantumExposureScore(quantumVulnerability, exposureWindow);
  const preBusinessRiskScore = Math.round(Math.min(100, Math.max(0, score * 0.7 + exposureBonus * 0.3)));

  const appliedMultiplier = BUSINESS_IMPORTANCE_MULTIPLIERS[options.businessImportance] ?? DEFAULT_BUSINESS_MULTIPLIER;
  const businessAdjustedRiskScore = Math.round(Math.min(100, preBusinessRiskScore * appliedMultiplier));

  return {
    score,
    severity: severityLabel(score),
    breakdown: { quantumVulnerability, keyStrength, classicalDeprecation, usageCriticality },
    weights: WEIGHTS,
    preBusinessRiskScore,
    businessAdjustedRiskScore,
    appliedMultiplier,
  };
}

module.exports = {
  scoreFinding,
  severityLabel,
  normalizeDataLifetime,
  calculateQuantumExposureWindow,
  quantumExposureScore,
};
