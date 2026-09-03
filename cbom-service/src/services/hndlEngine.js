/**
 * HNDL (Harvest-Now-Decrypt-Later) Engine
 *
 * Models quantum exposure risk based on data secrecy lifetime requirements
 * versus estimated years until a Cryptographically Relevant Quantum Computer (CRQC).
 */

const PURPOSE_DATA_LIFETIME = {
  data_encryption: 20,
  password_hashing: 15,
  key_exchange: 10,
  digital_signature: 5,
  mac: 5,
  random_generation: 5,
  integrity_hashing: 3,
  unknown: 10,
};

const DEFAULT_YEARS_TO_QUANTUM_THREAT = 7; // Estimated CRQC arrival: ~7 years

/**
 * Calculates HNDL parameters and risk score.
 *
 * @param {string} purpose - Derived purpose from purposeDetection
 * @param {number} quantumVulnerabilityScore - 0-100 quantum vulnerability score
 * @param {object} [options]
 * @param {number} [options.dataLifetimeYears] - Override secrecy requirement in years
 * @param {number} [options.yearsToQuantumThreat] - Override estimated years to CRQC
 */
function calculateHndlRisk(purpose, quantumVulnerabilityScore, options = {}) {
  const dataLifetimeYears = options.dataLifetimeYears ?? (PURPOSE_DATA_LIFETIME[purpose] || PURPOSE_DATA_LIFETIME.unknown);
  const yearsToQuantumThreat = options.yearsToQuantumThreat ?? DEFAULT_YEARS_TO_QUANTUM_THREAT;

  const quantumExposureWindow = Math.max(0, dataLifetimeYears - yearsToQuantumThreat);

  let hndlRisk = 0;
  if (quantumVulnerabilityScore >= 80) {
    // Asymmetric algorithms broken outright by Shor's algorithm (RSA, ECC, DH)
    if (quantumExposureWindow > 0) {
      hndlRisk = Math.min(100, Math.round(80 + (quantumExposureWindow / 15) * 20));
    } else {
      hndlRisk = 60; // Still high risk due to imminent threat
    }
  } else if (quantumVulnerabilityScore >= 40) {
    // Symmetric algorithms weakened by Grover's (e.g. AES-128)
    hndlRisk = Math.min(100, Math.round(quantumVulnerabilityScore * (0.4 + (quantumExposureWindow / 20) * 0.6)));
  } else {
    // Strong symmetric/hash (AES-256, SHA-256)
    hndlRisk = Math.round(quantumVulnerabilityScore * 0.5);
  }

  return {
    dataLifetimeYears,
    yearsToQuantumThreat,
    quantumExposureWindow,
    hndlRisk,
  };
}

module.exports = {
  calculateHndlRisk,
  PURPOSE_DATA_LIFETIME,
  DEFAULT_YEARS_TO_QUANTUM_THREAT,
};
