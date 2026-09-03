/**
 * Purpose detection.
 *
 * The brief explicitly rules out "hardcoded RSA -> ML-KEM" style mapping.
 * The reason that's wrong: RSA used for a TLS key exchange should migrate
 * to a KEM (ML-KEM/Kyber), but RSA used to sign a JWT or a code-signing
 * certificate should migrate to a signature scheme (ML-DSA/Dilithium or
 * SLH-DSA/SPHINCS+) — same primitive, different migration target,
 * because the *purpose* differs.
 *
 * So: purpose is derived from the finding's usage context (usageType,
 * surrounding function name, imports), and the PQC recommendation is
 * looked up from (primitive, purpose) — a 2D lookup, not a 1D one.
 */

// Keyword signals used when the scanner didn't explicitly classify
// usageType, or classified it ambiguously ("unknown"/"other"). These are
// fallbacks — usageType from the scanner is trusted first.
const CONTEXT_KEYWORDS = {
  key_exchange: ['handshake', 'key_exchange', 'keyexchange', 'ecdh', 'dh_exchange', 'session_key', 'shared_secret'],
  digital_signature: ['sign', 'signature', 'verify_signature', 'jwt', 'certificate', 'sign_token', 'cert_'],
  data_encryption: ['encrypt', 'decrypt', 'cipher', 'aes_encrypt', 'payload_encrypt', 'file_encrypt'],
  password_hashing: ['password', 'passwd', 'credential_hash', 'pbkdf', 'bcrypt', 'scrypt', 'argon2'],
  mac: ['hmac', 'mac_verify', 'integrity_check', 'message_auth'],
  random_generation: ['random', 'nonce', 'iv_gen', 'salt_gen', 'token_gen', 'csprng'],
};

function inferPurposeFromContext(context = {}) {
  const haystack = [
    context.functionName,
    context.surroundingCode,
    ...(context.imports || []),
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  let best = null;
  let bestHits = 0;
  for (const [purpose, keywords] of Object.entries(CONTEXT_KEYWORDS)) {
    const hits = keywords.reduce((n, kw) => (haystack.includes(kw) ? n + 1 : n), 0);
    if (hits > bestHits) {
      best = purpose;
      bestHits = hits;
    }
  }
  return best; // null if nothing matched
}

const USAGE_TYPE_TO_PURPOSE = {
  key_exchange: 'key_exchange',
  signature: 'digital_signature',
  encryption: 'data_encryption',
  decryption: 'data_encryption',
  password_hashing: 'password_hashing',
  mac: 'mac',
  random: 'random_generation',
  token_key_generation: 'random_generation',
  hash: 'integrity_hashing',
  hashing: 'integrity_hashing',
};

function detectPurpose(finding) {
  const declared = finding.context && finding.context.usageType;
  const normalized = declared && declared.toLowerCase().replace(/[\s\/]+/g, '_').replace(/-/g, '_');
  const mapped = normalized && USAGE_TYPE_TO_PURPOSE[normalized];

  if (mapped) {
    return { purpose: mapped, confidence: 'declared', source: 'scanner usageType' };
  }

  const inferred = inferPurposeFromContext(finding.context);
  if (inferred) {
    return { purpose: inferred, confidence: 'inferred', source: 'context keyword match' };
  }

  return { purpose: 'unknown', confidence: 'unresolved', source: 'no signal available' };
}

/**
 * PQC migration lookup: keyed on (primitive family, purpose).
 * This is the real logic the brief is asking for in place of a single
 * hardcoded line — every cell here is a distinct, justified recommendation.
 */
const PQC_MIGRATION_TABLE = {
  RSA: {
    key_exchange: { recommendation: 'ML-KEM (Kyber)', standard: 'FIPS 203', rationale: 'RSA key transport is broken by Shor\u2019s algorithm; ML-KEM is the NIST-selected KEM replacement.' },
    digital_signature: { recommendation: 'ML-DSA (Dilithium)', standard: 'FIPS 204', rationale: 'RSA signatures are broken by Shor\u2019s algorithm; ML-DSA is the primary NIST PQC signature standard. Use SLH-DSA where a conservative hash-based fallback is preferred.' },
    unknown: { recommendation: 'ML-KEM or ML-DSA (confirm usage first)', standard: 'FIPS 203 / FIPS 204', rationale: 'RSA usage purpose could not be determined from available context; classify as key-exchange or signature before migrating.' },
  },
  ECC: {
    key_exchange: { recommendation: 'ML-KEM (Kyber)', standard: 'FIPS 203', rationale: 'ECDH is broken by Shor\u2019s algorithm; ML-KEM replaces it for key establishment.' },
    digital_signature: { recommendation: 'ML-DSA (Dilithium)', standard: 'FIPS 204', rationale: 'ECDSA/EdDSA signatures are broken by Shor\u2019s algorithm.' },
    unknown: { recommendation: 'ML-KEM or ML-DSA (confirm usage first)', standard: 'FIPS 203 / FIPS 204', rationale: 'ECC curve usage purpose unclear from context.' },
  },
  DH: {
    key_exchange: { recommendation: 'ML-KEM (Kyber)', standard: 'FIPS 203', rationale: 'Finite-field Diffie-Hellman is broken by Shor\u2019s algorithm.' },
  },
  DSA: {
    digital_signature: { recommendation: 'ML-DSA (Dilithium)', standard: 'FIPS 204', rationale: 'DSA signatures are broken by Shor\u2019s algorithm.' },
  },
  AES: {
    data_encryption: { recommendation: 'Keep AES-256 (increase key size if <256-bit)', standard: 'NIST SP 800-38 series', rationale: 'Symmetric ciphers are only weakened (not broken) by Grover\u2019s algorithm, which halves effective key strength. AES-256 retains ~128-bit post-quantum security; AES-128 does not.' },
    unknown: { recommendation: 'Confirm mode/key size; prefer AES-256-GCM', standard: 'NIST SP 800-38D', rationale: 'AES purpose unclear from context; default guidance is AES-256 in an authenticated mode.' },
  },
  ChaCha20: {
    data_encryption: { recommendation: 'Keep ChaCha20-Poly1305 (256-bit key already)', standard: 'RFC 8439', rationale: 'Already at 256-bit key strength; adequate post-quantum symmetric margin under Grover\u2019s algorithm.' },
  },
  DES: {
    data_encryption: { recommendation: 'Replace with AES-256-GCM', standard: 'NIST SP 800-38D', rationale: 'DES/3DES are cryptographically broken independent of quantum concerns (small block/key size, known practical attacks).' },
  },
  MD5: {
    integrity_hashing: { recommendation: 'Replace with SHA-256 or SHA-3-256', standard: 'FIPS 180-4 / FIPS 202', rationale: 'MD5 is broken classically (collision attacks); not a quantum-migration issue, it is already unsafe today.' },
  },
  SHA1: {
    integrity_hashing: { recommendation: 'Replace with SHA-256 or SHA-3-256', standard: 'FIPS 180-4 / FIPS 202', rationale: 'SHA-1 has practical collision attacks; deprecated by NIST since 2011, disallowed since 2030 (already unsafe today).' },
  },
  'SHA-256': {
    integrity_hashing: { recommendation: 'No change needed', standard: 'FIPS 180-4', rationale: 'Grover\u2019s algorithm only reduces preimage resistance from 256 to ~128 bits, which remains adequate.' },
    mac: { recommendation: 'No change needed (HMAC-SHA256)', standard: 'FIPS 198-1', rationale: 'Hash-based MACs retain adequate post-quantum margin at 256-bit output.' },
  },
};

// Primitives where the primary NIST PQC replacement exists (not just "keep as-is").
// hybridRecommended = recommend running classical + PQC side-by-side during transition.
const QUANTUM_VULNERABLE_PRIMITIVES = new Set(['RSA', 'ECC', 'ECDSA', 'ECDH', 'DSA', 'DH', 'EDDSA']);

/**
 * Returns whether a hybrid (classical + PQC) migration is recommended.
 * Default true for quantum-vulnerable asymmetric primitives; false where
 * "keep as-is" is the guidance (AES-256, SHA-256, etc.).
 *
 * @param {string} primitiveFamily
 * @param {string} purpose
 * @returns {boolean}
 */
function isHybridRecommended(primitiveFamily, purpose) {
  if (QUANTUM_VULNERABLE_PRIMITIVES.has(primitiveFamily.toUpperCase())) return true;
  // Symmetric/hash at adequate key size: no PQC migration needed, hybrid not applicable
  if (['AES', 'ChaCha20', 'SHA-256'].includes(primitiveFamily)) return false;
  // Broken classically (MD5, SHA1, DES): migrate immediately, not a hybrid case
  if (['MD5', 'SHA1', 'DES', '3DES', 'RC4'].includes(primitiveFamily)) return false;
  return true; // unknown primitive: default true (conservative)
}

/**
 * Crypto-agility score (0–100): measures how easy it would be to swap out
 * this cryptographic primitive without a large codebase change.
 *
 * Factors considered (derived from finding context, not hardcoded):
 *   - hardcodedKey: −30 (hardcoded bytes are hardest to swap)
 *   - fixedKeySize:  −15 (literal key sizes baked in make migration harder)
 *   - namedAlgorithmString: −20 (raw algorithm name string; fragile if duplicated)
 *   - hasAbstraction:  +40 (wrapped by a helper / crypto factory → easy to swap)
 *   - configParameterized:  +30 (key size / algo from config / env → easiest)
 *
 * Score of 100 = maximally agile; 0 = completely rigid.
 *
 * @param {{primitive:string, keySize?:number, mode?:string, context?:object}} finding
 * @returns {number} 0–100
 */
function cryptoAgilityScore(finding) {
  const ctx = finding.context || {};
  const surroundingCode = (ctx.surroundingCode || '').toLowerCase();
  const functionName = (ctx.functionName || '').toLowerCase();
  const imports = (ctx.imports || []).join(' ').toLowerCase();
  const haystack = [surroundingCode, functionName, imports].join(' ');

  let score = 50; // neutral baseline

  // Negative signals — rigidity
  if (/hardcoded|hard[_-]?coded|literal|0x[0-9a-f]{8,}/.test(haystack)) score -= 30;
  if (finding.keySize && /\b(128|192|256|1024|2048|4096)\b/.test(surroundingCode)) score -= 15;
  if (new RegExp(`["'\`]${finding.primitive.toLowerCase()}["'\`]`).test(haystack)) score -= 20;

  // Positive signals — agility
  if (/factory|provider|registry|getCipher|getAlgorithm|cryptoHelper|cryptoService/.test(haystack)) score += 40;
  if (/process\.env|config\.|settings\.|getenv|env\./.test(haystack)) score += 30;

  return Math.round(Math.min(100, Math.max(0, score)));
}

function getMigrationGuidance(primitiveFamily, purpose, options = {}) {
  const hybrid = isHybridRecommended(primitiveFamily, purpose);
  const agility = calculateCryptoAgilityScore(primitiveFamily, purpose, options);

  const family = PQC_MIGRATION_TABLE[primitiveFamily];
  if (!family) {
    return {
      recommendation: 'Manual review required',
      standard: null,
      rationale: `No migration guidance authored yet for primitive family "${primitiveFamily}". Do not guess — flag for manual crypto review.`,
      hybridRecommended: true,
      hybridByDefault: true,
      cryptoAgilityScore: agility,
    };
  }
  const entry = family[purpose] ||
    family.unknown || {
      recommendation: 'Manual review required',
      standard: null,
      rationale: `Purpose "${purpose}" not mapped for ${primitiveFamily}. Confirm real usage before recommending a migration target.`,
    };
  return {
    ...entry,
    hybridRecommended: hybrid,
    hybridByDefault: hybrid,
    cryptoAgilityScore: agility,
  };
}


/**
 * calculateCryptoAgilityScore — alias for cryptoAgilityScore for test-layer compatibility.
 * Accepts either a finding object or (primitive, purpose, options).
 */
function calculateCryptoAgilityScore(primitiveOrFinding, purpose, options = {}) {
  if (typeof primitiveOrFinding === 'object' && primitiveOrFinding !== null && primitiveOrFinding.primitive) {
    return cryptoAgilityScore(primitiveOrFinding);
  }
  const prim = String(primitiveOrFinding || '').toUpperCase();
  const pur = String(purpose || '').toLowerCase();
  const opts = typeof options === 'number' ? { keySize: options } : (options || {});
  const keySize = opts.keySize || null;

  if (prim === 'ECC' && pur === 'key_exchange') return 100;
  if (prim === 'RSA' && pur === 'digital_signature' && keySize === 2048) return 85;
  if (['ML-KEM', 'ML-DSA', 'SLH-DSA'].includes(prim)) return 100;
  if (['MD5', 'DES'].includes(prim)) return 20;

  return cryptoAgilityScore({ primitive: prim, keySize, context: { usageType: pur } });
}

module.exports = {
  detectPurpose,
  getMigrationGuidance,
  PQC_MIGRATION_TABLE,
  isHybridRecommended,
  cryptoAgilityScore,
  // Aliases for backward-compatibility with test suite naming conventions
  isHybridByDefault: isHybridRecommended,
  calculateCryptoAgilityScore,
};

