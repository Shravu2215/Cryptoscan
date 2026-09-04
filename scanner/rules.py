"""
Single source of truth for algorithm -> (severity, quantum-risk tier, recommendation).
Both the Python analyzer and the JS analyzer import THIS table instead of keeping
their own copies, so the language scanners stay aligned.
"""
import re as _re
from .models import Severity, QuantumRisk

# ---------------------------------------------------------------------------
# Hash algorithms
# ---------------------------------------------------------------------------
HASH_ALGOS = {
    "md5":     dict(algorithm="MD5",     severity=Severity.CRITICAL,   quantum_risk=QuantumRisk.CLASSICAL_RISK,
                     recommendation="Replace MD5 with SHA-256/SHA-3. If used for password storage, use "
                                     "a memory-hard KDF (argon2id, scrypt, bcrypt) instead of a raw hash."),
    "sha1":    dict(algorithm="SHA-1",   severity=Severity.HIGH, quantum_risk=QuantumRisk.CLASSICAL_RISK,
                     recommendation="SHA-1 has known collision attacks. Replace with SHA-256 or SHA-3-256."),
    "sha256":  dict(algorithm="SHA-256", severity=Severity.INFO,    quantum_risk=QuantumRisk.SAFE,
                     recommendation="SHA-256 is strong and quantum-safe against Shor's algorithm."),
    "sha3":    dict(algorithm="SHA-3",   severity=Severity.INFO,   quantum_risk=QuantumRisk.SAFE,
                     recommendation="SHA-3 is strong and quantum-safe."),
    "sha512":  dict(algorithm="SHA-512", severity=Severity.INFO,   quantum_risk=QuantumRisk.SAFE,
                     recommendation="SHA-512 is strong and quantum-safe."),
}

# ---------------------------------------------------------------------------
# Symmetric ciphers, keyed by (algo, mode)
# ---------------------------------------------------------------------------
def symmetric_profile(algo: str, mode: str, key_bits: int = None):
    algo = algo.upper()
    mode = (mode or "").upper()
    label = f"{algo}-{key_bits}-{mode}" if key_bits else f"{algo}-{mode}" if mode else algo

    if algo in ("DES", "3DES", "DES3", "TDES", "RC2", "RC4", "ARC4", "BLOWFISH"):
        return dict(algorithm=label, severity=Severity.CRITICAL, quantum_risk=QuantumRisk.CLASSICAL_RISK,
                     recommendation=f"{algo} is deprecated/broken by classical cryptanalysis or has too "
                                     "small a block/key size. Replace with AES-256-GCM.")
    if mode == "ECB":
        return dict(algorithm=label, severity=Severity.CRITICAL, quantum_risk=QuantumRisk.CLASSICAL_RISK,
                     recommendation="ECB mode leaks plaintext structure (identical blocks encrypt "
                                     "identically). Switch to AES-256-GCM or AES-256-CBC+HMAC.")
    if mode in ("GCM", "CCM", "POLY1305", "CHACHA20-POLY1305", "OCB"):
        qr = QuantumRisk.QUANTUM_WEAKENED if (key_bits or 256) < 256 else QuantumRisk.SAFE
        sev = Severity.MEDIUM if (key_bits or 256) < 256 else Severity.INFO
        return dict(algorithm=label, severity=sev, quantum_risk=qr,
                     recommendation="AEAD mode in use - good. Use a 256-bit key to keep full margin "
                                     "against Grover's algorithm." if (key_bits or 256) < 256 else
                                     "No action needed.")
    if mode in ("CBC", "CTR", "CFB", "OFB"):
        sev = Severity.LOW if (key_bits and key_bits >= 256) else Severity.MEDIUM
        return dict(algorithm=label, severity=sev, quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
                     recommendation=f"{mode} mode provides no built-in integrity/authentication. Prefer "
                                     "AES-256-GCM. If CBC must be kept, pair it with a separate "
                                     "encrypt-then-MAC (HMAC-SHA-256).")
    sev = Severity.LOW if (key_bits and key_bits >= 256) else Severity.MEDIUM
    return dict(algorithm=label, severity=sev, quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
                 recommendation="Verify this cipher mode provides authenticated encryption; prefer "
                                 "AES-256-GCM.")


# ---------------------------------------------------------------------------
# Asymmetric algorithms - always Quantum-Broken (Shor's algorithm)
# ---------------------------------------------------------------------------
def rsa_profile(bits: int):
    if bits is None:
        sev = Severity.MEDIUM
    elif bits < 1024:
        sev = Severity.CRITICAL
    elif bits < 2048:
        sev = Severity.HIGH
    else:
        sev = Severity.MEDIUM
    tags = []
    if bits is not None and bits < 2048:
        tags.append("undersized-classical-key")
    return dict(
        algorithm=f"RSA-{bits}" if bits else "RSA",
        severity=sev,
        quantum_risk=QuantumRisk.QUANTUM_BROKEN,
        recommendation=(
            ("Key size is below the classically-safe 2048-bit minimum - raise it immediately. "
             "But note raising key size alone does not fix quantum exposure: ")
            if (bits is not None and bits < 2048) else ""
        ) + "RSA is broken by Shor's algorithm at any key size. Migrate to ML-KEM (key exchange) "
            "and/or ML-DSA (signatures) as NIST's standardized PQC replacements, or use a hybrid "
            "classical+PQC scheme during transition.",
        tags=tags,
    )


def ecc_profile(curve: str, purpose: str = "signature"):
    algo = f"ECDSA ({curve})" if purpose == "signature" else f"ECDH ({curve})"
    return dict(
        algorithm=algo,
        severity=Severity.MEDIUM,
        quantum_risk=QuantumRisk.QUANTUM_BROKEN,
        recommendation=(
            "Broken by Shor's algorithm regardless of curve size. Migrate signatures to ML-DSA "
            "(or SLH-DSA for a stateless hash-based fallback) and key exchange to ML-KEM, or use "
            "a hybrid classical+PQC construction during transition."
        ),
    )


INSECURE_RNG = dict(
    algorithm="Non-CSPRNG",
    severity=Severity.HIGH,
    quantum_risk=QuantumRisk.CLASSICAL_RISK,
    recommendation="This value feeds a security-sensitive operation (key/IV/token/nonce) but is "
                    "drawn from a non-cryptographic PRNG (random/Math.random). Attackers can "
                    "predict its output. Use os.urandom(), secrets.token_bytes(), or crypto.randomBytes().",
)

TIMING_UNSAFE_CMP = dict(
    algorithm="Variable-Time Comparison",
    severity=Severity.HIGH,
    quantum_risk=QuantumRisk.CLASSICAL_RISK,
    recommendation="Byte-by-byte equality ('==' or '!==') on signatures, hashes, MACs, or tokens "
                    "leaks execution time proportional to the first mismatched byte, allowing "
                    "forgery via timing oracle. Use hmac.compare_digest() (Python) or "
                    "crypto.timingSafeEqual() (Node.js).",
)
TIMING_UNSAFE_COMPARE = TIMING_UNSAFE_CMP

HARDCODED_KEY = dict(
    algorithm="Hardcoded key material",
    severity=Severity.CRITICAL,
    quantum_risk=QuantumRisk.CLASSICAL_RISK,
    recommendation="Key/secret material is embedded as a literal in source. Anyone with source or "
                    "repo access recovers it. Load from a secrets manager / KMS / environment variable "
                    "injected at deploy time, and rotate this key immediately.",
)

STATIC_IV = dict(
    algorithm="Static/Reused IV",
    severity=Severity.HIGH,
    quantum_risk=QuantumRisk.CLASSICAL_RISK,
    recommendation="Static, hardcoded, or zeroed IVs destroy confidentiality and allow replay/tampering "
                    "attacks. Generate a fresh cryptographic random IV for each encryption operation "
                    "using crypto.randomBytes() or os.urandom().",
)


# ---------------------------------------------------------------------------
# Secret-name detection
# ---------------------------------------------------------------------------

SINGLE_SECRET_HINTS = frozenset({
    "secret", "privkey", "password", "passwd", "apikey", "token", "auth",
    "key", "pass", "credential", "cert", "seed", "signature", "sig", "mac", "digest",
})

COMPOUND_SECRET_HINTS = (
    "private_key", "priv_key", "api_key", "auth_token", "access_token",
    "signing_key", "encryption_key", "aes_key", "des_key", "hmac_key",
    "bearer_token", "client_secret", "db_pass", "db_password", "master_password",
    "stripe_key", "webhook_key", "private_token", "expected_signature", "provided_signature",
)

def _tokenize_identifier(name: str):
    s = _re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name).lower()
    return [part for part in _re.split(r'[^a-z0-9]+', s) if part]


def matches_secret_hint(name: str) -> bool:
    low = name.lower()
    if any(h in low for h in COMPOUND_SECRET_HINTS):
        return True
    tokens = set(_tokenize_identifier(name))
    return any(hint in tokens for hint in SINGLE_SECRET_HINTS)


FERNET_PROFILE = dict(
    algorithm="Fernet (AES-128-CBC+HMAC-SHA256)",
    severity=Severity.LOW,
    quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
    recommendation="Fernet is authenticated (AES-128-CBC + HMAC-SHA256) so it isn't broken, but its "
                    "128-bit key gives a smaller post-quantum margin than AES-256-GCM. Prefer "
                    "AES-256-GCM directly for new code with long-lived confidentiality needs.",
)

# ---------------------------------------------------------------------------
# Centralized Algorithm Classification Registry (Weak, Strong, Non-Crypto)
# ---------------------------------------------------------------------------

NON_CRYPTO_ALGORITHMS = frozenset({
    "gzip", "zstd", "snappy", "lz4", "deflate", "bzip2", "br", "brotli", "lzo",
    "none", "raw", "null", "plain", "round-robin", "least-connections", "random",
    "linear", "binary", "dijkstra", "astar", "kmeans", "pca", "auto", "default",
    "lru", "lfu", "fifo",
})

MODERN_STRONG_ALGORITHMS = frozenset({
    "sha256", "sha-256", "sha3", "sha-3", "sha384", "sha-384", "sha512", "sha-512",
    "aes-gcm", "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "poly1305",
    "ml-kem", "ml-dsa", "slh-dsa", "ed25519", "x25519", "argon2", "argon2id",
    "bcrypt", "scrypt", "pbkdf2-sha256", "pbkdf2-sha512",
})

ALL_KNOWN_ALGORITHM_NAMES = NON_CRYPTO_ALGORITHMS | MODERN_STRONG_ALGORITHMS | frozenset({
    "md5", "md4", "md2", "sha1", "sha-1", "sha256", "sha-256", "sha384", "sha-384", "sha512", "sha-512", "sha3",
    "des", "3des", "des3", "tripledes", "tdes", "rc2", "rc4", "arc4", "blowfish", "cast5", "idea",
    "aes", "aes-128", "aes-256", "aes-gcm", "aes-cbc", "aes-ecb", "rsa", "dsa", "ecdh", "ecdsa", "ecc",
    "lru", "lfu", "fifo", "gzip", "zstd", "snappy", "deflate", "bzip2", "brotli", "lz4",
})

def is_known_algorithm_or_benign(val: str) -> bool:
    if not val or not isinstance(val, str):
        return False
    norm = val.strip().lower().strip('"\'')
    base = _re.split(r'[/_\-\s]', norm)[0] if norm else ""
    return norm in ALL_KNOWN_ALGORITHM_NAMES or base in ALL_KNOWN_ALGORITHM_NAMES


def classify_algorithm(value: str):
    """
    Classifies an algorithm string value from source code or config files.
    Returns a dict with vulnerability details if weak/deprecated, or None if safe/non-crypto.
    """
    if not value or not isinstance(value, str):
        return None

    norm = value.strip().lower().strip('"\'')
    base_token = _re.split(r'[/_\-\s]', norm)[0] if norm else ""

    if norm in NON_CRYPTO_ALGORITHMS or base_token in NON_CRYPTO_ALGORITHMS:
        return None

    if norm in MODERN_STRONG_ALGORITHMS or base_token in MODERN_STRONG_ALGORITHMS:
        return None

    # Check weak hashes
    if norm in {"md5", "md4", "md2"} or base_token in {"md5", "md4", "md2"}:
        return dict(
            algorithm="MD5",
            rule_id="config-weak-algorithm",
            rule_name="Weak Hash Algorithm Configured",
            category="hash",
            severity=Severity.CRITICAL,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            recommendation="MD5 is broken by collision attacks. Replace with SHA-256 or SHA-3.",
        )
    if norm in {"sha1", "sha-1"} or base_token in {"sha1", "sha-1"}:
        return dict(
            algorithm="SHA-1",
            rule_id="config-weak-algorithm",
            rule_name="Weak Hash Algorithm Configured",
            category="hash",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            recommendation="SHA-1 has known collision attacks. Replace with SHA-256 or SHA-3.",
        )
    if norm in {"ripemd160", "ripemd"} or base_token in {"ripemd160", "ripemd"}:
        return dict(
            algorithm="RIPEMD-160",
            rule_id="config-weak-algorithm",
            rule_name="Legacy Hash Algorithm Configured",
            category="hash",
            severity=Severity.MEDIUM,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            recommendation="Replace RIPEMD with SHA-256 or SHA-3.",
        )

    # Check weak symmetric ciphers
    if norm in {"des", "3des", "des3", "tripledes", "tdes"} or base_token in {"des", "3des", "des3", "tripledes", "tdes"}:
        return dict(
            algorithm="3DES/DES",
            rule_id="config-weak-algorithm",
            rule_name="Weak Legacy Cipher Configured",
            category="symmetric-cipher",
            severity=Severity.CRITICAL,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            recommendation="DES/3DES is deprecated with small 64-bit block size (Sweet32 attack). Replace with AES-256-GCM.",
        )
    if norm in {"rc4", "arc4", "rc2", "arc2"} or base_token in {"rc4", "arc4", "rc2"}:
        return dict(
            algorithm="RC4",
            rule_id="config-weak-algorithm",
            rule_name="Broken Stream Cipher Configured",
            category="symmetric-cipher",
            severity=Severity.CRITICAL,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            recommendation="RC4 stream cipher is cryptographically broken. Replace with AES-256-GCM or ChaCha20-Poly1305.",
        )
    if norm in {"blowfish", "cast5", "idea"} or base_token in {"blowfish", "cast5", "idea"}:
        return dict(
            algorithm="Blowfish/Legacy",
            rule_id="config-weak-algorithm",
            rule_name="Legacy Cipher Configured",
            category="symmetric-cipher",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            recommendation="Legacy ciphers with small block sizes are vulnerable to collision attacks. Migrate to AES-256-GCM.",
        )

    # Check ECB mode
    if "ecb" in norm.split("-") or "ecb" in norm.split("_") or norm == "ecb":
        return dict(
            algorithm="ECB Mode",
            rule_id="config-weak-algorithm",
            rule_name="Insecure ECB Cipher Mode Configured",
            category="symmetric-cipher",
            severity=Severity.CRITICAL,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            recommendation="ECB mode leaks plaintext structure. Switch to AES-256-GCM or AES-256-CBC with HMAC.",
        )

    return None
