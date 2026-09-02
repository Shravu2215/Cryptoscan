"""
Single source of truth for algorithm -> (severity, quantum-risk tier, recommendation).
Both the Python analyzer and the JS analyzer import THIS table instead of keeping
their own copies, so the two language scanners can't drift apart on risk tagging
(this is the bug called out in the review: JS path wasn't using the Classical Risk
tag at all and everything non-RSA showed a flat "Safe").
"""
from models import Severity, QuantumRisk

# ---------------------------------------------------------------------------
# Hash algorithms
# ---------------------------------------------------------------------------
HASH_ALGOS = {
    "md5":     dict(algorithm="MD5",     severity=Severity.CRITICAL,   quantum_risk=QuantumRisk.CLASSICAL_RISK,
                     recommendation="Replace MD5 with SHA-256/SHA-3. If used for password storage, use "
                                     "a memory-hard KDF (argon2id, scrypt, bcrypt) instead of a raw hash."),
    "sha1":    dict(algorithm="SHA-1",   severity=Severity.HIGH, quantum_risk=QuantumRisk.CLASSICAL_RISK,
                     recommendation="SHA-1 has known collision attacks. Replace with SHA-256 or SHA-3-256."),
    "sha256":  dict(algorithm="SHA-256", severity=Severity.LOW,    quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
                     recommendation="SHA-256 is currently fine; Grover's algorithm only halves effective "
                                     "search security (128-bit post-quantum), which is still adequate."),
    "sha3":    dict(algorithm="SHA-3",   severity=Severity.INFO,   quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
                     recommendation="No action needed."),
    "sha512":  dict(algorithm="SHA-512", severity=Severity.INFO,   quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
                     recommendation="No action needed."),
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
        # Non-AEAD mode. Severity is intentionally NOT critical by itself - it only becomes
        # critical when combined with another concrete red flag (hardcoded key, static/reused IV,
        # no separate MAC). Caller escalates severity when those companion flags are present.
        # Key size is a factor: AES-128 is Medium, AES-256 is Low.
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
# Asymmetric algorithms - always Quantum-Broken (Shor's algorithm), regardless
# of key size. Key size only affects the *classical* severity/urgency.
# ---------------------------------------------------------------------------
def rsa_profile(bits: int):
    if bits is None:
        sev = Severity.MEDIUM
    elif bits < 1024:
        sev = Severity.CRITICAL
    elif bits < 2048:
        sev = Severity.HIGH
    else:
        sev = Severity.MEDIUM  # classically fine today; still quantum-broken
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
    """purpose: 'signature' (ECDSA) or 'exchange' (ECDH). Never label these generically as 'ECC'."""
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


# ---------------------------------------------------------------------------
# Non-crypto-primitive but crypto-adjacent issues
# ---------------------------------------------------------------------------
INSECURE_RNG = dict(
    algorithm="Non-CSPRNG",
    severity=Severity.HIGH,
    quantum_risk=QuantumRisk.CLASSICAL_RISK,
    recommendation="This value feeds a security-sensitive operation (key/IV/token/nonce) but is "
                    "generated with a non-cryptographic RNG. Use os.urandom / secrets (Python) or "
                    "crypto.randomBytes (Node) instead.",
)

TIMING_UNSAFE_COMPARE = dict(
    algorithm="Non-constant-time comparison",
    severity=Severity.MEDIUM,
    quantum_risk=QuantumRisk.CLASSICAL_RISK,
    recommendation="Comparing secrets (tokens/passwords/HMACs/signatures) with == leaks timing "
                    "information that can be used to recover the value byte-by-byte (CWE-208). "
                    "Use hmac.compare_digest (Python) or crypto.timingSafeEqual (Node).",
)

HARDCODED_KEY = dict(
    algorithm="Hardcoded key material",
    severity=Severity.CRITICAL,
    quantum_risk=QuantumRisk.CLASSICAL_RISK,
    recommendation="Key/secret material is embedded as a literal in source. Anyone with source or "
                    "repo access recovers it. Load from a secrets manager / KMS / environment variable "
                    "injected at deploy time, and rotate this key immediately.",
)

STATIC_IV = dict(
    algorithm="Static/reused IV or nonce",
    severity=Severity.HIGH,
    quantum_risk=QuantumRisk.CLASSICAL_RISK,
    recommendation="A fixed or reused IV/nonce with CBC/CTR/GCM defeats the security guarantees of "
                    "the mode (e.g. two-time-pad style plaintext recovery, or catastrophic auth-key "
                    "reuse in GCM). Generate a fresh random IV/nonce per encryption call.",
)

# Secret-like identifier names used by both the hardcoded-key and RNG-context heuristics.
SECRET_NAME_HINTS = (
    "key", "secret", "password", "passwd", "pwd", "token", "apikey", "api_key",
    "auth", "credential", "signature", "sign", "hash", "hmac", "nonce", "iv",
    "salt", "session", "privatekey", "private_key", "otp", "pin", "reset",
    "seed",
)


import re as _re

def _tokenize_identifier(name: str):
    """
    Split an identifier into lowercase tokens on word boundaries.

    Handles:
      - UPPER_CASE_UNDERSCORED  → ["upper", "case", "underscored"]
      - camelCase / PascalCase  → ["camel", "case"] / ["pascal", "case"]
      - kebab-case              → ["kebab", "case"]
      - mixed                   → all of the above combined

    Returns a list of lowercase token strings.
    """
    # Insert a separator before each uppercase letter that follows a lowercase
    # letter or digits (camelCase split), then split on non-alphanumeric chars.
    s = _re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', name)
    return [t.lower() for t in _re.split(r'[^a-zA-Z0-9]+', s) if t]


def matches_secret_hint(name: str) -> bool:
    """
    Return True if the identifier/variable name contains a SECRET_NAME_HINTS
    token at a whole-word boundary — NOT as a raw substring.

    Examples:
      matches_secret_hint("API_KEY")                   → True  (hint "key" == token)
      matches_secret_hint("DB_PASSWORD")               → True  (hint "password" == token)
      matches_secret_hint("AUTH_TOKEN")                → True  (hints "auth", "token" == tokens)
      matches_secret_hint("NODE_TLS_REJECT_UNAUTHORIZED") → False (no token equals "auth")
      matches_secret_hint("TOKENIZER_MODEL_PATH")      → False (no token equals "token")
      matches_secret_hint("KEYBOARD_LAYOUT")           → False (no token equals "key")
      matches_secret_hint("AUTHOR_NAME")               → False (no token equals "auth")
      matches_secret_hint("PASSWORD_POLICY_MIN_LENGTH") → True (token "password" == hint)
    """
    tokens = set(_tokenize_identifier(name))
    return any(hint in tokens for hint in SECRET_NAME_HINTS)

# ---------------------------------------------------------------------------
# Symmetric constructions that aren't a single primitive call (e.g. Fernet,
# which is a composed AES-128-CBC + HMAC-SHA256 recipe from the `cryptography`
# package). Flagged informationally: it's already-authenticated, but pinned
# to a 128-bit key so it carries a smaller post-quantum margin than AES-256-GCM.
# ---------------------------------------------------------------------------
FERNET_PROFILE = dict(
    algorithm="Fernet (AES-128-CBC+HMAC-SHA256)",
    severity=Severity.LOW,
    quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
    recommendation="Fernet is authenticated (AES-128-CBC + HMAC-SHA256) so it isn't broken, but its "
                    "128-bit key gives a smaller post-quantum margin than AES-256-GCM. Prefer "
                    "AES-256-GCM directly for new code with long-lived confidentiality needs.",
)
