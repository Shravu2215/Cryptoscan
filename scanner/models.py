"""
Core data model shared by the Python and JS/Node analyzers.
Every analyzer emits Finding objects using this exact shape so the
dedup engine and reporters don't need to know which language produced them.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


class QuantumRisk(str, Enum):
    # Broken by Shor's algorithm on a cryptographically-relevant quantum computer:
    # RSA, (EC)DSA, ECDH, DH, ElGamal - regardless of key size.
    QUANTUM_BROKEN = "Quantum-Broken"
    # Weakened (effective security roughly halved) by Grover's algorithm:
    # symmetric ciphers/hashes below a PQC-safe margin (e.g. AES-128, SHA-1/SHA-256 as MAC-only edge cases).
    QUANTUM_WEAKENED = "Quantum-Weakened"
    # Weak/broken today for reasons that have nothing to do with quantum computers:
    # MD5, ECB mode, hardcoded keys, weak RNG, timing side-channels, undersized classical keys.
    CLASSICAL_RISK = "Classical Risk"
    # No known classical or quantum break at recommended parameters (AES-256-GCM, SHA-256/3,
    # ML-KEM, ML-DSA, SLH-DSA, ...).
    SAFE = "Safe"


class Confidence(str, Enum):
    """Cross-layer corroboration tier. Added by Person 1 (Detection Layers).

    CONFIRMED  — 2+ independent detection layers agree on the same issue.
    LIKELY     — one strong signal (e.g. resolved AST call against a known library,
                 or entropy-secret-high-confidence).  Default for AST findings.
    POSSIBLE   — weak/single signal (regex-only, or entropy-name-hint-only).
    """
    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    POSSIBLE = "Possible"


@dataclass
class Finding:
    file: str
    line: int
    column: int
    language: str            # "python" | "javascript"
    rule_id: str              # stable machine id, e.g. "md5-weak-password-hash"
    rule_name: str             # human label, e.g. "MD5 weak-password-hash"
    category: str              # "hash" | "symmetric-cipher" | "asymmetric" | "rng" | "comparison"
    algorithm: str              # "MD5", "AES-256-CBC", "RSA-512", ...
    severity: Severity
    quantum_risk: QuantumRisk
    message: str
    recommendation: str
    code_snippet: str = ""
    specificity: int = 1        # higher = more specific rule; used to suppress generic catch-alls
    generic: bool = False        # True for catch-all rules like "AES encryption"
    call_site: str = ""           # normalized (file:line:col) key used for dedup grouping
    tags: list = field(default_factory=list)
    # Confidence tier: set by the source analyzer; can be promoted to CONFIRMED
    # by confidence.promote_confirmed() when 2+ layers corroborate the same site.
    # Default=LIKELY preserves the existing behaviour for all AST-only findings.
    confidence: Confidence = field(default=None)

    def __post_init__(self):
        if not self.call_site:
            self.call_site = f"{self.file}:{self.line}:{self.column}"
        # Apply default here (not in field default) so that analyzers that
        # explicitly pass confidence=Confidence.POSSIBLE aren't overridden.
        if self.confidence is None:
            self.confidence = Confidence.LIKELY

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        d["quantum_risk"] = self.quantum_risk.value
        d["confidence"] = self.confidence.value  # additive key — no existing keys changed
        return d
