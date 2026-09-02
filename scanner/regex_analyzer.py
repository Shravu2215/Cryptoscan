"""
Regex / Config-File Layer.

Performs structural key-value parsing of config files:
  - Dockerfiles: ENV/ARG weak algorithm settings, plaintext secrets, disabled TLS flags
  - YAML / JSON / TOML: weak algorithm declarations, plaintext secrets, disabled TLS flags
  - .env / .ini / .conf: weak algorithms, plaintext secrets, disabled TLS flags

Centralized algorithm classification guarantees:
  - Non-crypto algorithm values (e.g. gzip, zstd, snappy, round-robin) are NEVER flagged.
  - Modern strong algorithms (e.g. SHA-256, AES-256-GCM, Ed25519) are NEVER flagged as vulnerable.
  - Reported line numbers strictly respect file line bounds.
"""
import os
import re
from typing import List, Optional, Tuple, Dict, Any

from .models import Finding, Severity, QuantumRisk, Confidence
from . import rules


# ---------------------------------------------------------------------------
# Placeholder / Template Values
# ---------------------------------------------------------------------------

_PLACEHOLDER_VALUES = frozenset({
    "", "changeme", "your-secret-here", "xxx", "<secret>",
    "todo", "fixme", "example", "replace_me", "insert_secret_here",
    "password", "secret", "your_password_here", "dummy", "test",
})

_PLACEHOLDER_PATTERNS = re.compile(
    r"""
    ^\$\{[^}]*\}$       |   # ${VAR} shell/docker interpolation
    ^%[^%]+%$           |   # %VAR% Windows-style interpolation
    ^\{\{[^}]+\}\}$     |   # {{var}} template interpolation
    ^\$\([^)]+\)$       |   # $(command) shell substitution
    ^<[^>]+>$               # <placeholder> style
    """,
    re.VERBOSE,
)


def _is_placeholder(value: str) -> bool:
    """Return True if the value is an obvious template or placeholder."""
    v = value.strip().strip('"\'')
    if v.lower() in _PLACEHOLDER_VALUES:
        return True
    if _PLACEHOLDER_PATTERNS.match(v):
        return True
    return False


def _secret_name_match(name: str) -> bool:
    """Delegates to rules.matches_secret_hint() using tokenized word boundaries."""
    return rules.matches_secret_hint(name)


# ---------------------------------------------------------------------------
# File Type Classifiers
# ---------------------------------------------------------------------------

def _is_dockerfile(path: str) -> bool:
    bn = os.path.basename(path)
    return bn == "Dockerfile" or bn.startswith("Dockerfile.") or "dockerfile" in bn.lower()


def _is_env_file(path: str) -> bool:
    bn = os.path.basename(path)
    return bn == ".env" or bn.startswith(".env.") or bn.endswith(".env")


def _is_yaml_file(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in {".yml", ".yaml"}


def _is_json_config(path: str) -> bool:
    bn = os.path.basename(path).lower()
    if bn in {"package.json", "package-lock.json", "composer.json"}:
        return False
    return path.lower().endswith(".json")


def _is_ini_conf(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in {".ini", ".conf", ".cfg", ".properties", ".toml"}


# ---------------------------------------------------------------------------
# TLS-Disabling Patterns
# ---------------------------------------------------------------------------

_TLS_DISABLED_PATTERNS = [
    (re.compile(r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0["\']?', re.IGNORECASE), "NODE_TLS_REJECT_UNAUTHORIZED=0"),
    (re.compile(r'\bcurl\b[^\n]*(?:-k\b|--insecure\b)', re.IGNORECASE), "curl --insecure"),
    (re.compile(r'\bwget\b[^\n]*--no-check-certificate\b', re.IGNORECASE), "wget --no-check-certificate"),
    (re.compile(r'\bpip\b[^\n]*--trusted-host\b', re.IGNORECASE), "pip --trusted-host"),
    (re.compile(r'\b(?:verify|ssl|rejectUnauthorized|tls_verify)\s*:\s*false\b', re.IGNORECASE), "TLS verify disabled"),
    (re.compile(r'\bInsecureSkipVerify\s*:\s*true\b', re.IGNORECASE), "InsecureSkipVerify: true"),
]


# ---------------------------------------------------------------------------
# Format Analyzers
# ---------------------------------------------------------------------------

def _validate_line_bounds(line_no: int, total_lines: int) -> int:
    """Hard bound check guaranteeing reported line number exists in file."""
    if total_lines <= 0:
        return 1
    return max(1, min(line_no, total_lines))


def _analyze_dockerfile(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()
    total_lines = len(lines)

    env_arg_re = re.compile(r'^[ \t]*(ENV|ARG)[ \t]+([A-Za-z0-9_\-]+)[ \t]*[= \t]+([^\n#]+)', re.IGNORECASE)

    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # 1. TLS-disabling flags
        for pattern, label in _TLS_DISABLED_PATTERNS:
            if pattern.search(raw_line):
                findings.append(Finding(
                    file=file_path,
                    line=_validate_line_bounds(line_no, total_lines),
                    column=0,
                    language="config",
                    rule_id="tls-verification-disabled",
                    rule_name="TLS verification disabled",
                    category="tls",
                    algorithm="Disabled TLS verification",
                    severity=Severity.CRITICAL,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"TLS/SSL certificate verification is explicitly disabled ({label}).",
                    recommendation="Remove TLS-disabling flags (curl -k, wget --no-check-certificate, NODE_TLS_REJECT_UNAUTHORIZED=0).",
                    code_snippet=stripped,
                    confidence=Confidence.POSSIBLE,
                    tags=["dockerfile", "tls", "mitm-risk"],
                ))

        # 2. Structural ENV/ARG parsing
        m = env_arg_re.match(raw_line)
        if m:
            instruction, var_name, raw_val = m.group(1), m.group(2), m.group(3).strip()
            val = raw_val.strip('"\'')

            # Check weak algorithm declaration
            algo_profile = rules.classify_algorithm(val)
            if algo_profile:
                findings.append(Finding(
                    file=file_path,
                    line=_validate_line_bounds(line_no, total_lines),
                    column=0,
                    language="config",
                    rule_id=algo_profile["rule_id"],
                    rule_name=algo_profile["rule_name"],
                    category=algo_profile["category"],
                    algorithm=algo_profile["algorithm"],
                    severity=algo_profile["severity"],
                    quantum_risk=algo_profile["quantum_risk"],
                    message=f"Dockerfile {instruction} sets '{var_name}' to weak algorithm '{val}'.",
                    recommendation=algo_profile["recommendation"],
                    code_snippet=stripped,
                    confidence=Confidence.POSSIBLE,
                    tags=["dockerfile", "weak-algorithm"],
                ))
            elif _secret_name_match(var_name) and not _is_placeholder(val) and len(val) >= 4:
                findings.append(Finding(
                    file=file_path,
                    line=_validate_line_bounds(line_no, total_lines),
                    column=0,
                    language="config",
                    rule_id="dockerfile-hardcoded-secret",
                    rule_name="Dockerfile hardcoded secret",
                    category="hardcoded-secret",
                    algorithm="Hardcoded key material",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Dockerfile {instruction} sets '{var_name}' to a plaintext literal secret.",
                    recommendation=rules.HARDCODED_KEY["recommendation"],
                    code_snippet=stripped,
                    confidence=Confidence.POSSIBLE,
                    tags=["dockerfile", "hardcoded-secret"],
                ))

    return findings


def _analyze_env_file(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()
    total_lines = len(lines)

    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        if "=" in stripped:
            key, raw_val = stripped.split("=", 1)
            key = key.strip()
            val = raw_val.strip()

            # Clean inline comments
            if " #" in val and not (val.startswith('"') or val.startswith("'")):
                val = val.split(" #", 1)[0].strip()
            val = val.strip('"\'')

            # Check weak algorithm
            algo_profile = rules.classify_algorithm(val)
            if algo_profile:
                findings.append(Finding(
                    file=file_path,
                    line=_validate_line_bounds(line_no, total_lines),
                    column=0,
                    language="config",
                    rule_id=algo_profile["rule_id"],
                    rule_name=algo_profile["rule_name"],
                    category=algo_profile["category"],
                    algorithm=algo_profile["algorithm"],
                    severity=algo_profile["severity"],
                    quantum_risk=algo_profile["quantum_risk"],
                    message=f"Environment variable '{key}' configures weak algorithm '{val}'.",
                    recommendation=algo_profile["recommendation"],
                    code_snippet=stripped,
                    confidence=Confidence.POSSIBLE,
                    tags=["env-file", "weak-algorithm"],
                ))
            elif _secret_name_match(key) and not _is_placeholder(val) and len(val) >= 4:
                findings.append(Finding(
                    file=file_path,
                    line=_validate_line_bounds(line_no, total_lines),
                    column=0,
                    language="config",
                    rule_id="config-plaintext-secret",
                    rule_name="Plaintext secret in .env file",
                    category="hardcoded-secret",
                    algorithm="Hardcoded key material",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Variable '{key}' in committed .env file holds a plaintext secret.",
                    recommendation="Remove .env from version control, use a secrets manager, and rotate credentials.",
                    code_snippet=stripped,
                    confidence=Confidence.POSSIBLE,
                    tags=["env-file", "committed-secret"],
                ))

    return findings


def _analyze_yaml_json(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()
    total_lines = len(lines)

    # Line-by-line key: value structural scan supporting JSON object formatting
    kv_re = re.compile(r'^[ \t\{]*["\']?([A-Za-z0-9_\.\-]+)["\']?[ \t]*:[ \t]*(.+)$')

    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Check TLS disabled flags
        for pattern, label in _TLS_DISABLED_PATTERNS:
            if pattern.search(raw_line):
                findings.append(Finding(
                    file=file_path,
                    line=_validate_line_bounds(line_no, total_lines),
                    column=0,
                    language="config",
                    rule_id="tls-verification-disabled",
                    rule_name="TLS verification disabled",
                    category="tls",
                    algorithm="Disabled TLS verification",
                    severity=Severity.CRITICAL,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"TLS certificate verification disabled in config ({label}).",
                    recommendation="Remove TLS-disabling settings and configure trusted CA certs.",
                    code_snippet=stripped,
                    confidence=Confidence.POSSIBLE,
                    tags=["config", "tls", "mitm-risk"],
                ))

        m = kv_re.match(raw_line)
        if m:
            key = m.group(1).strip()
            raw_val = m.group(2).strip()

            if " #" in raw_val and not (raw_val.startswith('"') or raw_val.startswith("'")):
                raw_val = raw_val.split(" #", 1)[0].strip()

            val = raw_val.strip(',"\'')
            if val.endswith('}') and not val.startswith('${') and not val.startswith('{{'):
                val = val.rstrip('}').strip(',"\'')

            # 1. Weak algorithm check (checked on VALUE)
            algo_profile = rules.classify_algorithm(val)
            if algo_profile:
                findings.append(Finding(
                    file=file_path,
                    line=_validate_line_bounds(line_no, total_lines),
                    column=0,
                    language="config",
                    rule_id=algo_profile["rule_id"],
                    rule_name=algo_profile["rule_name"],
                    category=algo_profile["category"],
                    algorithm=algo_profile["algorithm"],
                    severity=algo_profile["severity"],
                    quantum_risk=algo_profile["quantum_risk"],
                    message=f"Config key '{key}' sets weak/deprecated algorithm '{val}'.",
                    recommendation=algo_profile["recommendation"],
                    code_snippet=stripped,
                    confidence=Confidence.POSSIBLE,
                    tags=["config", "weak-algorithm"],
                ))
            # 2. Secret check (key matches secret hints, value is non-placeholder)
            elif _secret_name_match(key) and not _is_placeholder(val) and len(val) >= 4 and not val.startswith("{") and not val.startswith("["):
                findings.append(Finding(
                    file=file_path,
                    line=_validate_line_bounds(line_no, total_lines),
                    column=0,
                    language="config",
                    rule_id="config-plaintext-secret",
                    rule_name="Plaintext secret in config file",
                    category="hardcoded-secret",
                    algorithm="Hardcoded key material",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Config key '{key}' holds a plaintext literal secret.",
                    recommendation=rules.HARDCODED_KEY["recommendation"],
                    code_snippet=stripped,
                    confidence=Confidence.POSSIBLE,
                    tags=["config", "plaintext-secret"],
                ))

    return findings


def _analyze_ini_conf(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()
    total_lines = len(lines)

    ini_re = re.compile(r'^[ \t]*([A-Za-z0-9_\.\-]+)[ \t]*[=:][ \t]*(.+)$')

    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        m = ini_re.match(raw_line)
        if m:
            key = m.group(1).strip()
            raw_val = m.group(2).strip()

            if " #" in raw_val:
                raw_val = raw_val.split(" #", 1)[0].strip()
            if " ;" in raw_val:
                raw_val = raw_val.split(" ;", 1)[0].strip()

            val = raw_val.strip('"\'')

            algo_profile = rules.classify_algorithm(val)
            if algo_profile:
                findings.append(Finding(
                    file=file_path,
                    line=_validate_line_bounds(line_no, total_lines),
                    column=0,
                    language="config",
                    rule_id=algo_profile["rule_id"],
                    rule_name=algo_profile["rule_name"],
                    category=algo_profile["category"],
                    algorithm=algo_profile["algorithm"],
                    severity=algo_profile["severity"],
                    quantum_risk=algo_profile["quantum_risk"],
                    message=f"Configuration '{key}' specifies weak algorithm '{val}'.",
                    recommendation=algo_profile["recommendation"],
                    code_snippet=stripped,
                    confidence=Confidence.POSSIBLE,
                    tags=["config", "weak-algorithm"],
                ))
            elif _secret_name_match(key) and not _is_placeholder(val) and len(val) >= 4:
                findings.append(Finding(
                    file=file_path,
                    line=_validate_line_bounds(line_no, total_lines),
                    column=0,
                    language="config",
                    rule_id="config-plaintext-secret",
                    rule_name="Plaintext secret in config file",
                    category="hardcoded-secret",
                    algorithm="Hardcoded key material",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Configuration '{key}' in {os.path.basename(file_path)} holds plaintext secret.",
                    recommendation=rules.HARDCODED_KEY["recommendation"],
                    code_snippet=stripped,
                    confidence=Confidence.POSSIBLE,
                    tags=["config", "ini", "plaintext-secret"],
                ))

    return findings


# ---------------------------------------------------------------------------
# Main Analyzer Class
# ---------------------------------------------------------------------------

class RegexAnalyzer:
    """
    Structural config-file detection layer.
    Pure offline analyzer for Dockerfiles, YAML, JSON, .env, .ini, .conf, .toml.
    """

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        """Analyze a single config or infrastructure file."""
        if _is_dockerfile(file_path):
            return _analyze_dockerfile(file_path, source)
        if _is_env_file(file_path):
            return _analyze_env_file(file_path, source)
        if _is_yaml_file(file_path) or _is_json_config(file_path):
            return _analyze_yaml_json(file_path, source)
        if _is_ini_conf(file_path):
            return _analyze_ini_conf(file_path, source)
        return []
