"""
Regex / Config-File Layer.

Scans non-AST-parseable config formats for cryptographic hygiene issues:
  - Dockerfiles: hardcoded secrets in ENV/ARG, disabled TLS flags
  - YAML/JSON config files: plaintext secrets, disabled TLS/cert verification
  - .env files: committed plaintext secrets

Does NOT touch: package.json, package-lock.json, composer.json (Person 2's SCA
territory), or any .py/.js files (covered by the AST-based analyzers).

Output contract: RegexAnalyzer.analyze(file_path, source) -> List[Finding]
  language = "config" for all findings from this layer
  confidence defaults to Confidence.POSSIBLE (weak/single signal by design)
"""
import re
import os
from typing import List

from .models import Finding, Severity, QuantumRisk, Confidence
from . import rules

# ---------------------------------------------------------------------------
# Placeholder / template values that are NOT real secrets
# ---------------------------------------------------------------------------
_PLACEHOLDER_VALUES = frozenset({
    "", "changeme", "your-secret-here", "xxx", "<secret>",
    "todo", "fixme", "example", "replace_me", "insert_secret_here",
    "password", "secret", "your_password_here",
})

_PLACEHOLDER_PATTERNS = re.compile(
    r"""
    ^\$\{[^}]*\}$       |   # ${VAR} shell/docker interpolation
    ^%[^%]+%$           |   # %VAR% Windows-style interpolation
    ^\{\{[^}]+\}\}$     |   # {{var}} template interpolation
    ^\$\([^)]+\)$           # $(command) shell substitution
    """,
    re.VERBOSE,
)


def _is_placeholder(value: str) -> bool:
    """Return True if the value is an obvious placeholder that is not a real secret."""
    v = value.strip().strip('"\'')
    if v.lower() in _PLACEHOLDER_VALUES:
        return True
    if _PLACEHOLDER_PATTERNS.match(v):
        return True
    return False


def _secret_name_match(name: str) -> bool:
    """Delegates to the shared word-boundary matcher in rules.
    Reuses rules.matches_secret_hint() — single source of truth, consistent with the AST layer."""
    return rules.matches_secret_hint(name)


# ---------------------------------------------------------------------------
# File-type routing helpers
# ---------------------------------------------------------------------------

def _is_dockerfile(path: str) -> bool:
    """True for Dockerfile, Dockerfile.dev, Dockerfile.prod, etc."""
    bn = os.path.basename(path)
    return bn == "Dockerfile" or bn.startswith("Dockerfile.")


def _is_env_file(path: str) -> bool:
    """True for .env, .env.local, .env.production, etc."""
    bn = os.path.basename(path)
    return bn == ".env" or bn.startswith(".env.")


def _is_yaml_file(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in {".yml", ".yaml"}


def _is_json_config(path: str) -> bool:
    """True for .json files that are NOT package.json / package-lock.json / composer.json
    (those are Person 2's SCA territory)."""
    bn = os.path.basename(path).lower()
    if bn in {"package.json", "package-lock.json", "composer.json"}:
        return False
    ext = os.path.splitext(path)[1].lower()
    return ext == ".json"


def _is_ini_conf(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in {".ini", ".conf"}


# ---------------------------------------------------------------------------
# Dockerfile analysis
# ---------------------------------------------------------------------------

# Matches: ENV SECRET_KEY=value  or  ARG SECRET_KEY=value  (one-liner forms)
_DOCKER_ENV_ARG = re.compile(
    r'^[ \t]*(ENV|ARG)[ \t]+([A-Z_][A-Z0-9_]*)[ \t]*=[ \t]*(.+)',
    re.IGNORECASE | re.MULTILINE,
)

# TLS-disabling patterns in Dockerfiles
_DOCKER_TLS_PATTERNS = [
    # ENV NODE_TLS_REJECT_UNAUTHORIZED=0
    re.compile(r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0["\']?', re.IGNORECASE),
    # curl -k / curl --insecure
    re.compile(r'\bcurl\b[^\n]*(?:-k\b|--insecure\b)', re.IGNORECASE),
    # wget --no-check-certificate
    re.compile(r'\bwget\b[^\n]*--no-check-certificate\b', re.IGNORECASE),
    # pip install --trusted-host
    re.compile(r'\bpip\b[^\n]*--trusted-host\b', re.IGNORECASE),
]


def _analyze_dockerfile(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()

    # Check ENV/ARG for hardcoded secrets
    for m in _DOCKER_ENV_ARG.finditer(source):
        var_name = m.group(2)
        value = m.group(3).strip().strip('"\'')
        # Calculate line number from match position
        line_no = source[:m.start()].count('\n') + 1
        if not _secret_name_match(var_name):
            continue
        if _is_placeholder(value):
            continue
        findings.append(Finding(
            file=file_path,
            line=line_no,
            column=0,
            language="config",
            rule_id="dockerfile-hardcoded-secret",
            rule_name="Dockerfile hardcoded secret",
            category="hardcoded-secret",
            algorithm="Hardcoded key material",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message=(
                f"Dockerfile {m.group(1)} instruction sets '{var_name}' to a "
                "literal value — anyone with repo access recovers the secret."
            ),
            recommendation=rules.HARDCODED_KEY["recommendation"],
            code_snippet=m.group(0).strip(),
            confidence=Confidence.POSSIBLE,
            tags=["dockerfile", "hardcoded-secret"],
        ))

    # Check for TLS-disabling instructions
    for pattern in _DOCKER_TLS_PATTERNS:
        for m in pattern.finditer(source):
            line_no = source[:m.start()].count('\n') + 1
            findings.append(Finding(
                file=file_path,
                line=line_no,
                column=0,
                language="config",
                rule_id="tls-verification-disabled",
                rule_name="TLS verification disabled",
                category="tls",
                algorithm="Disabled TLS verification",
                severity=Severity.CRITICAL,
                quantum_risk=QuantumRisk.CLASSICAL_RISK,
                message=(
                    "TLS/SSL certificate verification is explicitly disabled. "
                    "This allows man-in-the-middle attacks without any crypto warning."
                ),
                recommendation=(
                    "Remove all TLS-disabling flags (curl -k, wget --no-check-certificate, "
                    "NODE_TLS_REJECT_UNAUTHORIZED=0). Use a properly configured CA bundle or "
                    "mount a custom certificate instead."
                ),
                code_snippet=m.group(0).strip(),
                confidence=Confidence.POSSIBLE,
                tags=["tls", "mitm-risk"],
            ))

    return findings


# ---------------------------------------------------------------------------
# .env / .env.* file analysis
# ---------------------------------------------------------------------------

# Matches: KEY=value lines (skips comments and blank lines)
_ENV_LINE = re.compile(
    r'^[ \t]*([A-Z_][A-Z0-9_]*)[ \t]*=[ \t]*(.+)$',
    re.IGNORECASE | re.MULTILINE,
)


def _analyze_env_file(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    for m in _ENV_LINE.finditer(source):
        key = m.group(1)
        value = m.group(2).strip().strip('"\'')
        line_no = source[:m.start()].count('\n') + 1

        # Skip comment lines (line starts with #)
        line_start = source.rfind('\n', 0, m.start()) + 1
        line_prefix = source[line_start:m.start()].lstrip()
        if line_prefix.startswith('#'):
            continue

        if not _secret_name_match(key):
            continue
        if not value or _is_placeholder(value):
            continue

        findings.append(Finding(
            file=file_path,
            line=line_no,
            column=0,
            language="config",
            rule_id="config-plaintext-secret",
            rule_name="Plaintext secret in .env file",
            category="hardcoded-secret",
            algorithm="Hardcoded key material",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message=(
                f"Variable '{key}' in committed .env file holds a plaintext secret. "
                "Committing .env files exposes credentials to all repo access holders."
            ),
            recommendation=(
                "Remove this file from version control (add to .gitignore), use a secrets "
                "manager or KMS, and rotate this credential immediately."
            ),
            code_snippet=m.group(0).strip(),
            confidence=Confidence.POSSIBLE,
            tags=["env-file", "committed-secret"],
        ))

    return findings


# ---------------------------------------------------------------------------
# YAML / JSON config file analysis
# ---------------------------------------------------------------------------

# Key: value patterns for plaintext secrets in YAML
_YAML_SECRET_KEY_VALUE = re.compile(
    r'^[ \t]*(["\']?)([a-z_][a-z0-9_]*)\1[ \t]*:[ \t]*(["\']?)([^#\n]+)\3',
    re.IGNORECASE | re.MULTILINE,
)

# JSON "key": "value" or "key": value patterns
_JSON_KEY_VALUE = re.compile(
    r'"([a-z_][a-z0-9_]*)"[ \t]*:[ \t]*"([^"]+)"',
    re.IGNORECASE,
)

# TLS/SSL disabled patterns in YAML/JSON configs
_CONFIG_TLS_PATTERNS = [
    # verify: false / verify: False
    re.compile(r'\bverify\s*:\s*false\b', re.IGNORECASE),
    # ssl: false
    re.compile(r'\bssl\s*:\s*false\b', re.IGNORECASE),
    # rejectUnauthorized: false  (Node.js TLS options)
    re.compile(r'\brejectUnauthorized\s*:\s*false\b', re.IGNORECASE),
    # InsecureSkipVerify: true  (Go TLS config)
    re.compile(r'\bInsecureSkipVerify\s*:\s*true\b', re.IGNORECASE),
    # tls_verify: false (Python requests / docker-compose style)
    re.compile(r'\btls_verify\s*:\s*false\b', re.IGNORECASE),
    # REQUESTS_CA_BUNDLE=''  / CURL_CA_BUNDLE=''
    re.compile(r'\b(REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE)\s*[=:]\s*["\']?\s*["\']?\s*$', re.IGNORECASE | re.MULTILINE),
]


def _analyze_yaml_json(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    is_json = file_path.lower().endswith(".json")

    # --- Check for TLS-disabling flags first ---
    for pattern in _CONFIG_TLS_PATTERNS:
        for m in pattern.finditer(source):
            line_no = source[:m.start()].count('\n') + 1
            findings.append(Finding(
                file=file_path,
                line=line_no,
                column=0,
                language="config",
                rule_id="tls-verification-disabled",
                rule_name="TLS verification disabled",
                category="tls",
                algorithm="Disabled TLS verification",
                severity=Severity.CRITICAL,
                quantum_risk=QuantumRisk.CLASSICAL_RISK,
                message=(
                    f"TLS/SSL certificate verification is explicitly disabled "
                    f"('{m.group(0).strip()}'). This allows MITM attacks silently."
                ),
                recommendation=(
                    "Remove TLS-disabling settings. Configure a proper CA bundle "
                    "or use a self-signed cert with explicit trust anchoring instead."
                ),
                code_snippet=m.group(0).strip(),
                confidence=Confidence.POSSIBLE,
                tags=["tls", "mitm-risk"],
            ))

    # --- Check for plaintext secrets in key:value pairs ---
    pattern = _JSON_KEY_VALUE if is_json else _YAML_SECRET_KEY_VALUE

    for m in pattern.finditer(source):
        if is_json:
            key = m.group(1)
            value = m.group(2).strip()
        else:
            key = m.group(2)
            value = m.group(4).strip().strip('"\'')

        if not _secret_name_match(key):
            continue
        if not value or _is_placeholder(value):
            continue

        line_no = source[:m.start()].count('\n') + 1
        findings.append(Finding(
            file=file_path,
            line=line_no,
            column=0,
            language="config",
            rule_id="config-plaintext-secret",
            rule_name="Plaintext secret in config file",
            category="hardcoded-secret",
            algorithm="Hardcoded key material",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message=(
                f"Config key '{key}' holds a plaintext literal secret. "
                "Committing secrets in config files exposes them to all repo access holders."
            ),
            recommendation=rules.HARDCODED_KEY["recommendation"],
            code_snippet=m.group(0).strip(),
            confidence=Confidence.POSSIBLE,
            tags=["config", "plaintext-secret"],
        ))

    return findings


# ---------------------------------------------------------------------------
# .ini / .conf file analysis
# ---------------------------------------------------------------------------

_INI_KEY_VALUE = re.compile(
    r'^[ \t]*([a-z_][a-z0-9_]*)[ \t]*[=:][ \t]*(.+)$',
    re.IGNORECASE | re.MULTILINE,
)


def _analyze_ini(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    for m in _INI_KEY_VALUE.finditer(source):
        key = m.group(1)
        value = m.group(2).strip().strip('"\'')
        line_no = source[:m.start()].count('\n') + 1

        # Skip comment lines
        line_start = source.rfind('\n', 0, m.start()) + 1
        raw_line = source[line_start:].split('\n')[0].lstrip()
        if raw_line.startswith('#') or raw_line.startswith(';'):
            continue

        if not _secret_name_match(key):
            continue
        if not value or _is_placeholder(value):
            continue

        findings.append(Finding(
            file=file_path,
            line=line_no,
            column=0,
            language="config",
            rule_id="config-plaintext-secret",
            rule_name="Plaintext secret in config file",
            category="hardcoded-secret",
            algorithm="Hardcoded key material",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message=(
                f"Config key '{key}' holds a plaintext literal secret in an .ini/.conf file."
            ),
            recommendation=rules.HARDCODED_KEY["recommendation"],
            code_snippet=m.group(0).strip(),
            confidence=Confidence.POSSIBLE,
            tags=["config", "ini", "plaintext-secret"],
        ))

    return findings


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------

class RegexAnalyzer:
    """
    Regex/config-file detection layer. Mirrors PythonAnalyzer/JSAnalyzer interface:
      .analyze(file_path: str, source: str) -> List[Finding]

    All findings have language="config" and confidence=Confidence.POSSIBLE by default.
    Call promote_confirmed() (scanner/confidence.py) after dedup to upgrade findings
    that are corroborated by the AST layer.
    """

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        """Analyze a single config/infra file. Returns zero findings for clean files."""
        if _is_dockerfile(file_path):
            return _analyze_dockerfile(file_path, source)
        if _is_env_file(file_path):
            return _analyze_env_file(file_path, source)
        if _is_yaml_file(file_path):
            return _analyze_yaml_json(file_path, source)
        if _is_json_config(file_path):
            return _analyze_yaml_json(file_path, source)
        if _is_ini_conf(file_path):
            return _analyze_ini(file_path, source)
        # Unknown type — return nothing rather than guess
        return []
