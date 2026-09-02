"""
Config & Infrastructure Layer.

Performs structural and configuration parsing for:
  1. Web server SSL/TLS configs (nginx, Apache, HAProxy): weak protocols and ciphers.
  2. Terraform files (.tf): hardcoded secret attributes.
  3. Kubernetes Secret manifests (.yaml, .yml): multi-document YAML aware scanning of kind: Secret data and stringData.
"""
import base64
import os
import re
from typing import List, Optional

from .models import Finding, Severity, QuantumRisk, Confidence
from . import rules


# ---------------------------------------------------------------------------
# Weak Protocol and Cipher Patterns
# ---------------------------------------------------------------------------

_WEAK_PROTOCOLS_RE = re.compile(r'\b(?:SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1(?![.\d]))\b', re.IGNORECASE)
_WEAK_CIPHERS_RE = re.compile(r'\b(RC4|DES|3DES|DES-CBC3|MD5|NULL|EXPORT|ADH|AECDH)\b', re.IGNORECASE)

_NGINX_PROTO_RE = re.compile(r'^\s*ssl_protocols\s+([^;]+);', re.IGNORECASE)
_NGINX_CIPHER_RE = re.compile(r'^\s*ssl_ciphers\s+([^;]+);', re.IGNORECASE)

_APACHE_PROTO_RE = re.compile(r'^\s*SSLProtocol\s+(.+)$', re.IGNORECASE)
_APACHE_CIPHER_RE = re.compile(r'^\s*SSLCipherSuite\s+(.+)$', re.IGNORECASE)

_HAPROXY_CIPHER_RE = re.compile(r'^\s*(?:ssl-default-bind-ciphers|ciphers)\s+([^#\n]+)', re.IGNORECASE)
_HAPROXY_PROTO_RE = re.compile(r'^\s*(?:ssl-default-bind-options|options)\s+([^#\n]+)', re.IGNORECASE)

_TF_SECRET_ASSIGN_RE = re.compile(
    r'^[ \t]*([A-Za-z0-9_\-]+)[ \t]*=[ \t]*"([^"$][^"]*)"'
)


# ---------------------------------------------------------------------------
# File Target Matchers
# ---------------------------------------------------------------------------

def _is_web_server_config(file_path: str) -> bool:
    """True for nginx, apache, or haproxy configuration files."""
    norm = file_path.replace("\\", "/").lower()
    fn = os.path.basename(norm)
    if fn in {"nginx.conf", "httpd.conf", "apache2.conf", "ssl.conf", "haproxy.cfg", "haproxy.conf"}:
        return True
    if fn.endswith(".conf") or fn.endswith(".cfg"):
        if any(k in norm for k in ["nginx", "apache", "haproxy", "sites-available", "sites-enabled", "conf.d"]):
            return True
    return False


def _is_terraform_file(file_path: str) -> bool:
    return file_path.lower().endswith(".tf")


def _is_k8s_manifest(file_path: str, source: str) -> bool:
    """True if YAML file contains Kubernetes resources (apiVersion or kind)."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in {".yaml", ".yml"}:
        return False
    return bool(re.search(r'^\s*(?:apiVersion|kind)\s*:', source, re.MULTILINE | re.IGNORECASE))


# ---------------------------------------------------------------------------
# Analyzers per format
# ---------------------------------------------------------------------------

def _analyze_web_server(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()

    for line_no, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Nginx, Apache, & HAProxy Protocol checks
        m_proto = _NGINX_PROTO_RE.match(line) or _APACHE_PROTO_RE.match(line) or _HAPROXY_PROTO_RE.match(line)
        if m_proto:
            proto_val = m_proto.group(1).strip()
            weak_matches = _WEAK_PROTOCOLS_RE.findall(proto_val)
            if weak_matches:
                findings.append(Finding(
                    file=file_path,
                    line=line_no,
                    column=0,
                    language="infra",
                    rule_id="infra-weak-tls-protocol",
                    rule_name="Weak TLS Protocol in Web Server Config",
                    category="tls",
                    algorithm="TLS/SSL",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Deprecated TLS protocol(s) enabled: {', '.join(sorted(set(weak_matches)))}.",
                    recommendation="Disable legacy SSLv2, SSLv3, TLSv1, and TLSv1.1 protocols. Enforce TLSv1.2 or TLSv1.3 only.",
                    code_snippet=line,
                    specificity=3,
                    generic=False,
                    confidence=Confidence.LIKELY,
                    tags=["infra", "tls", "web-server"],
                ))

        # Nginx, Apache, & HAProxy Cipher checks
        m_cipher = _NGINX_CIPHER_RE.match(line) or _APACHE_CIPHER_RE.match(line) or _HAPROXY_CIPHER_RE.match(line)
        if m_cipher:
            cipher_val = m_cipher.group(1).strip()
            weak_matches = _WEAK_CIPHERS_RE.findall(cipher_val)
            if weak_matches:
                findings.append(Finding(
                    file=file_path,
                    line=line_no,
                    column=0,
                    language="infra",
                    rule_id="infra-weak-cipher-suite",
                    rule_name="Weak Cipher Suite in Web Server Config",
                    category="tls",
                    algorithm="Cipher Suite",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Insecure cipher(s) configured: {', '.join(sorted(set(weak_matches)))}.",
                    recommendation="Remove broken ciphers (RC4, DES, 3DES, MD5, NULL, EXPORT). Use modern AEAD suites (ECDHE-ECDSA-AES256-GCM-SHA384, etc.).",
                    code_snippet=line,
                    specificity=3,
                    generic=False,
                    confidence=Confidence.LIKELY,
                    tags=["infra", "tls", "ciphers"],
                ))

    return findings


def _analyze_terraform(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()

    for line_no, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        m = _TF_SECRET_ASSIGN_RE.search(raw_line)
        if m:
            attr_name = m.group(1)
            val = m.group(2).strip()

            # Skip dynamic references
            if val.startswith("var.") or val.startswith("local.") or val.startswith("data."):
                continue
            if val.startswith("${") and ("var." in val or "data." in val or "local." in val):
                continue
            if len(val) < 6:
                continue

            if rules.matches_secret_hint(attr_name):
                findings.append(Finding(
                    file=file_path,
                    line=line_no,
                    column=0,
                    language="infra",
                    rule_id="infra-terraform-hardcoded-secret",
                    rule_name="Hardcoded Secret in Terraform",
                    category="hardcoded-secret",
                    algorithm="Plaintext Secret",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Terraform attribute '{attr_name}' assigned literal secret value.",
                    recommendation="Do not hardcode secrets in Terraform manifests. Use input variables or a secret manager integration (AWS Secrets Manager, HashiCorp Vault).",
                    code_snippet=line,
                    specificity=2,
                    generic=False,
                    confidence=Confidence.POSSIBLE,
                    tags=["infra", "terraform", "hardcoded-secret"],
                ))

    return findings


def _analyze_k8s_manifests(file_path: str, source: str) -> List[Finding]:
    """
    Multi-document YAML aware Kubernetes secret scanning.
    Accurately isolates documents where `kind: Secret` is declared.
    """
    findings: List[Finding] = []
    lines = source.splitlines()

    is_secret_doc = False
    in_string_data = False
    in_data = False

    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()

        # Multi-document YAML separator
        if stripped == "---":
            is_secret_doc = False
            in_string_data = False
            in_data = False
            continue

        if not stripped or stripped.startswith("#"):
            continue

        # Check if current document is a Secret
        if re.match(r'^kind\s*:\s*Secret\b', stripped, re.IGNORECASE):
            is_secret_doc = True
            continue
        elif re.match(r'^kind\s*:\s*(?!Secret\b)[A-Za-z0-9]+', stripped, re.IGNORECASE):
            is_secret_doc = False
            in_string_data = False
            in_data = False
            continue

        if not is_secret_doc:
            continue

        indent = len(raw_line) - len(raw_line.lstrip())

        if re.match(r'^stringData\s*:\s*$', stripped):
            in_string_data = True
            in_data = False
            continue
        elif re.match(r'^data\s*:\s*$', stripped):
            in_data = True
            in_string_data = False
            continue
        elif indent == 0 and ":" in stripped and not (stripped.startswith("stringData") or stripped.startswith("data")):
            in_string_data = False
            in_data = False

        if (in_string_data or in_data) and ":" in stripped:
            key, val = stripped.split(":", 1)
            key = key.strip()
            val = val.strip().strip('"\'')

            if not val or val.startswith("<") or val.startswith("${"):
                continue

            is_secret = False
            if in_string_data and len(val) >= 4:
                is_secret = True
            elif in_data and len(val) >= 4:
                try:
                    decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
                    if decoded and len(decoded.strip()) >= 4:
                        is_secret = True
                except Exception:
                    pass

            if is_secret:
                findings.append(Finding(
                    file=file_path,
                    line=line_no,
                    column=0,
                    language="infra",
                    rule_id="infra-k8s-secret-plaintext",
                    rule_name="Plaintext or Reversible Secret in Kubernetes Manifest",
                    category="hardcoded-secret",
                    algorithm="Plaintext Secret",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Kubernetes Secret entry '{key}' contains literal/base64 committed secret.",
                    recommendation="Kubernetes Secret data/stringData fields committed to version control expose plaintext secrets. Use external secret operators (External Secrets Operator, SealedSecrets, or Vault).",
                    code_snippet=stripped,
                    specificity=2,
                    generic=False,
                    confidence=Confidence.POSSIBLE,
                    tags=["infra", "kubernetes", "hardcoded-secret"],
                ))

    return findings


# ---------------------------------------------------------------------------
# Config & Infra Analyzer Class
# ---------------------------------------------------------------------------

class ConfigInfraAnalyzer:
    """
    Analyzes web server SSL configurations (Nginx/Apache/HAProxy), Terraform files, and Kubernetes Secret manifests.
    """

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        """Analyze infra/config source file."""
        if _is_web_server_config(file_path):
            return _analyze_web_server(file_path, source)
        if _is_terraform_file(file_path):
            return _analyze_terraform(file_path, source)
        if _is_k8s_manifest(file_path, source):
            return _analyze_k8s_manifests(file_path, source)
        return []
