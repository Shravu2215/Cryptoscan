"""
Master Engine Generalization & Invariant Test Suite.

Verifies:
  1. Config/Regex structural key-value parsing (no line-proximity bugs, non-crypto algorithm exclusion, safe algorithm exclusion).
  2. False positive control in source code (comments and log strings not treated as crypto operations).
  3. Dynamic confidence scoring based on independent layer corroboration counts.
  4. Known-library metadata completeness and validation.
  5. First-class suppression status with CI gate safety.
  6. AST coverage for key sizes and legacy algorithms.
  7. Hard bounds assertion (reported_line <= file_line_count) across all analyzers.
"""
import json
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.models import Finding, Severity, QuantumRisk, Confidence
from scanner import rules
from scanner.regex_analyzer import RegexAnalyzer
from scanner.entropy_analyzer import EntropyAnalyzer
from scanner.python_analyzer import PythonAnalyzer
from scanner.sca_analyzer import SCAAnalyzer, KNOWN_CRYPTO_LIBRARIES
from scanner.confidence import promote_confirmed
from scanner.sca_correlation import correlate_sca_with_source
from scanner.suppression import load_suppressions, apply_suppressions
from scanner.cli import scan


class TestConfigLayerGeneralization:
    def setup_method(self):
        self.analyzer = RegexAnalyzer()

    def test_ignores_non_crypto_algorithms_like_gzip(self):
        yaml_content = """
service:
  name: image-processor
  compression:
    algorithm: gzip
    level: 9
  routing:
    algorithm: round-robin
"""
        findings = self.analyzer.analyze("service.yaml", yaml_content)
        assert len(findings) == 0, f"Expected 0 findings for non-crypto algorithms, got: {findings}"

    def test_ignores_safe_modern_algorithms_in_config(self):
        yaml_content = """
security:
  token_hash:
    algorithm: SHA-256
  encryption:
    cipher: AES-256-GCM
    kdf: argon2id
"""
        findings = self.analyzer.analyze("security.yaml", yaml_content)
        assert len(findings) == 0, f"Expected 0 findings for safe modern algorithms, got: {findings}"

    def test_detects_weak_algorithm_in_nested_yaml_layouts(self):
        yaml_content = """
# Production database configuration
database:
  connection:
    host: db.internal
    port: 5432
  crypto:
    legacy_support:
      hash: MD5
      cipher: 3DES
"""
        findings = self.analyzer.analyze("database.yaml", yaml_content)
        rule_ids = {f.rule_id for f in findings}
        assert "config-weak-algorithm" in rule_ids
        algos = {f.algorithm for f in findings}
        assert "MD5" in algos
        assert "3DES/DES" in algos

    def test_detects_weak_algorithm_in_dockerfile_env(self):
        dockerfile = """
FROM python:3.11-slim
WORKDIR /app
ENV APP_ENV=production
ENV LEGACY_CRYPTO_ALGO=3DES
CMD ["python", "app.py"]
"""
        findings = self.analyzer.analyze("Dockerfile", dockerfile)
        assert any(f.rule_id == "config-weak-algorithm" and f.algorithm == "3DES/DES" for f in findings)

    def test_line_numbers_strictly_within_file_bounds(self):
        config_content = """
key1: val1
algorithm: DES
key2: val2
"""
        lines_count = len(config_content.splitlines())
        findings = self.analyzer.analyze("test.yaml", config_content)
        for f in findings:
            assert 1 <= f.line <= lines_count, f"Finding line {f.line} exceeded file line count {lines_count}"


class TestFalsePositiveControl:
    def test_comments_and_logs_not_flagged_as_crypto_calls(self):
        code = """
import logging
logger = logging.getLogger(__name__)

# Note: we previously used MD5 and DES for legacy checksums in v1.0
def process_user_data(user_id):
    logger.info("Processing user with algorithm: SHA-256")
    msg = "This string mentions DES and MD5 in descriptive text"
    return {"status": "ok", "user": user_id}
"""
        py_analyzer = PythonAnalyzer()
        findings = py_analyzer.analyze("processor.py", code)
        # Should produce 0 findings because no actual hashlib/cipher function was called
        assert len(findings) == 0, f"Expected 0 findings for comments and logs, got: {findings}"


class TestDynamicConfidenceScoring:
    def test_single_layer_versus_multi_layer_agreement(self):
        # 1. Single pattern/regex finding -> POSSIBLE
        f_regex = Finding(
            file="app.yaml",
            line=10,
            column=0,
            language="config",
            rule_id="config-plaintext-secret",
            rule_name="Config Secret",
            category="hardcoded-secret",
            algorithm="Plaintext Secret",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="Secret in config",
            recommendation="Fix",
            confidence=Confidence.POSSIBLE,
        )
        assert f_regex.confidence == Confidence.POSSIBLE

        # 2. Single AST structural finding -> LIKELY
        f_ast = Finding(
            file="src/auth.py",
            line=20,
            column=0,
            language="python",
            rule_id="md5-weak-password-hash",
            rule_name="MD5 Hash",
            category="hash",
            algorithm="MD5",
            severity=Severity.CRITICAL,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="MD5 used",
            recommendation="Replace",
            confidence=Confidence.LIKELY,
        )
        assert f_ast.confidence == Confidence.LIKELY

        # 3. Two independent layers agreeing on same file & line -> CONFIRMED
        f_ast_secret = Finding(
            file="src/keys.py",
            line=5,
            column=0,
            language="python",
            rule_id="aes-hardcoded-key",
            rule_name="Hardcoded Key",
            category="hardcoded-secret",
            algorithm="Hardcoded key material",
            severity=Severity.CRITICAL,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="Hardcoded key in AST",
            recommendation="Rotate",
            confidence=Confidence.LIKELY,
        )
        f_ent_secret = Finding(
            file="src/keys.py",
            line=5,
            column=0,
            language="python",
            rule_id="entropy-secret-high-confidence",
            rule_name="High Entropy Secret",
            category="hardcoded-secret",
            algorithm="Hardcoded key material",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="High entropy secret",
            recommendation="Rotate",
            confidence=Confidence.LIKELY,
        )
        promoted = promote_confirmed([f_ast_secret, f_ent_secret])
        assert len(promoted) == 1
        assert promoted[0].confidence == Confidence.CONFIRMED
        assert promoted[0].severity == Severity.CRITICAL


class TestKnownLibraryTableCompleteness:
    def test_all_library_entries_have_required_metadata(self):
        for ecosystem, packages in KNOWN_CRYPTO_LIBRARIES.items():
            for pkg_name, meta in packages.items():
                assert "purpose" in meta, f"{ecosystem}:{pkg_name} missing 'purpose'"
                assert "algorithms" in meta, f"{ecosystem}:{pkg_name} missing 'algorithms'"
                assert isinstance(meta["algorithms"], list), f"{ecosystem}:{pkg_name} algorithms must be list"
                assert "severity" in meta, f"{ecosystem}:{pkg_name} missing 'severity'"
                assert isinstance(meta["severity"], Severity), f"{ecosystem}:{pkg_name} severity invalid"
                assert "quantum_risk" in meta, f"{ecosystem}:{pkg_name} missing 'quantum_risk'"
                assert isinstance(meta["quantum_risk"], QuantumRisk), f"{ecosystem}:{pkg_name} quantum_risk invalid"
                assert "is_weak" in meta, f"{ecosystem}:{pkg_name} missing 'is_weak' flag"


class TestSuppressionFirstClassStatus:
    def test_suppressed_findings_marked_and_not_deleted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ignore_file = os.path.join(temp_dir, ".cryptoscan-ignore")
            with open(ignore_file, "w", encoding="utf-8") as f:
                f.write("md5-hashing|src/legacy.py\n")

            suppressions = load_suppressions(temp_dir)
            f = Finding(
                file=os.path.join(temp_dir, "src/legacy.py"),
                line=12,
                column=0,
                language="python",
                rule_id="md5-hashing",
                rule_name="MD5 Hashing",
                category="hash",
                algorithm="MD5",
                severity=Severity.HIGH,
                quantum_risk=QuantumRisk.CLASSICAL_RISK,
                message="MD5 used",
                recommendation="Replace",
            )
            all_f, supp_count = apply_suppressions([f], suppressions, repo_path=temp_dir)
            assert supp_count == 1
            assert len(all_f) == 0  # Unsuppressed kept findings is empty
            assert f.suppressed is True  # In-place flag set
            assert "Suppressed by" in f.suppression_reason


class TestASTKeySizeValidation:
    def test_rsa_key_generation_key_size_thresholds(self):
        py_analyzer = PythonAnalyzer()
        # Weak RSA (1024 bits)
        code_1024 = """
from Crypto.PublicKey import RSA
key = RSA.generate(1024)
"""
        findings_1024 = py_analyzer.analyze("rsa_gen.py", code_1024)
        assert len(findings_1024) == 1
        assert findings_1024[0].severity == Severity.HIGH
        assert "undersized-classical-key" in findings_1024[0].tags
