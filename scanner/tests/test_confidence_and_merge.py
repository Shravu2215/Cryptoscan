"""
Tests for Detection-Layer Bug Fixes:
1. Word-boundary matching for secret-name hints (no substring false positives).
2. Cross-layer deduplication/merging for same-secret findings.
3. End-to-end confidence tier differentiation (Confirmed, Likely, Possible).
4. Total-count consistency across fixture repos.
"""
import os
import sys
import pytest

# Ensure scanner directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.rules import matches_secret_hint
from scanner.models import Finding, Severity, QuantumRisk, Confidence
from scanner.confidence import promote_confirmed
from scanner.regex_analyzer import RegexAnalyzer
from scanner.entropy_analyzer import EntropyAnalyzer
from cli import scan


# ===========================================================================
# 1. Word-Boundary Matching Unit Tests
# ===========================================================================

class TestWordBoundaryMatching:
    """Validate that matches_secret_hint uses token boundaries, not raw substrings."""

    @pytest.mark.parametrize("identifier", [
        "NODE_TLS_REJECT_UNAUTHORIZED",  # contains 'auth' inside 'UNAUTHORIZED' -> must NOT match
        "AUTHOR_NAME",                   # contains 'auth' inside 'AUTHOR' -> must NOT match
        "TOKENIZER_MODEL_PATH",          # contains 'token' inside 'TOKENIZER' -> must NOT match
        "KEYBOARD_LAYOUT",               # contains 'key' inside 'KEYBOARD' -> must NOT match
        "keyboard_layout_type",          # snake_case negative
        "TokenizerVocabSize",            # camelCase negative
        "unauthorizedAccessHandler",     # camelCase negative
    ])
    def test_negative_identifiers_do_not_match(self, identifier):
        assert not matches_secret_hint(identifier), (
            f"Identifier {identifier!r} should NOT match secret hints (word-boundary violation)"
        )

    @pytest.mark.parametrize("identifier", [
        "API_KEY",
        "DB_PASSWORD",
        "AUTH_TOKEN",
        "SESSION_SECRET",
        "STRIPE_API_KEY",
        "PASSWORD_POLICY_MIN_LENGTH",    # 'password' is a genuine hint token -> must match
        "apiKey",
        "dbPassword",
        "authToken",
        "session_secret_val",
    ])
    def test_positive_identifiers_match(self, identifier):
        assert matches_secret_hint(identifier), (
            f"Identifier {identifier!r} SHOULD match secret hints"
        )


# ===========================================================================
# 2. Cross-Layer Merging Unit Tests
# ===========================================================================

class TestCrossLayerMerge:
    """Validate that multiple findings for the same secret are merged into one Confirmed finding."""

    def test_ast_and_entropy_same_site_merges_to_single_confirmed_finding(self):
        """When AST and entropy both flag the same line for hardcoded secret, merge to 1."""
        ast_finding = Finding(
            file="/repo/app.py",
            line=12,
            column=4,
            language="python",
            rule_id="hardcoded-key",
            rule_name="Hardcoded Key Material",
            category="hardcoded-secret",
            algorithm="Hardcoded key material",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="Hardcoded key at line 12",
            recommendation="Move to env var",
            confidence=Confidence.LIKELY,
        )
        entropy_finding = Finding(
            file="/repo/app.py",
            line=12,
            column=4,
            language="python",
            rule_id="entropy-secret-high-confidence",
            rule_name="High-Entropy Secret with Name Hint",
            category="hardcoded-secret",
            algorithm="Hardcoded Secret Material",
            severity=Severity.CRITICAL,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="High entropy secret at line 12",
            recommendation="Move to KMS",
            confidence=Confidence.LIKELY,
        )

        result = promote_confirmed([ast_finding, entropy_finding])

        assert len(result) == 1, f"Expected 1 merged finding, got {len(result)}"
        merged = result[0]
        assert merged.confidence == Confidence.CONFIRMED, "Merged finding must be CONFIRMED"
        assert merged.severity == Severity.CRITICAL, "Merged finding must keep the highest severity (CRITICAL)"
        assert merged.rule_id == "entropy-secret-high-confidence", "Must prefer higher-quality entropy rule_id"

    def test_distinct_vulnerabilities_on_same_line_not_dropped(self):
        """Findings with distinct categories on the same line are not dropped."""
        f_cipher = Finding(
            file="/repo/app.py",
            line=20,
            column=0,
            language="python",
            rule_id="aes-ecb-mode",
            rule_name="AES ECB Mode",
            category="symmetric-cipher",
            algorithm="AES-ECB",
            severity=Severity.CRITICAL,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="ECB mode used",
            recommendation="Use GCM",
            confidence=Confidence.LIKELY,
        )
        f_key = Finding(
            file="/repo/app.py",
            line=20,
            column=0,
            language="config",
            rule_id="config-plaintext-secret",
            rule_name="Plaintext Secret in Config",
            category="hardcoded-secret",
            algorithm="Plaintext Secret",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="Secret in config",
            recommendation="Use env",
            confidence=Confidence.POSSIBLE,
        )

        result = promote_confirmed([f_cipher, f_key])
        assert len(result) == 2, "Distinct vulnerability classes on the same line must both be preserved"
        assert all(f.confidence == Confidence.CONFIRMED for f in result)


# ===========================================================================
# 3. Confidence Tier Defaults
# ===========================================================================

class TestConfidenceDefaults:
    """Validate explicit confidence tiers per layer."""

    def test_ast_defaults_to_likely(self):
        f = Finding(
            file="app.py", line=1, column=0, language="python",
            rule_id="md5-hashing", rule_name="MD5 Hash", category="hash",
            algorithm="MD5", severity=Severity.CRITICAL, quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="MD5 used", recommendation="Use SHA-256",
        )
        assert f.confidence == Confidence.LIKELY

    def test_regex_analyzer_produces_possible(self):
        ra = RegexAnalyzer()
        content = "ENV DB_PASSWORD=mysecretpassword123\n"
        findings = ra.analyze("Dockerfile", content)
        assert len(findings) >= 1
        for fi in findings:
            assert fi.confidence == Confidence.POSSIBLE

    def test_entropy_high_confidence_is_likely(self):
        ea = EntropyAnalyzer()
        content = 'api_key = "dGVzdC1oaWdoLWVudHJvcHktc2VjcmV0LTk5ODg3Nw=="\n'
        findings = ea.analyze("config.py", content)
        assert len(findings) >= 1
        high_conf = [f for f in findings if f.rule_id == "entropy-secret-high-confidence"]
        assert len(high_conf) >= 1
        assert high_conf[0].confidence == Confidence.LIKELY

    def test_entropy_name_hint_only_is_possible(self):
        ea = EntropyAnalyzer()
        content = 'db_password = "simplepassword"\n'
        findings = ea.analyze("config.py", content)
        name_only = [f for f in findings if f.rule_id == "entropy-secret-name-hint-only"]
        assert len(name_only) >= 1
        assert name_only[0].confidence == Confidence.POSSIBLE


# ===========================================================================
# 4. End-to-End Scan Tests on Fresh Fixture Repos
# ===========================================================================

class TestFreshFixtureRepos:
    """End-to-end tests against fresh fixture repos with varied variable names."""

    FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "config")

    def test_repo_a_scan(self):
        repo_a_dir = os.path.join(self.FIXTURES_DIR, "repo_a")
        findings = scan(repo_a_dir)

        # 1. Benign identifiers in .env must NOT produce findings
        benign_rules = [f for f in findings if any(w in f.message for w in ["AUTHOR_NAME", "TOKENIZER_MODEL_PATH", "KEYBOARD_LAYOUT"])]
        assert len(benign_rules) == 0, f"False positives on benign identifiers: {benign_rules}"

        # 2. TLS disabled in Dockerfile produces exactly 1 finding
        tls_findings = [f for f in findings if f.rule_id == "tls-verification-disabled"]
        assert len(tls_findings) == 1, f"Expected 1 TLS finding, got {len(tls_findings)}"

        # 3. Clean YAML produces zero findings
        clean_yaml_findings = [f for f in findings if "config_clean.yml" in f.file]
        assert len(clean_yaml_findings) == 0, f"Clean YAML had findings: {clean_yaml_findings}"

        # 4. Confidence tiers are differentiated
        confidences = {f.confidence for f in findings}
        assert Confidence.POSSIBLE in confidences, "Expected at least one Possible confidence finding"

    def test_repo_b_scan(self):
        repo_b_dir = os.path.join(self.FIXTURES_DIR, "repo_b")
        findings = scan(repo_b_dir)

        # 1. No false positives on benign identifiers in repo_b
        for f in findings:
            for benign in ["KEYBOARD_LAYOUT_TYPE", "AUTHENTICATION_PROVIDER_CLASS", "TOKENIZER_VOCAB_SIZE"]:
                assert benign not in (f.code_snippet or ""), f"Flagged benign identifier {benign}"

        # 2. MD5 hash in sample.py produces 1 finding with Likely confidence
        md5_findings = [f for f in findings if "md5" in f.rule_id]
        assert len(md5_findings) == 1
        assert md5_findings[0].confidence == Confidence.LIKELY

        # 3. Multi-layer corroborated secrets in repo_b (.env) are CONFIRMED
        confirmed_findings = [f for f in findings if f.confidence == Confidence.CONFIRMED]
        assert len(confirmed_findings) >= 2, "Corroborated secrets in .env should be CONFIRMED"

        # 4. Total findings has a mix of tiers
        tiers = {f.confidence for f in findings}
        assert Confidence.CONFIRMED in tiers
        assert Confidence.LIKELY in tiers
