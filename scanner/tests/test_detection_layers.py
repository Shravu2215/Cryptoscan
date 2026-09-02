"""
Tests for the three new detection layers added by Person 1:
  - scanner/scanner/regex_analyzer.py   (Regex/Config layer)
  - scanner/scanner/entropy_analyzer.py (Entropy/Secrets layer)
  - scanner/scanner/confidence.py       (Confidence promotion)

These tests are entirely additive — they do NOT modify or depend on any
internals of the existing test_scanner.py suite.

Run with: python3 -m pytest scanner/tests/test_detection_layers.py -v
"""
import os
import sys
import math

import pytest

# Add the scanner directory so the module resolves correctly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.regex_analyzer import RegexAnalyzer, _is_placeholder
from scanner.entropy_analyzer import (
    EntropyAnalyzer,
    shannon_entropy,
    ENTROPY_THRESHOLD,
    MIN_SECRET_LEN,
)
from scanner.confidence import promote_confirmed
from scanner.models import Finding, Severity, QuantumRisk, Confidence

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES_CONFIG = os.path.join(os.path.dirname(__file__), "fixtures", "config")

ra = RegexAnalyzer()
ea = EntropyAnalyzer()


def _read(filename: str) -> str:
    with open(os.path.join(FIXTURES_CONFIG, filename), "r", encoding="utf-8") as fh:
        return fh.read()


def _fixture_path(filename: str) -> str:
    return os.path.join(FIXTURES_CONFIG, filename)


def _make_finding(language="python", rule_id="test-rule", line=10,
                  file="test.py", confidence=Confidence.LIKELY) -> Finding:
    """Helper: synthetic Finding for confidence promotion tests."""
    return Finding(
        file=file,
        line=line,
        column=0,
        language=language,
        rule_id=rule_id,
        rule_name="Test Rule",
        category="test",
        algorithm="Test",
        severity=Severity.HIGH,
        quantum_risk=QuantumRisk.CLASSICAL_RISK,
        message="Test finding",
        recommendation="Fix it.",
        confidence=confidence,
    )


# ===========================================================================
# Section 1 — Shannon Entropy unit tests
# ===========================================================================

class TestShannonEntropy:
    """
    Hand-verified expected values. The formula is:
      H = -sum(p_i * log2(p_i))  where p_i = count(c_i) / len(s)
    """

    def test_empty_string_returns_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_string_returns_zero(self):
        # Only one symbol → p=1 → H = -(1 * log2(1)) = 0
        assert shannon_entropy("aaaa") == 0.0

    def test_two_equal_symbol_string(self):
        # "aabb": p_a=0.5, p_b=0.5 → H = -(0.5*log2(0.5) + 0.5*log2(0.5)) = 1.0
        result = shannon_entropy("aabb")
        assert abs(result - 1.0) < 1e-9, f"expected 1.0, got {result}"

    def test_four_equal_symbols(self):
        # "abcd": each p=0.25 → H = -(4 * 0.25*log2(0.25)) = -(4 * 0.25*(-2)) = 2.0
        result = shannon_entropy("abcd")
        assert abs(result - 2.0) < 1e-9, f"expected 2.0, got {result}"

    def test_known_high_entropy_secret(self):
        # A Base64-style string with full alphanumeric + symbols charset exceeds 4.0 bits/char.
        # This string uses chars from multiple character classes to ensure high entropy.
        secret = "sK7mP2xNqR9vLwT4uY1hJfBzC5dGe8Ao"  # 32 chars, mixed case + digits
        h = shannon_entropy(secret)
        assert h >= ENTROPY_THRESHOLD, f"expected entropy >= {ENTROPY_THRESHOLD}, got {h}"

    def test_hex_string_entropy_is_below_4_bits(self):
        # Pure hex strings (only 16 distinct symbols: 0-9, a-f) have max theoretical
        # entropy of log2(16)=4.0 but in practice measured entropy is slightly below 4.0.
        # This confirms the documented behaviour: hex API keys may be caught by name-hint
        # alone rather than entropy alone — both signals work together.
        hex_secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        h = shannon_entropy(hex_secret)
        # Pure hex tokens have measured entropy around 3.9 bits/char (16 symbols max)
        assert 3.5 <= h <= 4.0, f"hex string entropy expected ~3.9, got {h}"

    def test_low_entropy_prose(self):
        # A typical English word / version string should be well below threshold
        assert shannon_entropy("production") < ENTROPY_THRESHOLD
        assert shannon_entropy("1.2.3") < ENTROPY_THRESHOLD
        assert shannon_entropy("changeme") < ENTROPY_THRESHOLD

    def test_returns_float(self):
        assert isinstance(shannon_entropy("hello world"), float)


# ===========================================================================
# Section 2 — Regex/Config Layer
# ===========================================================================

class TestRegexAnalyzerDockerfile:

    def test_dockerfile_hardcoded_secret_fires(self):
        """ENV instruction with a secret-like variable name → dockerfile-hardcoded-secret"""
        path = _fixture_path("Dockerfile.vuln")
        src = _read("Dockerfile.vuln")
        findings = ra.analyze(path, src)
        rule_ids = [f.rule_id for f in findings]
        assert "dockerfile-hardcoded-secret" in rule_ids, (
            f"Expected dockerfile-hardcoded-secret, got: {rule_ids}"
        )

    def test_dockerfile_tls_disabled_fires(self):
        """ENV NODE_TLS_REJECT_UNAUTHORIZED=0 → tls-verification-disabled"""
        path = _fixture_path("Dockerfile.vuln")
        src = _read("Dockerfile.vuln")
        findings = ra.analyze(path, src)
        rule_ids = [f.rule_id for f in findings]
        assert "tls-verification-disabled" in rule_ids, (
            f"Expected tls-verification-disabled, got: {rule_ids}"
        )

    def test_dockerfile_findings_have_correct_language(self):
        path = _fixture_path("Dockerfile.vuln")
        src = _read("Dockerfile.vuln")
        findings = ra.analyze(path, src)
        assert all(f.language == "config" for f in findings)

    def test_dockerfile_findings_have_line_numbers(self):
        path = _fixture_path("Dockerfile.vuln")
        src = _read("Dockerfile.vuln")
        findings = ra.analyze(path, src)
        assert all(f.line >= 1 for f in findings)

    def test_dockerfile_tls_is_critical(self):
        path = _fixture_path("Dockerfile.vuln")
        src = _read("Dockerfile.vuln")
        tls = [f for f in ra.analyze(path, src) if f.rule_id == "tls-verification-disabled"]
        assert len(tls) >= 1
        assert all(f.severity == Severity.CRITICAL for f in tls)

    def test_dockerfile_placeholder_not_flagged(self):
        """Placeholder values must be silently skipped."""
        fake_docker = "ENV SECRET_KEY=changeme\n"
        findings = ra.analyze("/tmp/Dockerfile", fake_docker)
        assert len(findings) == 0, f"Should not flag placeholder, got: {findings}"


class TestRegexAnalyzerYAML:

    def test_yaml_plaintext_secret_fires(self):
        path = _fixture_path("config-vuln.yml")
        src = _read("config-vuln.yml")
        findings = ra.analyze(path, src)
        rule_ids = [f.rule_id for f in findings]
        assert "config-plaintext-secret" in rule_ids, (
            f"Expected config-plaintext-secret in YAML, got: {rule_ids}"
        )

    def test_yaml_tls_disabled_fires(self):
        path = _fixture_path("config-vuln.yml")
        src = _read("config-vuln.yml")
        findings = ra.analyze(path, src)
        rule_ids = [f.rule_id for f in findings]
        assert "tls-verification-disabled" in rule_ids, (
            f"Expected tls-verification-disabled in YAML, got: {rule_ids}"
        )

    def test_yaml_clean_produces_zero_findings(self):
        """Negative control: clean config → zero findings."""
        path = _fixture_path("config-clean.yml")
        src = _read("config-clean.yml")
        findings = ra.analyze(path, src)
        # ${DATABASE_PASSWORD} is a placeholder — must be skipped
        secret_findings = [f for f in findings if f.rule_id == "config-plaintext-secret"]
        assert len(secret_findings) == 0, (
            f"Clean config should produce zero secret findings, got: {secret_findings}"
        )

    def test_yaml_tls_true_not_flagged(self):
        """verify: true is not a TLS-disabling setting."""
        src = "http_client:\n  verify: true\n"
        findings = ra.analyze("/fake/config.yml", src)
        tls = [f for f in findings if f.rule_id == "tls-verification-disabled"]
        assert len(tls) == 0, f"verify: true should not fire TLS rule, got: {tls}"


class TestRegexAnalyzerEnvFile:

    def test_env_plaintext_secret_fires(self):
        path = _fixture_path(".env.vuln")
        src = _read(".env.vuln")
        findings = ra.analyze(path, src)
        rule_ids = [f.rule_id for f in findings]
        assert "config-plaintext-secret" in rule_ids, (
            f"Expected config-plaintext-secret in .env, got: {rule_ids}"
        )

    def test_env_non_secret_var_not_flagged(self):
        """Non-secret variables like APP_PORT should not be flagged."""
        src = "APP_PORT=3000\nAPP_ENV=production\n"
        findings = ra.analyze("/fake/.env", src)
        assert len(findings) == 0, f"Non-secret vars should not fire, got: {findings}"

    def test_env_placeholder_not_flagged(self):
        """Placeholder values must be silently skipped."""
        src = "API_KEY=changeme\nDATABASE_PASSWORD=\n"
        findings = ra.analyze("/fake/.env", src)
        assert len(findings) == 0, f"Placeholders should not fire, got: {findings}"


class TestRegexAnalyzerIni:

    def test_ini_secret_key_fires(self):
        path = _fixture_path("app-vuln.ini")
        src = _read("app-vuln.ini")
        findings = ra.analyze(path, src)
        rule_ids = [f.rule_id for f in findings]
        assert "config-plaintext-secret" in rule_ids, (
            f"Expected config-plaintext-secret in .ini, got: {rule_ids}"
        )


# ===========================================================================
# Section 3 — Entropy/Secrets Layer
# ===========================================================================

class TestEntropyAnalyzer:

    def test_high_entropy_secret_fires(self):
        """A variable named 'api_key' with a high-entropy value → finding."""
        src = 'API_KEY = "test_sec_key_4xK9mNqRp2vBn7tLwS3cur3P4ssw0rdXq8mZ"\n'
        findings = ea.analyze("/fake/config.py", src)
        assert len(findings) >= 1, "High-entropy api_key should be flagged"

    def test_rule_id_high_confidence_when_both_signals(self):
        """entropy + name hit → entropy-secret-high-confidence"""
        src = 'SECRET_KEY = "4xK9mNqRp2vBn7tLwS3cur3P4ssw0rdXq8mZ1234"\n'
        findings = ea.analyze("/fake/app.py", src)
        hc = [f for f in findings if f.rule_id == "entropy-secret-high-confidence"]
        assert len(hc) >= 1, f"Expected entropy-secret-high-confidence, got: {[f.rule_id for f in findings]}"

    def test_high_entropy_only_fires_when_no_name_hint(self):
        """High entropy but random name → entropy-secret-high-entropy-only"""
        src = 'RANDOM_JUNK = "4xK9mNqRp2vBn7tLwS3cur3P4ssw0rdXq8mZ1234"\n'
        findings = ea.analyze("/fake/app.py", src)
        he_only = [f for f in findings if f.rule_id == "entropy-secret-high-entropy-only"]
        assert len(he_only) >= 1, f"Expected entropy-secret-high-entropy-only, got: {[f.rule_id for f in findings]}"

    def test_name_hint_only_fires_for_low_entropy_secret_name(self):
        """Low-entropy value but name says 'password' → entropy-secret-name-hint-only"""
        # "admin1234" has low entropy but is still flagged by name hint
        src = 'DATABASE_PASSWORD = "admin1234567890"\n'  # len >= 8
        findings = ea.analyze("/fake/app.py", src)
        # Should produce at least name-hint-only (might also match high-confidence)
        assert len(findings) >= 1, "Secret-named variable should be flagged even at low entropy"

    def test_short_strings_not_flagged(self):
        """Strings shorter than MIN_SECRET_LEN should not trigger entropy rule."""
        src = 'API_KEY = "short"\n'
        findings = ea.analyze("/fake/app.py", src)
        # len("short") < MIN_SECRET_LEN AND < MIN_NAME_HINT_LEN=8 → no finding
        assert len(findings) == 0, f"Too-short string should not be flagged, got: {findings}"

    def test_placeholder_not_flagged(self):
        """Placeholder values must be silently skipped."""
        src = 'SECRET_KEY = "changeme"\n'
        findings = ea.analyze("/fake/app.py", src)
        assert len(findings) == 0, f"Placeholder should not be flagged, got: {findings}"

    def test_version_string_not_flagged(self):
        """Version strings must be skipped as false positives."""
        src = 'APP_VERSION = "1.2.3"\n'
        findings = ea.analyze("/fake/app.py", src)
        assert len(findings) == 0, f"Version string should not be flagged, got: {findings}"

    def test_url_without_credentials_not_flagged(self):
        """Plain URLs without embedded user:pass@ are not secrets."""
        src = 'API_URL = "https://api.example.com/v2/endpoint"\n'
        findings = ea.analyze("/fake/app.py", src)
        assert len(findings) == 0, f"Bare URL should not be flagged, got: {findings}"

    def test_high_confidence_finding_has_likely_confidence(self):
        """entropy-secret-high-confidence → Confidence.LIKELY"""
        src = 'SECRET_KEY = "4xK9mNqRp2vBn7tLwS3cur3P4ssw0rdXq8mZ1234"\n'
        findings = ea.analyze("/fake/app.py", src)
        hc = [f for f in findings if f.rule_id == "entropy-secret-high-confidence"]
        assert len(hc) >= 1
        assert hc[0].confidence == Confidence.LIKELY

    def test_name_hint_only_finding_has_possible_confidence(self):
        """entropy-secret-name-hint-only → Confidence.POSSIBLE"""
        src = 'DATABASE_PASSWORD = "admin1234567890"\n'
        findings = ea.analyze("/fake/app.py", src)
        nh = [f for f in findings if f.rule_id == "entropy-secret-name-hint-only"]
        if nh:
            assert nh[0].confidence == Confidence.POSSIBLE

    def test_entropy_does_not_flag_low_entropy_non_secret_name(self):
        """Low entropy + no name hint → no finding (avoids pure prose FPs)."""
        src = 'GREETING = "hello world goodbye everyone"\n'
        findings = ea.analyze("/fake/app.py", src)
        assert len(findings) == 0, f"Low-entropy non-secret should not fire, got: {findings}"

    def test_js_assignment_extracted(self):
        """JS const/let/var assignments are extracted and analyzed."""
        src = 'const API_KEY = "test_sec_key_4xK9mNqRp2vBn7tLwS3cur3P4ssw0rdXq8mZ";\n'
        findings = ea.analyze("/fake/app.js", src)
        assert len(findings) >= 1, "JS const assignment with high-entropy secret should be flagged"


# ===========================================================================
# Section 4 — Confidence Promotion
# ===========================================================================

class TestPromoteConfirmed:

    def test_promotes_when_two_different_layers_agree(self):
        """AST finding (language='python') + config finding (language='config')
        at same file+line → both promoted to CONFIRMED."""
        ast_finding = _make_finding(
            language="python", rule_id="md5-weak-password-hash",
            file="/repo/app.py", line=42, confidence=Confidence.LIKELY,
        )
        config_finding = _make_finding(
            language="config", rule_id="entropy-secret-high-confidence",
            file="/repo/app.py", line=42, confidence=Confidence.LIKELY,
        )
        result = promote_confirmed([ast_finding, config_finding])
        assert all(f.confidence == Confidence.CONFIRMED for f in result), (
            f"Both should be CONFIRMED, got: {[f.confidence for f in result]}"
        )

    def test_no_promotion_when_only_one_layer(self):
        """Two findings from the same layer at the same site → no upgrade."""
        f1 = _make_finding(language="python", rule_id="md5-rule",
                           file="/repo/app.py", line=42, confidence=Confidence.LIKELY)
        f2 = _make_finding(language="python", rule_id="sha1-rule",
                           file="/repo/app.py", line=42, confidence=Confidence.LIKELY)
        result = promote_confirmed([f1, f2])
        # Both are AST (python) layer → same layer → no promotion
        assert all(f.confidence == Confidence.LIKELY for f in result), (
            f"Same-layer findings should stay LIKELY, got: {[f.confidence for f in result]}"
        )

    def test_no_promotion_when_different_files(self):
        """Findings from different layers but at different files → no promotion."""
        ast_finding = _make_finding(
            language="python", rule_id="md5-rule",
            file="/repo/app.py", line=10, confidence=Confidence.LIKELY,
        )
        config_finding = _make_finding(
            language="config", rule_id="config-plaintext-secret",
            file="/repo/config.yml", line=10, confidence=Confidence.POSSIBLE,
        )
        result = promote_confirmed([ast_finding, config_finding])
        assert all(f.confidence != Confidence.CONFIRMED for f in result), (
            "Different files should not be promoted"
        )

    def test_no_promotion_when_different_lines(self):
        """Findings at same file but different lines → no promotion."""
        ast_finding = _make_finding(
            language="python", rule_id="md5-rule",
            file="/repo/app.py", line=10, confidence=Confidence.LIKELY,
        )
        config_finding = _make_finding(
            language="config", rule_id="config-plaintext-secret",
            file="/repo/app.py", line=20, confidence=Confidence.POSSIBLE,
        )
        result = promote_confirmed([ast_finding, config_finding])
        assert all(f.confidence != Confidence.CONFIRMED for f in result), (
            "Different lines should not be promoted"
        )

    def test_entropy_and_ast_at_same_site_promotes(self):
        """AST (python) + entropy (python, but rule_id starts with 'entropy-')
        at same file+line → treated as different layers → CONFIRMED."""
        ast_finding = _make_finding(
            language="python", rule_id="md5-hardcoded-key",
            file="/repo/app.py", line=15, confidence=Confidence.LIKELY,
        )
        ent_finding = _make_finding(
            language="python", rule_id="entropy-secret-high-confidence",
            file="/repo/app.py", line=15, confidence=Confidence.LIKELY,
        )
        result = promote_confirmed([ast_finding, ent_finding])
        assert all(f.confidence == Confidence.CONFIRMED for f in result), (
            f"AST + entropy at same site should be CONFIRMED, got: {[f.confidence for f in result]}"
        )

    def test_single_finding_not_promoted(self):
        """A lone finding with no corroboration must stay at its original confidence."""
        f = _make_finding(language="python", rule_id="md5-rule",
                          file="/repo/app.py", line=5, confidence=Confidence.LIKELY)
        result = promote_confirmed([f])
        assert result[0].confidence == Confidence.LIKELY

    def test_does_not_touch_severity(self):
        """Confidence promotion must NEVER change severity or quantum_risk."""
        ast_f = _make_finding(language="python", file="/repo/app.py", line=7,
                              confidence=Confidence.LIKELY)
        cfg_f = _make_finding(language="config", file="/repo/app.py", line=7,
                              confidence=Confidence.POSSIBLE)
        original_severities = [f.severity for f in [ast_f, cfg_f]]
        original_qr = [f.quantum_risk for f in [ast_f, cfg_f]]
        result = promote_confirmed([ast_f, cfg_f])
        assert [f.severity for f in result] == original_severities, "severity must not change"
        assert [f.quantum_risk for f in result] == original_qr, "quantum_risk must not change"


# ===========================================================================
# Section 5 — Placeholder guard
# ===========================================================================

class TestIsPlaceholder:

    def test_changeme_is_placeholder(self):
        from scanner.regex_analyzer import _is_placeholder
        assert _is_placeholder("changeme")

    def test_env_interpolation_is_placeholder(self):
        from scanner.regex_analyzer import _is_placeholder
        assert _is_placeholder("${MY_SECRET}")

    def test_windows_env_is_placeholder(self):
        from scanner.regex_analyzer import _is_placeholder
        assert _is_placeholder("%MY_SECRET%")

    def test_template_syntax_is_placeholder(self):
        from scanner.regex_analyzer import _is_placeholder
        assert _is_placeholder("{{secret}}")

    def test_real_secret_is_not_placeholder(self):
        from scanner.regex_analyzer import _is_placeholder
        assert not _is_placeholder("test_sec_key_4xK9mNqRp2vBn7tLwS3cur3P4ssw0rdXq8mZ")


# ===========================================================================
# Section 6 — Models.py Confidence field
# ===========================================================================

class TestConfidenceDefault:

    def test_ast_finding_defaults_to_likely(self):
        """When no confidence is passed, Finding defaults to LIKELY (backwards compat)."""
        f = Finding(
            file="app.py", line=1, column=0,
            language="python", rule_id="test-rule",
            rule_name="Test", category="test", algorithm="MD5",
            severity=Severity.HIGH, quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="Test", recommendation="Fix it.",
        )
        assert f.confidence == Confidence.LIKELY

    def test_confidence_in_to_dict(self):
        """to_dict() must include 'confidence' key."""
        f = Finding(
            file="app.py", line=1, column=0,
            language="python", rule_id="test-rule",
            rule_name="Test", category="test", algorithm="MD5",
            severity=Severity.HIGH, quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="Test", recommendation="Fix it.",
        )
        d = f.to_dict()
        assert "confidence" in d
        assert d["confidence"] == "Likely"

    def test_existing_keys_in_to_dict_unchanged(self):
        """All original to_dict() keys must still be present."""
        f = Finding(
            file="app.py", line=1, column=0,
            language="python", rule_id="test-rule",
            rule_name="Test", category="test", algorithm="MD5",
            severity=Severity.HIGH, quantum_risk=QuantumRisk.CLASSICAL_RISK,
            message="Test", recommendation="Fix it.",
        )
        d = f.to_dict()
        for key in ("file", "line", "column", "language", "rule_id", "rule_name",
                    "category", "algorithm", "severity", "quantum_risk",
                    "message", "recommendation"):
            assert key in d, f"Missing existing key '{key}' from to_dict()"


if __name__ == "__main__":
    tests_run = 0
    tests_failed = 0
    for name, obj in sorted(globals().items()):
        if isinstance(obj, type) and name.startswith("Test"):
            inst = obj()
            for method_name in [m for m in dir(inst) if m.startswith("test_")]:
                tests_run += 1
                try:
                    getattr(inst, method_name)()
                    print(f"PASS {name}.{method_name}")
                except AssertionError as e:
                    tests_failed += 1
                    print(f"FAIL {name}.{method_name}: {e}")
                except Exception as e:
                    tests_failed += 1
                    print(f"ERROR {name}.{method_name}: {type(e).__name__}: {e}")
    print(f"\n{tests_run - tests_failed}/{tests_run} passed")
    sys.exit(1 if tests_failed else 0)
