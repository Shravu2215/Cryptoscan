"""
Test Suite: Confidence Consistency and Determinism.

Validates that confidence tier assignment is completely consistent and
deterministic across any repository, regardless of file name, variable name,
or scan ordering:
  - 8 synthetic Python secret findings with novel names/values all receive LIKELY
  - 4 synthetic config-layer findings with novel names/values all receive POSSIBLE
  - 1 negative control produces zero findings
  - Corroborated multi-layer findings receive CONFIRMED
  - auth.py, payment.py, and notifications.py fixture patterns are deterministic
"""
import pytest
from scanner.models import Confidence, Severity
from scanner.python_analyzer import PythonAnalyzer
from scanner.regex_analyzer import RegexAnalyzer
from scanner.entropy_analyzer import EntropyAnalyzer
from scanner.dedup import dedup
from scanner.confidence import promote_confirmed


def _scan_snippet(file_path: str, source: str):
    """Run all analyzers matching the file extension, dedup, and promote."""
    findings = []
    ext = file_path.split(".")[-1].lower()
    fn = file_path.split("/")[-1].lower()

    py = PythonAnalyzer()
    rx = RegexAnalyzer()
    ent = EntropyAnalyzer()

    if ext == "py":
        findings.extend(py.analyze(file_path, source))
        findings.extend(ent.analyze(file_path, source))
    elif ext in ("yml", "yaml", "json", "ini", "conf", "env") or fn.startswith(".env") or "dockerfile" in fn:
        findings.extend(rx.analyze(file_path, source))
        findings.extend(ent.analyze(file_path, source))

    deduped = dedup(findings)
    return promote_confirmed(deduped)


class TestSyntheticConsistency:
    """8 fresh, novel synthetic Python secret findings."""

    SYNTHETIC_PY_CASES = [
        ("auth_vault.py", 'API_TOKEN = "zK9#mQ2$vL8!pX4*nB7@jR1%tY5^wU9&"'),
        ("database_conn.py", 'DB_PASS = "vM3&kL9!qP5#xR8$nZ2%jT6*wY4@tC1^"'),
        ("signer.py", 'SIGNING_SECRET = "bN8*pX2@mQ4%vK6!tY1#jR9$wL3^zC7&"'),
        ("hooks.py", 'WEBHOOK_KEY = "pX4%mQ8#vL2!kR6*nB1@tY9$wZ3^jC5&"'),
        ("oauth_client.py", 'OAUTH_CLIENT_SECRET = "jR7!vK1@mQ9#pX3%tY5*nB2$wL8^zC4&"'),
        ("crypto_util.py", 'ENCRYPTION_KEY = "tY3#nB8*vL4%mQ1!pX6@wZ9$jC2^kR5&"'),
        ("session.py", 'PRIVATE_TOKEN = "wL9^pX5!mQ2#vK8*tY4@nB1%zC6$jR3&"'),
        ("admin.py", 'MASTER_PASSWORD = "zC1$tY7@nB3!mQ8#pX2%vK5*wL9^jR4&"'),
    ]

    def test_eight_synthetic_py_secrets_get_identical_likely_tier(self):
        """All 8 novel Python secret findings must receive the exact same LIKELY confidence tier."""
        results = []
        for filename, code in self.SYNTHETIC_PY_CASES:
            findings = _scan_snippet(f"/app/{filename}", code)
            assert len(findings) == 1, f"Expected exactly 1 finding for {filename}, got {len(findings)}"
            results.append((filename, findings[0].confidence))

        # Assert every single one is LIKELY
        for filename, conf in results:
            assert conf == Confidence.LIKELY, f"{filename} expected LIKELY, got {conf}"

        # Assert all 8 are strictly identical to each other
        tiers = set(conf for _, conf in results)
        assert len(tiers) == 1, f"Expected all 8 findings to have identical tier, got: {tiers}"

    def test_four_synthetic_config_findings_get_possible_tier(self):
        """4 novel config-layer secret findings must consistently land on POSSIBLE."""
        configs = [
            ("Dockerfile", "ENV INGEST_AUTH_TOKEN=super_secret_ingest_token_val1234"),
            ("vault.yml", 'vault_credential_token: "super_secret_vault_token_val5678"'),
            (".env.service", "GATEWAY_SIGNING_KEY=super_secret_gateway_key_val9012"),
            ("config.json", '{"internal_service_api_key": "super_secret_internal_key_val3456"}'),
        ]
        for filename, content in configs:
            # Use regex analyzer directly to test config-layer tier
            rx = RegexAnalyzer()
            findings = rx.analyze(f"/app/{filename}", content)
            assert len(findings) >= 1, f"Expected config finding for {filename}"
            for f in findings:
                assert f.confidence == Confidence.POSSIBLE, f"{filename} expected POSSIBLE, got {f.confidence}"

    def test_negative_control_produces_zero_findings(self):
        """Clean code with no crypto weaknesses or secrets must produce zero findings."""
        clean_code = """
def calculate_metrics(values):
    total = sum(values)
    avg = total / len(values) if values else 0
    return {"total": total, "average": avg}

def format_greeting(user_name):
    return f"Welcome back, {user_name}!"
"""
        findings = _scan_snippet("/app/helpers.py", clean_code)
        assert len(findings) == 0, f"Expected 0 findings for clean file, got: {findings}"

    def test_corroborated_multi_layer_finding_receives_confirmed(self):
        """When AST and Entropy layers independently flag a secret on the same line, it is CONFIRMED."""
        corroborated_code = """from Crypto.Cipher import AES
KEY = b"zK9#mQ2$vL8!pX4*nB7@jR1%tY5^wU9&"; cipher = AES.new(KEY, AES.MODE_ECB)
"""
        findings = _scan_snippet("/app/notifications.py", corroborated_code)
        secret_findings = [f for f in findings if f.category == "hardcoded-secret"]
        assert len(secret_findings) == 1, f"Expected 1 merged secret finding, got: {secret_findings}"
        assert secret_findings[0].confidence == Confidence.CONFIRMED
        assert secret_findings[0].severity == Severity.CRITICAL

    def test_auth_payment_deterministic_behavior(self):
        """auth.py (low entropy, name hint) vs payment.py (high entropy, name hint) are deterministic."""
        auth_src = 'auth_token = "hunter2password"\n'
        payment_src = 'stripe_key = "test_sec_key_112233445566778899aabbccddee"\n'

        f_auth = _scan_snippet("/app/auth.py", auth_src)
        f_pay = _scan_snippet("/app/payment.py", payment_src)

        assert len(f_auth) == 1
        assert f_auth[0].confidence == Confidence.POSSIBLE  # Name hint only, entropy < 4.0
        assert f_auth[0].rule_id == "entropy-secret-name-hint-only"

        assert len(f_pay) == 1
        assert f_pay[0].confidence == Confidence.LIKELY    # Name hint + high entropy >= 4.0
        assert f_pay[0].rule_id == "entropy-secret-high-confidence"
