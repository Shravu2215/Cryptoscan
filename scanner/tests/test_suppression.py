"""
Unit tests for Allow-list / Finding Suppression (.cryptoscan-ignore).
"""
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.suppression import load_suppressions, apply_suppressions
from scanner.models import Finding, Severity, QuantumRisk, Confidence


class TestSuppression:
    def test_load_and_apply_suppressions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ignore_path = os.path.join(temp_dir, ".cryptoscan-ignore")
            with open(ignore_path, "w", encoding="utf-8") as f:
                f.write("""# This is a comment
# Suppress all md5 findings in legacy_hasher.py
md5-weak-password-hash|src/legacy_hasher.py

# Suppress single line in auth.py
aes-ecb-mode|src/auth.py|42
""")

            suppressions = load_suppressions(temp_dir)
            assert ("md5-weak-password-hash", "src/legacy_hasher.py") in suppressions
            assert ("aes-ecb-mode", "src/auth.py", 42) in suppressions

            f1 = Finding(
                file=os.path.join(temp_dir, "src/legacy_hasher.py"),
                line=10,
                column=0,
                language="python",
                rule_id="md5-weak-password-hash",
                rule_name="MD5 hash",
                category="hash",
                algorithm="MD5",
                severity=Severity.HIGH,
                quantum_risk=QuantumRisk.CLASSICAL_RISK,
                message="MD5 in legacy file",
                recommendation="Replace",
            )
            f2 = Finding(
                file=os.path.join(temp_dir, "src/auth.py"),
                line=42,
                column=0,
                language="python",
                rule_id="aes-ecb-mode",
                rule_name="AES ECB",
                category="symmetric-cipher",
                algorithm="AES",
                severity=Severity.HIGH,
                quantum_risk=QuantumRisk.CLASSICAL_RISK,
                message="AES ECB at line 42",
                recommendation="Use GCM",
            )
            f3 = Finding(
                file=os.path.join(temp_dir, "src/auth.py"),
                line=88,
                column=0,
                language="python",
                rule_id="aes-ecb-mode",
                rule_name="AES ECB",
                category="symmetric-cipher",
                algorithm="AES",
                severity=Severity.HIGH,
                quantum_risk=QuantumRisk.CLASSICAL_RISK,
                message="AES ECB at line 88",
                recommendation="Use GCM",
            )
            f4 = Finding(
                file=os.path.join(temp_dir, "src/payment.py"),
                line=15,
                column=0,
                language="python",
                rule_id="rsa-small-key",
                rule_name="RSA Small Key",
                category="asymmetric",
                algorithm="RSA",
                severity=Severity.HIGH,
                quantum_risk=QuantumRisk.QUANTUM_BROKEN,
                message="RSA finding",
                recommendation="Upgrade",
            )

            all_findings = [f1, f2, f3, f4]
            kept, suppressed_count = apply_suppressions(all_findings, suppressions, repo_path=temp_dir)

            assert suppressed_count == 2
            assert len(kept) == 2
            assert f3 in kept
            assert f4 in kept
            assert f1 not in kept
            assert f2 not in kept
