"""
Unit tests for Allow-list / Finding Suppression (.cryptoscan-ignore).
"""
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.suppression import load_suppressions, apply_suppressions, _normalize_rel_path
from scanner.models import Finding, Severity, QuantumRisk, Confidence
from scanner.pipeline import scan_repo


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

    def test_windows_backslashes_and_case_normalization(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ignore_path = os.path.join(temp_dir, ".cryptoscan-ignore")
            with open(ignore_path, "w", encoding="utf-8") as f:
                f.write("""# POSIX path in ignore file
CRYPTO-RULE-MD5-BROKEN|src/crypto/hasher.py|12
# Windows backslash path in ignore file
CRYPTO-RULE-DES-WEAK|src\\legacy\\des.py
""")

            suppressions = load_suppressions(temp_dir)

            # Finding generated with Windows backslashes
            f1 = Finding(
                file=os.path.join(temp_dir, "src", "crypto", "hasher.py"),
                line=12,
                column=0,
                language="python",
                rule_id="CRYPTO-RULE-MD5-BROKEN",
                rule_name="MD5 Broken",
                category="hash",
                algorithm="MD5",
                severity=Severity.CRITICAL,
                quantum_risk=QuantumRisk.CLASSICAL_RISK,
                message="MD5 usage",
                recommendation="Use SHA256",
            )

            # Finding generated with POSIX slashes
            f2 = Finding(
                file=f"{temp_dir}/src/legacy/des.py",
                line=5,
                column=0,
                language="python",
                rule_id="CRYPTO-RULE-DES-WEAK",
                rule_name="DES Weak",
                category="symmetric-cipher",
                algorithm="DES",
                severity=Severity.HIGH,
                quantum_risk=QuantumRisk.CLASSICAL_RISK,
                message="DES usage",
                recommendation="Use AES",
            )

            # Unsuppressed finding
            f3 = Finding(
                file=os.path.join(temp_dir, "src", "crypto", "safe.py"),
                line=20,
                column=0,
                language="python",
                rule_id="CRYPTO-ASSET-AES-GCM",
                rule_name="AES GCM",
                category="symmetric-cipher",
                algorithm="AES-GCM",
                severity=Severity.INFO,
                quantum_risk=QuantumRisk.SAFE,
                message="AES GCM usage",
                recommendation="Compliant",
            )

            kept, supp_count = apply_suppressions([f1, f2, f3], suppressions, repo_path=temp_dir)
            assert supp_count == 2
            assert len(kept) == 1
            assert kept[0] == f3
            assert f1.suppressed is True
            assert f2.suppressed is True
            assert f3.suppressed is False

    def test_pipeline_scan_repo_with_ignore_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src_dir = os.path.join(temp_dir, "src")
            os.makedirs(src_dir, exist_ok=True)

            code_file = os.path.join(src_dir, "app.py")
            with open(code_file, "w", encoding="utf-8") as f:
                f.write("""import hashlib
# line 2: md5
h = hashlib.md5(b'test').hexdigest()
# line 4: sha256
s = hashlib.sha256(b'test').hexdigest()
""")

            ignore_file = os.path.join(temp_dir, ".cryptoscan-ignore")
            with open(ignore_file, "w", encoding="utf-8") as f:
                f.write("md5-hashing|src/app.py|3\n")

            result = scan_repo(temp_dir)
            assert result["status"] == "COMPLETED"
            findings = result["findings"]
            
            # Find MD5 finding
            md5_f = [f for f in findings if f["algorithm"] == "MD5"]
            if md5_f:
                assert md5_f[0]["suppressed"] is True
                assert result["suppressed_count"] >= 1
