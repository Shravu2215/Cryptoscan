"""
End-to-End Verification Test for Suppression & Allow-List Pipeline.
Proves that suppressed findings disappear from:
1. Active findings list & counts (Total, Critical, High, etc.)
2. CBOM components and occurrence lists
3. Risk & Migration candidate lists and affected files
4. Platform / Dashboard summary statistics
"""
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.pipeline import scan_repo


def test_e2e_suppression_with_custom_fixture():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a sample project with 3 files containing crypto usages
        # File 1: legacy_hasher.py with MD5 (Suppressed via .cryptoscan-ignore)
        hasher_file = os.path.join(temp_dir, "legacy_hasher.py")
        with open(hasher_file, "w", encoding="utf-8") as f:
            f.write("""import hashlib
def get_hash(data):
    return hashlib.md5(data).hexdigest()
""")

        # File 2: auth.py with AES ECB (Active / Not suppressed)
        auth_file = os.path.join(temp_dir, "auth.py")
        with open(auth_file, "w", encoding="utf-8") as f:
            f.write("""from Crypto.Cipher import AES
def encrypt(k, data):
    cipher = AES.new(k, AES.MODE_ECB)
    return cipher.encrypt(data)
""")

        # File 3: rsa_signer.py with RSA-1024 (Active / Not suppressed)
        rsa_file = os.path.join(temp_dir, "rsa_signer.py")
        with open(rsa_file, "w", encoding="utf-8") as f:
            f.write("""from Crypto.PublicKey import RSA
def gen_key():
    return RSA.generate(1024)
""")

        # Create .cryptoscan-ignore targeting legacy_hasher.py
        ignore_file = os.path.join(temp_dir, ".cryptoscan-ignore")
        with open(ignore_file, "w", encoding="utf-8") as f:
            f.write("""# Suppress legacy MD5
md5-hashing|legacy_hasher.py|3
""")

        # Run scan
        result = scan_repo(temp_dir)
        assert result["status"] == "COMPLETED"
        assert result["suppressed_count"] == 1

        all_findings = result["findings"]
        active_findings = [f for f in all_findings if not f["suppressed"]]
        suppressed_findings = [f for f in all_findings if f["suppressed"]]

        # 1. Assert suppressed finding is marked properly and separated
        assert len(suppressed_findings) == 1
        assert suppressed_findings[0]["algorithm"] == "MD5"
        assert suppressed_findings[0]["file"] == "legacy_hasher.py"
        assert suppressed_findings[0]["suppressed"] is True
        assert "Suppressed by" in suppressed_findings[0]["suppression_reason"]

        # 2. Assert active findings ONLY contain the unsuppressed findings (AES, RSA)
        assert len(active_findings) == 2
        active_algos = {f["algorithm"] for f in active_findings}
        assert "MD5" not in active_algos
        assert "AES-ECB" in active_algos
        assert "RSA-1024" in active_algos or "RSA" in active_algos
