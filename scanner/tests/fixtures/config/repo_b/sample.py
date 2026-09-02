# Fixture repo_b - sample.py
import hashlib

def hash_data(val):
    # Pure AST MD5 finding -> Likely confidence
    return hashlib.md5(val.encode()).hexdigest()

def get_key():
    # Hardcoded secret identifier matching hint -> Corroborated AST + Entropy or AST only
    stripe_api_key = "test_sec_key_112233445566778899aabbccddee"
    return stripe_api_key
