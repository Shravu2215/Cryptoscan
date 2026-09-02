import rsa
import argon2

def generate_legacy_key():
    # Undersized 1024-bit RSA key
    (pubkey, privkey) = rsa.newkeys(1024)
    return pubkey, privkey

def hash_token(token: str) -> str:
    # Modern secure Argon2id password hasher
    ph = argon2.PasswordHasher()
    return ph.hash(token)
