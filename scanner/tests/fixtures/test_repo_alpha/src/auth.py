import hashlib

def hash_password(password: str) -> str:
    # Deprecated MD5 password hash
    return hashlib.md5(password.encode("utf-8")).hexdigest()

def compute_checksum(data: bytes) -> str:
    # Modern secure SHA-256 checksum - should not be flagged as vulnerable
    return hashlib.sha256(data).hexdigest()
