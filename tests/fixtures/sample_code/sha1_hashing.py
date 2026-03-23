"""Sample SHA-1 hashing for scanner testing."""

import hashlib


def hash_password(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()


def verify_checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()
