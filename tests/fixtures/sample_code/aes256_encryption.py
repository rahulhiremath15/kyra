"""Sample AES-256 encryption for scanner testing."""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_at_rest(plaintext: bytes, key: bytes) -> bytes:
    # Using AES-256-GCM for data at rest
    aesgcm = AESGCM(key)
    nonce = b"\x00" * 12
    return aesgcm.encrypt(nonce, plaintext, None)
