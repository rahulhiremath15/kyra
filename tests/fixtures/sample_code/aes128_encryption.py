"""Sample AES-128 encryption for scanner testing."""

from Crypto.Cipher import AES


def encrypt_data(key: bytes, plaintext: bytes) -> bytes:
    # AES-128 key (16 bytes)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext
