"""Sample RSA key generation for scanner testing."""

from Crypto.PublicKey import RSA


def generate_rsa_key():
    key = RSA.generate(2048)
    return key.export_key()


def generate_large_rsa_key():
    key = RSA.generate(4096)
    return key.export_key()
