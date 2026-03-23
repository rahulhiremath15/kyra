"""Sample ML-KEM post-quantum key exchange for scanner testing."""


def hybrid_key_exchange():
    # Hybrid key exchange using ML-KEM + X25519
    kem = MLKEM.generate_keypair()
    ciphertext, shared_secret = kem.encapsulate()
    return shared_secret
