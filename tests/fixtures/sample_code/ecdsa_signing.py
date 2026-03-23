"""Sample ECDSA signing for scanner testing."""

from cryptography.hazmat.primitives.asymmetric import ec


def sign_message(private_key, message: bytes) -> bytes:
    # ECDSA signature using P-256 curve
    signature = private_key.sign(
        message,
        ec.ECDSA(None),
    )
    return signature
