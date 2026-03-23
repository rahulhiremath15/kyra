"""HNDL Risk scoring factors and constants."""

from __future__ import annotations

from kyra.cbom.schema import AlgorithmFamily

# Algorithm risk scores: probability that a CRQC breaks this algorithm.
# 0.0 = quantum-safe, 1.0 = already broken or trivially broken by quantum.
ALGORITHM_RISK: dict[str, float] = {
    # Already broken classically
    "MD5": 1.0,
    "SHA-1": 1.0,
    "DES": 1.0,
    "3DES": 0.9,
    # Quantum-vulnerable asymmetric
    "RSA-1024": 1.0,
    "RSA-2048": 0.9,
    "RSA-3072": 0.88,
    "RSA-4096": 0.85,
    "ECDSA-P256": 0.9,
    "ECDSA-P384": 0.85,
    "ECDH-P256": 0.9,
    "ECDH-P384": 0.85,
    "DH-2048": 0.9,
    "DH-4096": 0.85,
    "DSA-2048": 0.9,
    # Symmetric — Grover's halves effective key length
    "AES-128": 0.3,
    "AES-192": 0.15,
    "AES-256": 0.05,
    "ChaCha20": 0.1,
    # Hashing — Grover's on collision resistance
    "SHA-256": 0.1,
    "SHA-384": 0.05,
    "SHA-512": 0.05,
    "SHA-3": 0.05,
    # Post-quantum (NIST standards)
    "ML-KEM-512": 0.05,
    "ML-KEM-768": 0.02,
    "ML-KEM-1024": 0.02,
    "ML-DSA-44": 0.05,
    "ML-DSA-65": 0.02,
    "ML-DSA-87": 0.02,
    "SLH-DSA": 0.02,
}

# Default risk for unknown algorithms
DEFAULT_ALGORITHM_RISK = 0.5


def get_algorithm_risk(algorithm: str, family: AlgorithmFamily) -> float:
    """Look up algorithm risk score. Falls back to family-level defaults."""
    if algorithm in ALGORITHM_RISK:
        return ALGORITHM_RISK[algorithm]

    # Family-level fallbacks
    family_defaults: dict[str, float] = {
        AlgorithmFamily.RSA: 0.9,
        AlgorithmFamily.ECC: 0.9,
        AlgorithmFamily.DH: 0.9,
        AlgorithmFamily.DSA: 0.9,
        AlgorithmFamily.AES: 0.15,
        AlgorithmFamily.SHA2: 0.1,
        AlgorithmFamily.SHA3: 0.05,
        AlgorithmFamily.MD5: 1.0,
        AlgorithmFamily.SHA1: 1.0,
        AlgorithmFamily.DES: 1.0,
        AlgorithmFamily.TDES: 0.9,
        AlgorithmFamily.CHACHA20: 0.1,
        AlgorithmFamily.MLKEM: 0.02,
        AlgorithmFamily.MLDSA: 0.02,
        AlgorithmFamily.SLHDSA: 0.02,
    }

    return family_defaults.get(family, DEFAULT_ALGORITHM_RISK)


def parse_lifetime_to_factor(lifetime: str) -> float:
    """Convert a data lifetime string to a risk factor (0.0–1.0).

    Examples: "session", "30d", "1y", "7y", "permanent"
    """
    lifetime = lifetime.lower().strip()

    if lifetime in ("session", "ephemeral", "temporary"):
        return 0.1
    if lifetime == "permanent":
        return 1.0

    # Parse numeric durations
    try:
        if lifetime.endswith("d"):
            days = int(lifetime[:-1])
            if days < 30:
                return 0.2
            if days < 365:
                return 0.4
            return 0.7
        if lifetime.endswith("y"):
            years = int(lifetime[:-1])
            if years <= 1:
                return 0.4
            if years <= 5:
                return 0.7
            return 0.9
    except ValueError:
        pass

    return 0.5  # Unknown lifetime — moderate risk


EXPOSURE_FACTORS: dict[str, float] = {
    "external": 0.9,
    "transit": 0.7,
    "internal": 0.3,
    "storage": 0.4,
    "signing": 0.5,
}

DEFAULT_EXPOSURE_FACTOR = 0.5


def get_exposure_factor(exposure: str) -> float:
    """Look up exposure risk factor."""
    return EXPOSURE_FACTORS.get(exposure.lower(), DEFAULT_EXPOSURE_FACTOR)
