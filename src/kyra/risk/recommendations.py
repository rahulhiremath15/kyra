"""Remediation recommendations for PQC migration.

Maps algorithm families to concrete upgrade paths based on NIST FIPS 203/204/205
and NSA CNSA 2.0 guidance.  Separating this from the scoring engine keeps the
risk logic focused on math while this module owns the human-readable advice.
"""

from __future__ import annotations

from kyra.cbom.schema import AlgorithmFamily, CBOMEntry

# ------------------------------------------------------------------
# Migration path table
# ------------------------------------------------------------------

_MIGRATION_TABLE: list[tuple[AlgorithmFamily, str]] = [
    (
        AlgorithmFamily.RSA,
        "Migrate to ML-KEM (FIPS 203) for key exchange or ML-DSA (FIPS 204) for signing",
    ),
    (
        AlgorithmFamily.ECC,
        "Migrate to ML-KEM (FIPS 203) for key exchange or ML-DSA (FIPS 204) for signing",
    ),
    (AlgorithmFamily.DH, "Migrate to ML-KEM (FIPS 203) for key exchange"),
    (AlgorithmFamily.DSA, "Migrate to ML-DSA (FIPS 204) for signing"),
    (AlgorithmFamily.SHA1, "Replace with SHA-256 immediately (classically broken)"),
    (AlgorithmFamily.MD5, "Replace with SHA-256 immediately (classically broken)"),
    (AlgorithmFamily.DES, "Replace with AES-256-GCM immediately (classically broken)"),
    (AlgorithmFamily.TDES, "Replace with AES-256-GCM (deprecated)"),
]

# Families that are already quantum-safe — no migration needed.
_SAFE_FAMILIES: set[AlgorithmFamily] = {
    AlgorithmFamily.MLKEM,
    AlgorithmFamily.MLDSA,
    AlgorithmFamily.SLHDSA,
    AlgorithmFamily.SHA2,
    AlgorithmFamily.SHA3,
    AlgorithmFamily.CHACHA20,
}

# Urgency labels keyed by RiskLevel value.
URGENCY_LABELS: dict[str, str] = {
    "LOW": "low priority",
    "MEDIUM": "plan migration",
    "HIGH": "migrate within 12 months",
    "CRITICAL": "immediate action required",
}


def get_recommendation(entry: CBOMEntry) -> str:
    """Return a migration recommendation string for a CBOM entry.

    Takes key_size into account for AES (128 needs upgrade, 256 is safe).
    """
    family = entry.algorithm_family

    # AES special case: depends on key size.
    if family == AlgorithmFamily.AES:
        if entry.key_size is not None and entry.key_size < 256:
            return "Upgrade to AES-256 (Grover's algorithm halves effective key length)"
        return "No action needed (quantum-safe)"

    # Already quantum-safe.
    if family in _SAFE_FAMILIES:
        return "No action needed (quantum-safe)"

    # Look up in migration table.
    for table_family, text in _MIGRATION_TABLE:
        if family == table_family:
            return text

    return "Review algorithm for PQC migration"


def format_with_urgency(base: str, risk_level: str) -> str:
    """Append urgency suffix to a recommendation string.

    If the base recommendation already says "No action needed", it is
    returned unchanged — no point attaching urgency to a safe finding.
    """
    if "No action needed" in base:
        return base
    urgency = URGENCY_LABELS.get(risk_level, "review recommended")
    return f"{base} — {urgency}"
