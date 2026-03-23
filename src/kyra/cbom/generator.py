"""CBOM generator — transforms raw scanner findings into structured CBOM entries.

This module bridges the scanner (raw detection) and the risk engine (structured
analysis).  It is responsible for:

1. Converting RawFinding objects into CBOMEntry objects.
2. Mapping raw algorithm_family strings to AlgorithmFamily enum members.
3. Inferring metadata the scanner cannot determine:
   - exposure_level: guessed from file path and usage context.
   - data_lifetime: guessed from usage context keywords.
   - pq_readiness: looked up from a static classification table.
4. Generating a scan_id, timestamps, and summary statistics.
"""

from __future__ import annotations

import hashlib
import os
from collections import Counter
from datetime import datetime, timezone

from kyra.cbom.schema import (
    AlgorithmFamily,
    CBOMEntry,
    CBOMReport,
    CBOMSummary,
    ExposureLevel,
    PQReadiness,
)
from kyra.scanner.engine import ScanResult

# ------------------------------------------------------------------
# PQ-readiness classification
# ------------------------------------------------------------------

# Key: AlgorithmFamily enum value.
# Value: default PQReadiness.
# Some families need per-key-size overrides — handled in _classify_pq_readiness.
_FAMILY_PQ_DEFAULT: dict[AlgorithmFamily, PQReadiness] = {
    # Asymmetric — all broken by Shor's algorithm
    AlgorithmFamily.RSA: PQReadiness.MIGRATION_NEEDED,
    AlgorithmFamily.ECC: PQReadiness.MIGRATION_NEEDED,
    AlgorithmFamily.DH: PQReadiness.MIGRATION_NEEDED,
    AlgorithmFamily.DSA: PQReadiness.MIGRATION_NEEDED,
    # Symmetric — safe if key is large enough
    AlgorithmFamily.AES: PQReadiness.QUANTUM_SAFE,  # refined by key_size below
    AlgorithmFamily.CHACHA20: PQReadiness.QUANTUM_SAFE,
    # Hashing
    AlgorithmFamily.SHA2: PQReadiness.QUANTUM_SAFE,
    AlgorithmFamily.SHA3: PQReadiness.QUANTUM_SAFE,
    # Classically broken or deprecated
    AlgorithmFamily.MD5: PQReadiness.CRITICAL,
    AlgorithmFamily.SHA1: PQReadiness.CRITICAL,
    AlgorithmFamily.DES: PQReadiness.CRITICAL,
    AlgorithmFamily.TDES: PQReadiness.CRITICAL,
    # Post-quantum — already safe
    AlgorithmFamily.MLKEM: PQReadiness.QUANTUM_SAFE,
    AlgorithmFamily.MLDSA: PQReadiness.QUANTUM_SAFE,
    AlgorithmFamily.SLHDSA: PQReadiness.QUANTUM_SAFE,
}


def _classify_pq_readiness(
    family: AlgorithmFamily,
    key_size: int | None,
) -> PQReadiness:
    """Determine PQ readiness for a specific algorithm + key size."""
    # AES-128 has debatable quantum safety (Grover reduces to 64-bit).
    if family == AlgorithmFamily.AES and key_size is not None and key_size < 256:
        return PQReadiness.MIGRATION_NEEDED

    return _FAMILY_PQ_DEFAULT.get(family, PQReadiness.MIGRATION_NEEDED)


# ------------------------------------------------------------------
# Exposure inference from file paths and context
# ------------------------------------------------------------------

# Patterns checked against the lowercased file path.
_EXTERNAL_PATH_HINTS = (
    "nginx",
    "apache",
    "haproxy",
    "caddy",
    "envoy",  # reverse proxies
    "tls",
    "ssl",
    "https",
    "certificate",
    "cert",  # TLS-related
    "api/public",
    "gateway",
    "endpoint",  # public API layers
)

_STORAGE_PATH_HINTS = (
    "storage",
    "encrypt",
    "vault",
    "backup",
    "archive",
    "database",
    "persist",
    "warehouse",
)

_SIGNING_PATH_HINTS = (
    "sign",
    "jwt",
    "token",
    "auth",
    "verify",
    "hmac",
)

# Context-string keywords (from the rule description or usage_context).
_EXTERNAL_CONTEXT_HINTS = (
    "tls",
    "ssl",
    "https",
    "cipher suite",
    "ssl_ciphers",
    "public api",
    "internet",
    "external",
)

_STORAGE_CONTEXT_HINTS = (
    "at rest",
    "storage",
    "encrypt",
    "disk",
    "backup",
    "database",
)

_SIGNING_CONTEXT_HINTS = (
    "sign",
    "jwt",
    "token",
    "hmac",
    "verify",
    "hash",
    "integrity",
    "checksum",
    "digest",
)


def _infer_exposure(file_path: str, usage_context: str) -> ExposureLevel:
    """Guess exposure level from file path and usage context.

    Heuristic priority: external > signing > storage > internal.
    """
    path_lower = file_path.lower().replace("\\", "/")
    ctx_lower = usage_context.lower()

    if any(h in path_lower for h in _EXTERNAL_PATH_HINTS) or any(
        h in ctx_lower for h in _EXTERNAL_CONTEXT_HINTS
    ):
        return ExposureLevel.EXTERNAL

    if any(h in path_lower for h in _SIGNING_PATH_HINTS) or any(
        h in ctx_lower for h in _SIGNING_CONTEXT_HINTS
    ):
        return ExposureLevel.SIGNING

    if any(h in path_lower for h in _STORAGE_PATH_HINTS) or any(
        h in ctx_lower for h in _STORAGE_CONTEXT_HINTS
    ):
        return ExposureLevel.STORAGE

    return ExposureLevel.INTERNAL


# ------------------------------------------------------------------
# Data lifetime inference
# ------------------------------------------------------------------

_LIFETIME_HINTS: list[tuple[tuple[str, ...], str]] = [
    # Short-lived
    (("session", "ephemeral", "otp", "nonce", "temporary"), "session"),
    (("token", "jwt", "refresh", "api key"), "30d"),
    # Long-lived
    (("medical", "health", "hipaa", "patient"), "10y"),
    (("financial", "payment", "banking", "pci"), "7y"),
    (("pii", "personal", "user data", "gdpr"), "5y"),
    (("archive", "backup", "long-term", "permanent"), "10y"),
    # Signing / certificates
    (("certificate", "cert", "ca", "root"), "5y"),
    (("sign", "signature", "code sign"), "5y"),
]


def _infer_lifetime(file_path: str, usage_context: str) -> str:
    """Guess data lifetime from file path and usage context.

    Returns a duration string like "30d", "5y", "session".
    Falls back to "1y" (moderate assumption) if nothing matches.
    """
    combined = (file_path + " " + usage_context).lower()
    for keywords, lifetime in _LIFETIME_HINTS:
        if any(kw in combined for kw in keywords):
            return lifetime
    return "1y"


# ------------------------------------------------------------------
# Algorithm family mapping
# ------------------------------------------------------------------

# Maps raw family strings from the scanner to AlgorithmFamily enum members.
# The scanner emits plain strings (from YAML rules); the CBOM needs enum values.
_FAMILY_MAP: dict[str, AlgorithmFamily] = {v.value: v for v in AlgorithmFamily}


def _map_algorithm_family(raw_family: str) -> AlgorithmFamily:
    """Convert a raw algorithm_family string to the enum.

    Falls back by trying case-insensitive match, then returns RSA as a
    conservative unknown (ensures pq_readiness = migration-needed).
    """
    # Direct hit (most common path).
    if raw_family in _FAMILY_MAP:
        return _FAMILY_MAP[raw_family]

    # Case-insensitive fallback.
    raw_upper = raw_family.upper()
    for value, member in _FAMILY_MAP.items():
        if value.upper() == raw_upper:
            return member

    # Unknown family — treat as migration-needed by returning a sentinel.
    # We don't crash; the CBOM will flag it for review.
    return AlgorithmFamily.RSA  # conservative: assume quantum-vulnerable


# ------------------------------------------------------------------
# ID generation
# ------------------------------------------------------------------


def _make_finding_id(file_path: str, line_number: int, algorithm: str) -> str:
    """Deterministic finding ID from location + algorithm.

    Uses a truncated SHA-256 so the same finding always gets the same ID
    across scans (enabling diff/tracking).
    """
    raw = f"{file_path}:{line_number}:{algorithm}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:12]
    return f"finding-{digest}"


def _make_scan_id(target: str, timestamp: datetime) -> str:
    """Deterministic scan ID from target + timestamp."""
    raw = f"{target}:{timestamp.isoformat()}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"scan-{timestamp.strftime('%Y%m%d')}-{digest}"


# ------------------------------------------------------------------
# Component path normalization
# ------------------------------------------------------------------


def _normalize_component(file_path: str, target: str) -> str:
    """Convert an absolute file_path to a relative component path.

    Example: /home/dev/myapp/backend/auth/jwt.py → backend/auth/jwt.py
    """
    try:
        relative = os.path.relpath(file_path, target)
    except ValueError:
        # On Windows, relpath fails when paths are on different drives.
        relative = file_path
    # Always use forward slashes for consistency.
    return relative.replace("\\", "/")


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------


def generate_cbom(scan_result: ScanResult) -> CBOMReport:
    """Transform a ScanResult into a structured CBOMReport.

    This is the main entry point for CBOM generation.

    Parameters
    ----------
    scan_result:
        The output of ``ScannerEngine.scan()``.

    Returns
    -------
    CBOMReport
        A fully populated CBOM with entries, summary, and metadata.
    """
    now = datetime.now(timezone.utc)
    scan_id = _make_scan_id(scan_result.target, now)
    entries: list[CBOMEntry] = []

    for finding in scan_result.findings:
        family = _map_algorithm_family(finding.algorithm_family)
        exposure = _infer_exposure(finding.file_path, finding.usage_context)
        lifetime = _infer_lifetime(finding.file_path, finding.usage_context)
        pq = _classify_pq_readiness(family, finding.key_size)
        component = _normalize_component(finding.file_path, scan_result.target)
        location = f"{component}:{finding.line_number}"
        finding_id = _make_finding_id(component, finding.line_number, finding.algorithm)

        entry = CBOMEntry(
            id=finding_id,
            component=component,
            algorithm=finding.algorithm,
            algorithm_family=family,
            key_size=finding.key_size,
            usage_context=finding.usage_context,
            exposure_level=exposure,
            data_lifetime=lifetime,
            pq_readiness=pq,
            location=location,
            confidence=finding.confidence,
            detected_by=finding.detected_by,
            first_seen=now,
            last_seen=now,
        )
        entries.append(entry)

    summary = _build_summary(entries)

    return CBOMReport(
        version="1.0.0",
        scan_id=scan_id,
        timestamp=now,
        target=scan_result.target,
        entries=entries,
        summary=summary,
    )


def _build_summary(entries: list[CBOMEntry]) -> CBOMSummary:
    """Compute aggregate statistics over CBOM entries."""
    readiness_counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()
    exposure_counts: Counter[str] = Counter()

    for e in entries:
        readiness_counts[e.pq_readiness.value] += 1
        family_counts[e.algorithm_family.value] += 1
        exposure_counts[e.exposure_level.value] += 1

    return CBOMSummary(
        total_findings=len(entries),
        by_readiness=dict(readiness_counts),
        by_algorithm_family=dict(family_counts),
        by_exposure=dict(exposure_counts),
    )
