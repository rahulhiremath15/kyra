"""Convert TLS scan results into CBOM-compatible RawFinding objects.

This bridges the network scanner to the existing CBOM/risk pipeline so that
TLS endpoint findings receive the same risk scoring and recommendations as
locally scanned code.
"""

from __future__ import annotations

from kyra.network.tls_scanner import TLSScanResult
from kyra.scanner.detectors.base import RawFinding

# Maps public key algorithm names (from the TLS scanner) to CBOM algorithm families.
_PK_FAMILY_MAP: dict[str, str] = {
    "RSA": "RSA",
    "ECC": "ECC",
    "DSA": "DSA",
    "Ed25519": "ECC",
    "Ed448": "ECC",
}


def tls_result_to_findings(result: TLSScanResult) -> list[RawFinding]:
    """Convert a TLSScanResult into a list of RawFinding objects.

    Produces one finding for the certificate's public key algorithm (the
    primary quantum-vulnerable component of a TLS connection).
    """
    if result.error is not None:
        return []

    findings: list[RawFinding] = []

    # Certificate public key algorithm — this is the main PQ-relevant finding.
    if result.cert_public_key_algorithm is not None:
        family = _PK_FAMILY_MAP.get(
            result.cert_public_key_algorithm, result.cert_public_key_algorithm
        )
        key_size = result.cert_public_key_size
        algorithm = f"{family}-{key_size}" if key_size else family

        findings.append(
            RawFinding(
                file_path=f"tls://{result.host}:{result.port}",
                line_number=0,
                algorithm=algorithm,
                algorithm_family=family,
                key_size=key_size,
                usage_context=f"TLS certificate public key ({result.tls_version})",
                confidence=1.0,
                detected_by="tls-scanner",
                raw_match=f"{result.cipher_suite} / {algorithm}",
            )
        )

    return findings
