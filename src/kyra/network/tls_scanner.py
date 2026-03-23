"""TLS endpoint scanner — connects to a live host and extracts cryptographic metadata.

This module performs a read-only TLS handshake against a remote host to determine:
- TLS protocol version
- Negotiated cipher suite
- Certificate signature algorithm
- Certificate public key algorithm and size

All connections are read-only (no data is sent after the handshake) and use
configurable timeouts to handle unreachable hosts gracefully.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass

# Default connection timeout in seconds.
_DEFAULT_TIMEOUT_S = 10.0


@dataclass
class TLSScanResult:
    """Cryptographic metadata extracted from a TLS handshake."""

    host: str
    port: int
    tls_version: str
    cipher_suite: str
    cipher_bits: int | None
    cert_signature_algorithm: str | None
    cert_public_key_algorithm: str | None
    cert_public_key_size: int | None
    error: str | None = None


def parse_host(raw: str) -> tuple[str, int]:
    """Parse a user-supplied host string into (hostname, port).

    Accepted formats:
    - example.com
    - example.com:8443
    - https://example.com
    - https://example.com:8443
    """
    cleaned = raw.strip()
    # Strip protocol scheme if present.
    cleaned = re.sub(r"^https?://", "", cleaned)
    # Strip trailing path/slash.
    cleaned = cleaned.split("/")[0]

    if ":" in cleaned:
        host_part, port_str = cleaned.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            # Colon was not a port separator (shouldn't normally happen).
            return cleaned, 443
        return host_part, port
    return cleaned, 443


def scan_tls(
    host: str,
    port: int = 443,
    *,
    timeout: float = _DEFAULT_TIMEOUT_S,
) -> TLSScanResult:
    """Perform a TLS handshake and extract cryptographic metadata.

    Parameters
    ----------
    host:
        Hostname to connect to (e.g. ``"example.com"``).
    port:
        TCP port (default 443).
    timeout:
        Connection timeout in seconds.

    Returns
    -------
    TLSScanResult
        Extracted TLS and certificate information.  If the connection
        fails, the ``error`` field is set and other fields use defaults.
    """
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                return _extract_metadata(tls_sock, host, port)
    except (OSError, ssl.SSLError) as exc:
        return TLSScanResult(
            host=host,
            port=port,
            tls_version="unknown",
            cipher_suite="unknown",
            cipher_bits=None,
            cert_signature_algorithm=None,
            cert_public_key_algorithm=None,
            cert_public_key_size=None,
            error=str(exc),
        )


def _extract_metadata(
    tls_sock: ssl.SSLSocket,
    host: str,
    port: int,
) -> TLSScanResult:
    """Read TLS session and certificate details from an established socket."""
    # --- TLS session info ---
    tls_version = tls_sock.version() or "unknown"
    cipher_info = tls_sock.cipher()
    if cipher_info is not None:
        cipher_suite = cipher_info[0]
        cipher_bits = cipher_info[2]
    else:
        cipher_suite = "unknown"
        cipher_bits = None

    # --- Certificate info ---
    cert_sig_alg: str | None = None
    cert_pk_alg: str | None = None
    cert_pk_size: int | None = None

    der_cert = tls_sock.getpeercert(binary_form=True)
    if der_cert is not None:
        cert_sig_alg, cert_pk_alg, cert_pk_size = _parse_der_cert(der_cert)

    return TLSScanResult(
        host=host,
        port=port,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        cipher_bits=cipher_bits,
        cert_signature_algorithm=cert_sig_alg,
        cert_public_key_algorithm=cert_pk_alg,
        cert_public_key_size=cert_pk_size,
    )


def _parse_der_cert(
    der_bytes: bytes,
) -> tuple[str | None, str | None, int | None]:
    """Extract signature algorithm, public key algorithm, and key size from DER.

    Uses the ``cryptography`` library which is already a KYRA dependency.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        dsa,
        ec,
        ed448,
        ed25519,
        rsa,
    )

    cert = x509.load_der_x509_certificate(der_bytes)

    # Signature algorithm
    sig_alg: str | None = None
    try:
        sig_oid = cert.signature_algorithm_oid
        sig_alg = sig_oid._name  # noqa: SLF001
    except Exception:  # noqa: BLE001, S110
        pass  # sig_alg stays None — not all certs expose a parseable OID name

    # Public key algorithm + size
    pk_alg: str | None = None
    pk_size: int | None = None
    pub = cert.public_key()

    if isinstance(pub, rsa.RSAPublicKey):
        pk_alg = "RSA"
        pk_size = pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pk_alg = "ECC"
        pk_size = pub.key_size
    elif isinstance(pub, dsa.DSAPublicKey):
        pk_alg = "DSA"
        pk_size = pub.key_size
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        pk_alg = "Ed25519"
        pk_size = 256
    elif isinstance(pub, ed448.Ed448PublicKey):
        pk_alg = "Ed448"
        pk_size = 448
    else:
        pk_alg = type(pub).__name__

    return sig_alg, pk_alg, pk_size
