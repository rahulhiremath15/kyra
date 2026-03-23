"""Tests for the TLS endpoint scanner."""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

import pytest

from kyra.network.cbom_bridge import tls_result_to_findings
from kyra.network.tls_scanner import (
    TLSScanResult,
    _extract_metadata,
    _parse_der_cert,
    parse_host,
    scan_tls,
)

# ------------------------------------------------------------------
# Tests: parse_host
# ------------------------------------------------------------------


class TestParseHost:
    def test_bare_hostname(self) -> None:
        host, port = parse_host("example.com")
        assert host == "example.com"
        assert port == 443

    def test_hostname_with_port(self) -> None:
        host, port = parse_host("example.com:8443")
        assert host == "example.com"
        assert port == 8443

    def test_https_scheme(self) -> None:
        host, port = parse_host("https://example.com")
        assert host == "example.com"
        assert port == 443

    def test_http_scheme(self) -> None:
        host, port = parse_host("http://example.com")
        assert host == "example.com"
        assert port == 443

    def test_https_with_port(self) -> None:
        host, port = parse_host("https://example.com:8443")
        assert host == "example.com"
        assert port == 8443

    def test_trailing_slash(self) -> None:
        host, port = parse_host("https://example.com/")
        assert host == "example.com"
        assert port == 443

    def test_trailing_path(self) -> None:
        host, port = parse_host("https://example.com/some/path")
        assert host == "example.com"
        assert port == 443

    def test_whitespace_stripped(self) -> None:
        host, port = parse_host("  example.com  ")
        assert host == "example.com"
        assert port == 443


# ------------------------------------------------------------------
# Tests: scan_tls with mocked sockets
# ------------------------------------------------------------------


def _make_mock_tls_socket(
    *,
    version: str = "TLSv1.3",
    cipher: tuple[str, str, int] = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
    peercert_der: bytes | None = None,
) -> MagicMock:
    """Create a mock SSLSocket with configurable TLS metadata."""
    mock_sock = MagicMock(spec=ssl.SSLSocket)
    mock_sock.version.return_value = version
    mock_sock.cipher.return_value = cipher
    mock_sock.getpeercert.return_value = peercert_der

    # Support context manager.
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    return mock_sock


class TestScanTLS:
    @patch("kyra.network.tls_scanner.ssl.create_default_context")
    @patch("kyra.network.tls_scanner.socket.create_connection")
    def test_successful_scan_without_cert(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        """Test TLS scan when no DER certificate is returned."""
        tls_sock = _make_mock_tls_socket()

        # Set up the context manager chain: socket -> wrap_socket -> tls_sock
        mock_raw = MagicMock()
        mock_raw.__enter__ = MagicMock(return_value=mock_raw)
        mock_raw.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_raw

        ctx_instance = mock_ctx.return_value
        ctx_instance.wrap_socket.return_value = tls_sock

        result = scan_tls("example.com", 443)

        assert result.host == "example.com"
        assert result.port == 443
        assert result.tls_version == "TLSv1.3"
        assert result.cipher_suite == "TLS_AES_256_GCM_SHA384"
        assert result.cipher_bits == 256
        assert result.error is None

    @patch("kyra.network.tls_scanner.ssl.create_default_context")
    @patch("kyra.network.tls_scanner.socket.create_connection")
    def test_connection_timeout(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        """Test that connection timeouts are handled gracefully."""
        mock_conn.side_effect = OSError("Connection timed out")

        result = scan_tls("unreachable.example.com", 443, timeout=1.0)

        assert result.error is not None
        assert "timed out" in result.error
        assert result.tls_version == "unknown"

    @patch("kyra.network.tls_scanner.ssl.create_default_context")
    @patch("kyra.network.tls_scanner.socket.create_connection")
    def test_ssl_error(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        """Test that SSL errors are handled gracefully."""
        mock_conn.side_effect = ssl.SSLError("SSL handshake failed")

        result = scan_tls("bad-ssl.example.com", 443)

        assert result.error is not None
        assert "SSL" in result.error
        assert result.cipher_suite == "unknown"

    @patch("kyra.network.tls_scanner.ssl.create_default_context")
    @patch("kyra.network.tls_scanner.socket.create_connection")
    def test_dns_failure(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        """Test that DNS resolution failures are handled gracefully."""
        mock_conn.side_effect = OSError("Name or service not known")

        result = scan_tls("nonexistent.invalid", 443)

        assert result.error is not None
        assert result.tls_version == "unknown"

    @patch("kyra.network.tls_scanner.ssl.create_default_context")
    @patch("kyra.network.tls_scanner.socket.create_connection")
    def test_custom_port(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        """Test scanning a non-standard port."""
        tls_sock = _make_mock_tls_socket()
        mock_raw = MagicMock()
        mock_raw.__enter__ = MagicMock(return_value=mock_raw)
        mock_raw.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_raw
        ctx_instance = mock_ctx.return_value
        ctx_instance.wrap_socket.return_value = tls_sock

        result = scan_tls("example.com", 8443)

        assert result.port == 8443
        mock_conn.assert_called_once_with(("example.com", 8443), timeout=10.0)


# ------------------------------------------------------------------
# Tests: _extract_metadata
# ------------------------------------------------------------------


class TestExtractMetadata:
    def test_all_fields_populated(self) -> None:
        tls_sock = _make_mock_tls_socket()
        result = _extract_metadata(tls_sock, "example.com", 443)

        assert result.tls_version == "TLSv1.3"
        assert result.cipher_suite == "TLS_AES_256_GCM_SHA384"
        assert result.cipher_bits == 256
        assert result.error is None

    def test_no_cipher_info(self) -> None:
        tls_sock = _make_mock_tls_socket()
        tls_sock.cipher.return_value = None

        result = _extract_metadata(tls_sock, "example.com", 443)

        assert result.cipher_suite == "unknown"
        assert result.cipher_bits is None

    def test_no_version(self) -> None:
        tls_sock = _make_mock_tls_socket()
        tls_sock.version.return_value = None

        result = _extract_metadata(tls_sock, "example.com", 443)

        assert result.tls_version == "unknown"


# ------------------------------------------------------------------
# Tests: _parse_der_cert with generated test certificates
# ------------------------------------------------------------------


class TestParseDerCert:
    @pytest.fixture
    def rsa_cert_der(self) -> bytes:
        """Generate a self-signed RSA-2048 certificate in DER format."""
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    @pytest.fixture
    def ec_cert_der(self) -> bytes:
        """Generate a self-signed ECDSA P-256 certificate in DER format."""
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_rsa_cert(self, rsa_cert_der: bytes) -> None:
        sig_alg, pk_alg, pk_size = _parse_der_cert(rsa_cert_der)

        assert pk_alg == "RSA"
        assert pk_size == 2048
        assert sig_alg is not None

    def test_ec_cert(self, ec_cert_der: bytes) -> None:
        sig_alg, pk_alg, pk_size = _parse_der_cert(ec_cert_der)

        assert pk_alg == "ECC"
        assert pk_size == 256
        assert sig_alg is not None


# ------------------------------------------------------------------
# Tests: CBOM bridge
# ------------------------------------------------------------------


class TestCBOMBridge:
    def test_successful_result_produces_finding(self) -> None:
        result = TLSScanResult(
            host="example.com",
            port=443,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_signature_algorithm="sha256WithRSAEncryption",
            cert_public_key_algorithm="RSA",
            cert_public_key_size=2048,
        )

        findings = tls_result_to_findings(result)

        assert len(findings) == 1
        f = findings[0]
        assert f.algorithm == "RSA-2048"
        assert f.algorithm_family == "RSA"
        assert f.key_size == 2048
        assert f.confidence == 1.0
        assert f.detected_by == "tls-scanner"
        assert "tls://" in f.file_path

    def test_ecc_result(self) -> None:
        result = TLSScanResult(
            host="example.com",
            port=443,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_signature_algorithm="ecdsa-with-SHA256",
            cert_public_key_algorithm="ECC",
            cert_public_key_size=256,
        )

        findings = tls_result_to_findings(result)

        assert len(findings) == 1
        assert findings[0].algorithm_family == "ECC"
        assert findings[0].algorithm == "ECC-256"

    def test_error_result_produces_no_findings(self) -> None:
        result = TLSScanResult(
            host="example.com",
            port=443,
            tls_version="unknown",
            cipher_suite="unknown",
            cipher_bits=None,
            cert_signature_algorithm=None,
            cert_public_key_algorithm=None,
            cert_public_key_size=None,
            error="Connection refused",
        )

        findings = tls_result_to_findings(result)

        assert findings == []

    def test_no_public_key_produces_no_findings(self) -> None:
        result = TLSScanResult(
            host="example.com",
            port=443,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_signature_algorithm=None,
            cert_public_key_algorithm=None,
            cert_public_key_size=None,
        )

        findings = tls_result_to_findings(result)

        assert findings == []

    def test_finding_has_tls_context(self) -> None:
        result = TLSScanResult(
            host="example.com",
            port=443,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_signature_algorithm="sha256WithRSAEncryption",
            cert_public_key_algorithm="RSA",
            cert_public_key_size=4096,
        )

        findings = tls_result_to_findings(result)

        assert len(findings) == 1
        assert "TLS" in findings[0].usage_context
        assert "TLSv1.3" in findings[0].usage_context


# ------------------------------------------------------------------
# Tests: CLI integration
# ------------------------------------------------------------------


class TestTLSCLI:
    @patch("kyra.cli.main.scan_tls")
    def test_tls_scan_success(self, mock_scan: MagicMock) -> None:
        from typer.testing import CliRunner

        from kyra.cli.main import app

        mock_scan.return_value = TLSScanResult(
            host="example.com",
            port=443,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_signature_algorithm="sha256WithRSAEncryption",
            cert_public_key_algorithm="RSA",
            cert_public_key_size=2048,
        )

        runner = CliRunner()
        result = runner.invoke(app, ["tls", "scan", "example.com"])

        assert result.exit_code == 0
        assert "TLS Scan Results" in result.output
        assert "example.com" in result.output
        assert "TLSv1.3" in result.output
        assert "TLS_AES_256_GCM_SHA384" in result.output

    @patch("kyra.cli.main.scan_tls")
    def test_tls_scan_shows_risk(self, mock_scan: MagicMock) -> None:
        from typer.testing import CliRunner

        from kyra.cli.main import app

        mock_scan.return_value = TLSScanResult(
            host="example.com",
            port=443,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_signature_algorithm="sha256WithRSAEncryption",
            cert_public_key_algorithm="RSA",
            cert_public_key_size=2048,
        )

        runner = CliRunner()
        result = runner.invoke(app, ["tls", "scan", "example.com"])

        assert result.exit_code == 0
        assert "Post-Quantum Risk" in result.output
        assert "Recommendation" in result.output

    @patch("kyra.cli.main.scan_tls")
    def test_tls_scan_connection_error(self, mock_scan: MagicMock) -> None:
        from typer.testing import CliRunner

        from kyra.cli.main import app

        mock_scan.return_value = TLSScanResult(
            host="unreachable.example.com",
            port=443,
            tls_version="unknown",
            cipher_suite="unknown",
            cipher_bits=None,
            cert_signature_algorithm=None,
            cert_public_key_algorithm=None,
            cert_public_key_size=None,
            error="Connection timed out",
        )

        runner = CliRunner()
        result = runner.invoke(app, ["tls", "scan", "unreachable.example.com"])

        assert result.exit_code == 1

    @patch("kyra.cli.main.scan_tls")
    def test_tls_scan_with_port(self, mock_scan: MagicMock) -> None:
        from typer.testing import CliRunner

        from kyra.cli.main import app

        mock_scan.return_value = TLSScanResult(
            host="example.com",
            port=8443,
            tls_version="TLSv1.2",
            cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
            cipher_bits=256,
            cert_signature_algorithm="sha256WithRSAEncryption",
            cert_public_key_algorithm="RSA",
            cert_public_key_size=4096,
        )

        runner = CliRunner()
        result = runner.invoke(app, ["tls", "scan", "example.com:8443"])

        assert result.exit_code == 0
        assert "example.com" in result.output

    @patch("kyra.cli.main.scan_tls")
    def test_tls_scan_with_https_prefix(self, mock_scan: MagicMock) -> None:
        from typer.testing import CliRunner

        from kyra.cli.main import app

        mock_scan.return_value = TLSScanResult(
            host="example.com",
            port=443,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cert_signature_algorithm="sha256WithRSAEncryption",
            cert_public_key_algorithm="RSA",
            cert_public_key_size=2048,
        )

        runner = CliRunner()
        result = runner.invoke(app, ["tls", "scan", "https://example.com"])

        assert result.exit_code == 0
