"""Tests for KYRA report exporters (JSON, CSV, CycloneDX)."""

from __future__ import annotations

import csv
import io
import json

from kyra.cbom.generator import generate_cbom
from kyra.cbom.schema import CBOMReport
from kyra.network.cbom_bridge import tls_result_to_findings
from kyra.network.tls_scanner import TLSScanResult
from kyra.report.exporters import export_csv, export_cyclonedx, export_json
from kyra.risk import analyze_cbom
from kyra.risk.engine import RiskReport
from kyra.scanner.detectors.base import RawFinding
from kyra.scanner.engine import ScanResult

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _repo_scan_fixtures() -> tuple[CBOMReport, RiskReport]:
    """Build CBOM + Risk from a simulated repo scan (no network calls)."""
    findings = [
        RawFinding(
            file_path="/repo/auth/jwt.py",
            line_number=42,
            algorithm="RSA-2048",
            algorithm_family="RSA",
            key_size=2048,
            usage_context="JWT signing",
            confidence=0.85,
            detected_by="regex",
            raw_match="RSA.generate(2048)",
        ),
        RawFinding(
            file_path="/repo/utils/hash.py",
            line_number=10,
            algorithm="SHA-1",
            algorithm_family="SHA-1",
            key_size=None,
            usage_context="SHA-1 hash usage",
            confidence=0.70,
            detected_by="regex",
            raw_match="sha1",
        ),
    ]
    scan = ScanResult(
        target="/repo",
        findings=findings,
        files_scanned=2,
        files_skipped=0,
        duration_s=0.1,
    )
    cbom = generate_cbom(scan)
    risk = analyze_cbom(cbom)
    return cbom, risk


def _tls_scan_fixtures() -> tuple[CBOMReport, RiskReport]:
    """Build CBOM + Risk from a simulated TLS scan (no network calls)."""
    tls_result = TLSScanResult(
        host="example.com",
        port=443,
        tls_version="TLSv1.2",
        cipher_suite="ECDHE-RSA-AES128-GCM-SHA256",
        cipher_bits=128,
        cert_signature_algorithm="sha256WithRSAEncryption",
        cert_public_key_algorithm="RSA",
        cert_public_key_size=2048,
        error=None,
    )
    findings = tls_result_to_findings(tls_result)
    scan = ScanResult(
        target="tls://example.com:443",
        findings=findings,
        files_scanned=0,
        files_skipped=0,
        duration_s=0.0,
    )
    cbom = generate_cbom(scan)
    risk = analyze_cbom(cbom)
    return cbom, risk


# ------------------------------------------------------------------
# JSON export tests
# ------------------------------------------------------------------


class TestJsonExport:
    def test_valid_json(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        text = export_json(cbom, risk)
        parsed = json.loads(text)
        assert isinstance(parsed, dict)

    def test_has_required_top_level_keys(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        parsed = json.loads(export_json(cbom, risk))
        for key in ("kyra_version", "timestamp", "target", "overall_risk", "findings"):
            assert key in parsed, f"missing key: {key}"

    def test_findings_count(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        parsed = json.loads(export_json(cbom, risk))
        assert len(parsed["findings"]) == 2

    def test_finding_fields(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        parsed = json.loads(export_json(cbom, risk))
        finding = parsed["findings"][0]
        expected_keys = {
            "component_name",
            "algorithm",
            "algorithm_family",
            "key_size",
            "protocol_context",
            "pq_readiness_state",
            "risk_level",
            "recommendation",
        }
        assert expected_keys.issubset(finding.keys())

    def test_deterministic_output(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        a = export_json(cbom, risk)
        b = export_json(cbom, risk)
        assert a == b


# ------------------------------------------------------------------
# CSV export tests
# ------------------------------------------------------------------


class TestCsvExport:
    def test_valid_csv(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        text = export_csv(cbom, risk)
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) == 2

    def test_csv_header_columns(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        text = export_csv(cbom, risk)
        header = text.splitlines()[0]
        for col in ("component_name", "algorithm_family", "pq_readiness_state", "risk_level"):
            assert col in header

    def test_csv_contains_correct_values(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        reader = csv.DictReader(io.StringIO(export_csv(cbom, risk)))
        rows = list(reader)
        rsa_row = [r for r in rows if r["algorithm"] == "RSA-2048"][0]
        assert rsa_row["algorithm_family"] == "RSA"
        assert rsa_row["pq_readiness_state"] == "migration-needed"
        assert rsa_row["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_csv_no_blank_lines(self) -> None:
        """Verify no blank lines (the Windows newline bug was producing these)."""
        cbom, risk = _repo_scan_fixtures()
        text = export_csv(cbom, risk)
        lines = text.split("\n")
        # Last element after split may be empty (trailing newline), that's fine.
        non_trailing = lines[:-1] if lines[-1] == "" else lines
        for i, line in enumerate(non_trailing):
            assert line.strip() != "", f"blank line at index {i}"

    def test_csv_null_key_size(self) -> None:
        """SHA-1 has no key_size — should export as empty string."""
        cbom, risk = _repo_scan_fixtures()
        reader = csv.DictReader(io.StringIO(export_csv(cbom, risk)))
        rows = list(reader)
        sha_row = [r for r in rows if r["algorithm"] == "SHA-1"][0]
        assert sha_row["key_size"] == ""

    def test_deterministic_output(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        a = export_csv(cbom, risk)
        b = export_csv(cbom, risk)
        assert a == b


# ------------------------------------------------------------------
# CycloneDX export tests
# ------------------------------------------------------------------


class TestCycloneDxExport:
    def test_valid_json(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        text = export_cyclonedx(cbom, risk)
        parsed = json.loads(text)
        assert isinstance(parsed, dict)

    def test_bom_format(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        parsed = json.loads(export_cyclonedx(cbom, risk))
        assert parsed["bomFormat"] == "CycloneDX"
        assert parsed["specVersion"] == "1.6"

    def test_components_count(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        parsed = json.loads(export_cyclonedx(cbom, risk))
        assert len(parsed["components"]) == 2

    def test_crypto_properties(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        parsed = json.loads(export_cyclonedx(cbom, risk))
        component = parsed["components"][0]
        crypto = component["cryptoProperties"]
        assert "algorithmFamily" in crypto
        assert "pqReadinessState" in crypto
        assert "keySize" in crypto
        assert "protocolContext" in crypto

    def test_component_fields(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        parsed = json.loads(export_cyclonedx(cbom, risk))
        component = parsed["components"][0]
        assert component["type"] == "cryptographic-asset"
        assert "bom-ref" in component
        assert "name" in component

    def test_properties_contain_risk_level(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        parsed = json.loads(export_cyclonedx(cbom, risk))
        component = parsed["components"][0]
        prop_names = [p["name"] for p in component["properties"]]
        assert "kyra:component_name" in prop_names
        assert "kyra:risk_level" in prop_names
        assert "kyra:recommendation" in prop_names

    def test_metadata_has_tool(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        parsed = json.loads(export_cyclonedx(cbom, risk))
        tools = parsed["metadata"]["tools"]
        assert any(t["name"] == "kyra" for t in tools)


# ------------------------------------------------------------------
# TLS scan findings export
# ------------------------------------------------------------------


class TestTlsScanExport:
    def test_tls_json_export(self) -> None:
        cbom, risk = _tls_scan_fixtures()
        parsed = json.loads(export_json(cbom, risk))
        assert parsed["target"] == "tls://example.com:443"
        assert len(parsed["findings"]) >= 1

    def test_tls_csv_export(self) -> None:
        cbom, risk = _tls_scan_fixtures()
        reader = csv.DictReader(io.StringIO(export_csv(cbom, risk)))
        rows = list(reader)
        assert len(rows) >= 1
        assert rows[0]["algorithm_family"] == "RSA"

    def test_tls_cyclonedx_export(self) -> None:
        cbom, risk = _tls_scan_fixtures()
        parsed = json.loads(export_cyclonedx(cbom, risk))
        assert len(parsed["components"]) >= 1
        crypto = parsed["components"][0]["cryptoProperties"]
        assert crypto["algorithmFamily"] == "RSA"


# ------------------------------------------------------------------
# Repo scan findings export
# ------------------------------------------------------------------


class TestRepoScanExport:
    def test_repo_json_has_all_findings(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        parsed = json.loads(export_json(cbom, risk))
        algorithms = [f["algorithm"] for f in parsed["findings"]]
        assert "RSA-2048" in algorithms
        assert "SHA-1" in algorithms

    def test_repo_csv_has_all_findings(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        reader = csv.DictReader(io.StringIO(export_csv(cbom, risk)))
        rows = list(reader)
        algorithms = [r["algorithm"] for r in rows]
        assert "RSA-2048" in algorithms
        assert "SHA-1" in algorithms

    def test_repo_cyclonedx_has_all_findings(self) -> None:
        cbom, risk = _repo_scan_fixtures()
        parsed = json.loads(export_cyclonedx(cbom, risk))
        names = [c["name"] for c in parsed["components"]]
        assert "RSA-2048" in names
        assert "SHA-1" in names
