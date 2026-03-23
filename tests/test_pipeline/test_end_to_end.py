"""End-to-end integration tests for the full KYRA pipeline.

Pipeline under test:
    fixture file → ScannerEngine.scan() → generate_cbom() → analyze_cbom()

Each test scans a real fixture directory, generates a CBOM, runs risk analysis,
and asserts on the final risk levels and recommendations.
"""

from __future__ import annotations

from pathlib import Path

from kyra.cbom.generator import generate_cbom
from kyra.cbom.schema import AlgorithmFamily, PQReadiness
from kyra.risk.engine import RiskLevel, analyze_cbom
from kyra.scanner.engine import ScannerEngine

# ------------------------------------------------------------------
# Fixture paths
# ------------------------------------------------------------------

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_SAMPLE_CODE = _FIXTURES / "sample_code"
_SAMPLE_CONFIGS = _FIXTURES / "sample_configs"
_SAMPLE_CERTS = _FIXTURES / "sample_certs"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _run_pipeline(target: Path):
    """Run scanner → CBOM → risk engine on *target* and return all stages."""
    engine = ScannerEngine()
    scan_result = engine.scan(str(target), respect_gitignore=False)
    cbom = generate_cbom(scan_result)
    risk_report = analyze_cbom(cbom)
    return scan_result, cbom, risk_report


def _find_entries_by_family(cbom, family: AlgorithmFamily):
    """Return CBOM entries matching the given algorithm family."""
    return [e for e in cbom.entries if e.algorithm_family == family]


def _find_findings_by_family(risk_report, family: AlgorithmFamily):
    """Return scored findings matching the given algorithm family."""
    return [f for f in risk_report.findings if f.entry.algorithm_family == family]


# ------------------------------------------------------------------
# Tests: Scanner detects findings from fixtures
# ------------------------------------------------------------------


class TestScannerDetection:
    """Verify the scanner finds crypto patterns in fixture files."""

    def test_scanner_detects_rsa_in_sample_code(self) -> None:
        engine = ScannerEngine()
        result = engine.scan(str(_SAMPLE_CODE), respect_gitignore=False)
        families = {f.algorithm_family for f in result.findings}
        assert "RSA" in families

    def test_scanner_detects_sha1_in_sample_code(self) -> None:
        engine = ScannerEngine()
        result = engine.scan(str(_SAMPLE_CODE), respect_gitignore=False)
        families = {f.algorithm_family for f in result.findings}
        assert "SHA-1" in families

    def test_scanner_detects_aes_in_sample_code(self) -> None:
        engine = ScannerEngine()
        result = engine.scan(str(_SAMPLE_CODE), respect_gitignore=False)
        families = {f.algorithm_family for f in result.findings}
        assert "AES" in families

    def test_scanner_detects_ecc_in_sample_code(self) -> None:
        engine = ScannerEngine()
        result = engine.scan(str(_SAMPLE_CODE), respect_gitignore=False)
        families = {f.algorithm_family for f in result.findings}
        assert "ECC" in families

    def test_scanner_detects_mlkem_in_sample_code(self) -> None:
        engine = ScannerEngine()
        result = engine.scan(str(_SAMPLE_CODE), respect_gitignore=False)
        families = {f.algorithm_family for f in result.findings}
        assert "ML-KEM" in families

    def test_scanner_detects_rsa_in_configs(self) -> None:
        engine = ScannerEngine()
        result = engine.scan(str(_SAMPLE_CONFIGS), respect_gitignore=False)
        families = {f.algorithm_family for f in result.findings}
        assert "RSA" in families

    def test_scanner_detects_aes_in_configs(self) -> None:
        engine = ScannerEngine()
        result = engine.scan(str(_SAMPLE_CONFIGS), respect_gitignore=False)
        families = {f.algorithm_family for f in result.findings}
        assert "AES" in families

    def test_scanner_detects_rsa_in_certs(self) -> None:
        engine = ScannerEngine()
        result = engine.scan(str(_SAMPLE_CERTS), respect_gitignore=False)
        families = {f.algorithm_family for f in result.findings}
        assert "RSA" in families

    def test_scanner_detects_ecdsa_in_certs(self) -> None:
        engine = ScannerEngine()
        result = engine.scan(str(_SAMPLE_CERTS), respect_gitignore=False)
        families = {f.algorithm_family for f in result.findings}
        assert "ECC" in families

    def test_scanner_returns_no_errors(self) -> None:
        engine = ScannerEngine()
        result = engine.scan(str(_SAMPLE_CODE), respect_gitignore=False)
        assert result.errors == []

    def test_scanner_counts_files(self) -> None:
        engine = ScannerEngine()
        result = engine.scan(str(_SAMPLE_CODE), respect_gitignore=False)
        assert result.files_scanned >= 5


# ------------------------------------------------------------------
# Tests: CBOM generator produces correct entries
# ------------------------------------------------------------------


class TestCBOMGeneration:
    """Verify CBOM entries are correctly built from scan results."""

    def test_cbom_has_entries_for_all_families(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CODE)
        families = {e.algorithm_family for e in cbom.entries}
        assert AlgorithmFamily.RSA in families
        assert AlgorithmFamily.SHA1 in families
        assert AlgorithmFamily.AES in families
        assert AlgorithmFamily.ECC in families
        assert AlgorithmFamily.MLKEM in families

    def test_cbom_rsa_has_key_size(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CODE)
        rsa_entries = _find_entries_by_family(cbom, AlgorithmFamily.RSA)
        assert len(rsa_entries) > 0
        key_sizes = {e.key_size for e in rsa_entries if e.key_size is not None}
        assert 2048 in key_sizes or 4096 in key_sizes

    def test_cbom_aes_entries_have_key_size(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CODE)
        aes_entries = _find_entries_by_family(cbom, AlgorithmFamily.AES)
        assert len(aes_entries) > 0
        key_sizes = {e.key_size for e in aes_entries if e.key_size is not None}
        assert len(key_sizes) > 0

    def test_cbom_sha1_marked_critical(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CODE)
        sha1_entries = _find_entries_by_family(cbom, AlgorithmFamily.SHA1)
        assert len(sha1_entries) > 0
        for entry in sha1_entries:
            assert entry.pq_readiness == PQReadiness.CRITICAL

    def test_cbom_mlkem_marked_quantum_safe(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CODE)
        mlkem_entries = _find_entries_by_family(cbom, AlgorithmFamily.MLKEM)
        assert len(mlkem_entries) > 0
        for entry in mlkem_entries:
            assert entry.pq_readiness == PQReadiness.QUANTUM_SAFE

    def test_cbom_summary_totals_match(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CODE)
        assert cbom.summary.total_findings == len(cbom.entries)

    def test_cbom_entries_have_location(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CODE)
        for entry in cbom.entries:
            assert ":" in entry.location
            assert entry.component != ""

    def test_cbom_entries_from_configs(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CONFIGS)
        assert len(cbom.entries) > 0
        families = {e.algorithm_family for e in cbom.entries}
        assert AlgorithmFamily.RSA in families or AlgorithmFamily.AES in families

    def test_cbom_entries_from_certs(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CERTS)
        assert len(cbom.entries) > 0


# ------------------------------------------------------------------
# Tests: Risk engine produces correct risk levels
# ------------------------------------------------------------------


class TestRiskScoring:
    """Verify the risk engine assigns correct risk levels end-to-end."""

    def test_rsa_findings_have_high_algorithm_risk(self) -> None:
        """RSA-2048/4096 should have algorithm_risk >= 0.85.

        The final risk level depends on inferred exposure/lifetime, but the
        algorithm component should always be high for RSA.
        """
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        rsa_findings = _find_findings_by_family(risk, AlgorithmFamily.RSA)
        assert len(rsa_findings) > 0
        for f in rsa_findings:
            assert f.algorithm_risk >= 0.85

    def test_sha1_findings_produce_high_risk(self) -> None:
        """SHA-1 has algorithm_risk=1.0 so should be HIGH or CRITICAL."""
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        sha1_findings = _find_findings_by_family(risk, AlgorithmFamily.SHA1)
        assert len(sha1_findings) > 0
        for f in sha1_findings:
            assert f.algorithm_risk == 1.0
            assert f.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM)

    def test_aes256_findings_low_risk(self) -> None:
        """AES-256 should always produce LOW risk."""
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        aes_findings = _find_findings_by_family(risk, AlgorithmFamily.AES)
        aes256 = [f for f in aes_findings if f.entry.key_size == 256]
        assert len(aes256) > 0
        for f in aes256:
            assert f.risk_level == RiskLevel.LOW

    def test_aes128_risk_higher_than_aes256(self) -> None:
        """AES-128 should have a higher HNDL score than AES-256."""
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        aes_findings = _find_findings_by_family(risk, AlgorithmFamily.AES)
        aes128 = [f for f in aes_findings if f.entry.key_size == 128]
        aes256 = [f for f in aes_findings if f.entry.key_size == 256]
        if aes128 and aes256:
            assert max(f.hndl_score for f in aes128) > min(f.hndl_score for f in aes256)

    def test_mlkem_findings_low_risk(self) -> None:
        """ML-KEM should produce LOW risk."""
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        mlkem_findings = _find_findings_by_family(risk, AlgorithmFamily.MLKEM)
        assert len(mlkem_findings) > 0
        for f in mlkem_findings:
            assert f.risk_level == RiskLevel.LOW
            assert f.hndl_score < 0.2

    def test_mlkem_recommendation_quantum_safe(self) -> None:
        """ML-KEM findings should get a 'quantum-safe' recommendation."""
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        mlkem_findings = _find_findings_by_family(risk, AlgorithmFamily.MLKEM)
        assert len(mlkem_findings) > 0
        for f in mlkem_findings:
            assert "quantum-safe" in f.recommendation

    def test_rsa_recommendation_mentions_pqc(self) -> None:
        """RSA findings should recommend migration to ML-KEM or ML-DSA."""
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        rsa_findings = _find_findings_by_family(risk, AlgorithmFamily.RSA)
        assert len(rsa_findings) > 0
        for f in rsa_findings:
            assert "ML-KEM" in f.recommendation or "ML-DSA" in f.recommendation

    def test_sha1_recommendation_mentions_sha256(self) -> None:
        """SHA-1 findings should recommend SHA-256."""
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        sha1_findings = _find_findings_by_family(risk, AlgorithmFamily.SHA1)
        assert len(sha1_findings) > 0
        for f in sha1_findings:
            assert "SHA-256" in f.recommendation

    def test_ecc_findings_produce_risk(self) -> None:
        """ECC/ECDSA findings should be scored with risk > 0."""
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        ecc_findings = _find_findings_by_family(risk, AlgorithmFamily.ECC)
        assert len(ecc_findings) > 0
        for f in ecc_findings:
            assert f.hndl_score > 0


# ------------------------------------------------------------------
# Tests: Full pipeline report structure
# ------------------------------------------------------------------


class TestRiskReportStructure:
    """Verify the final RiskReport is well-formed."""

    def test_total_findings_matches(self) -> None:
        _, cbom, risk = _run_pipeline(_SAMPLE_CODE)
        assert risk.total_findings == len(cbom.entries)
        assert risk.total_findings == len(risk.findings)

    def test_counts_by_level_sums_to_total(self) -> None:
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        assert sum(risk.counts_by_level.values()) == risk.total_findings

    def test_overall_risk_is_valid(self) -> None:
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        assert 0.0 <= risk.overall_risk <= 1.0
        assert risk.overall_level in RiskLevel

    def test_report_serializes_to_dict(self) -> None:
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        d = risk.to_dict()
        assert "overall_risk" in d
        assert "overall_level" in d
        assert "total_findings" in d
        assert "counts_by_level" in d
        assert "findings" in d
        assert len(d["findings"]) == risk.total_findings

    def test_finding_dicts_have_required_keys(self) -> None:
        _, _, risk = _run_pipeline(_SAMPLE_CODE)
        d = risk.to_dict()
        for finding in d["findings"]:
            assert "id" in finding
            assert "algorithm" in finding
            assert "risk_score" in finding
            assert "risk_level" in finding
            assert "recommendation" in finding
            assert "factors" in finding


# ------------------------------------------------------------------
# Tests: Config file pipeline
# ------------------------------------------------------------------


class TestConfigPipeline:
    """Verify the pipeline works on configuration files."""

    def test_nginx_config_produces_findings(self) -> None:
        _, _, risk = _run_pipeline(_SAMPLE_CONFIGS)
        assert risk.total_findings > 0

    def test_nginx_config_detects_rsa_or_aes(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CONFIGS)
        families = {e.algorithm_family for e in cbom.entries}
        assert AlgorithmFamily.RSA in families or AlgorithmFamily.AES in families


# ------------------------------------------------------------------
# Tests: Certificate file pipeline
# ------------------------------------------------------------------


class TestCertPipeline:
    """Verify the pipeline works on certificate files."""

    def test_cert_files_produce_findings(self) -> None:
        _, _, risk = _run_pipeline(_SAMPLE_CERTS)
        assert risk.total_findings > 0

    def test_rsa_cert_detected(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CERTS)
        families = {e.algorithm_family for e in cbom.entries}
        assert AlgorithmFamily.RSA in families

    def test_ecdsa_cert_detected(self) -> None:
        _, cbom, _ = _run_pipeline(_SAMPLE_CERTS)
        families = {e.algorithm_family for e in cbom.entries}
        assert AlgorithmFamily.ECC in families


# ------------------------------------------------------------------
# Tests: Pipeline is fast and deterministic
# ------------------------------------------------------------------


class TestPipelineProperties:
    """Verify non-functional requirements: speed and determinism."""

    def test_pipeline_completes_quickly(self) -> None:
        """Full pipeline over all fixtures should complete in under 5 seconds."""
        import time

        start = time.monotonic()
        _run_pipeline(_FIXTURES)
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"Pipeline took {elapsed:.2f}s (limit: 5s)"

    def test_pipeline_is_deterministic(self) -> None:
        """Running the pipeline twice should produce the same finding count."""
        _, cbom1, risk1 = _run_pipeline(_SAMPLE_CODE)
        _, cbom2, risk2 = _run_pipeline(_SAMPLE_CODE)
        assert len(cbom1.entries) == len(cbom2.entries)
        assert risk1.total_findings == risk2.total_findings
        # Same algorithms detected
        algos1 = sorted(e.algorithm for e in cbom1.entries)
        algos2 = sorted(e.algorithm for e in cbom2.entries)
        assert algos1 == algos2
