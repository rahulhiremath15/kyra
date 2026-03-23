"""Tests for the CBOM generator."""

from __future__ import annotations

from kyra.cbom.generator import (
    _classify_pq_readiness,
    _infer_exposure,
    _infer_lifetime,
    _make_finding_id,
    _map_algorithm_family,
    _normalize_component,
    generate_cbom,
)
from kyra.cbom.schema import (
    AlgorithmFamily,
    CBOMReport,
    ExposureLevel,
    PQReadiness,
)
from kyra.scanner.detectors.base import RawFinding
from kyra.scanner.engine import ScanResult

# ------------------------------------------------------------------
# Helpers to build test data
# ------------------------------------------------------------------


def _make_finding(**overrides) -> RawFinding:
    """Build a RawFinding with sensible defaults, overridable by keyword."""
    defaults = dict(
        file_path="/repo/backend/auth/jwt.py",
        line_number=42,
        algorithm="RSA-2048",
        algorithm_family="RSA",
        key_size=2048,
        usage_context="RSA key generation with explicit key size",
        confidence=0.85,
        detected_by="regex",
        raw_match="RSA.generate(2048)",
    )
    defaults.update(overrides)
    return RawFinding(**defaults)


def _make_scan_result(findings: list[RawFinding] | None = None) -> ScanResult:
    """Build a ScanResult wrapping the given findings."""
    if findings is None:
        findings = [_make_finding()]
    return ScanResult(
        target="/repo",
        findings=findings,
        files_scanned=len({f.file_path for f in findings}),
        files_skipped=0,
        duration_s=0.5,
    )


# ------------------------------------------------------------------
# Tests: generate_cbom (integration)
# ------------------------------------------------------------------


class TestGenerateCBOM:
    """Full pipeline: ScanResult → CBOMReport."""

    def test_returns_cbom_report(self) -> None:
        result = _make_scan_result()
        report = generate_cbom(result)
        assert isinstance(report, CBOMReport)
        assert report.version == "1.0.0"
        assert report.target == "/repo"

    def test_entry_count_matches_findings(self) -> None:
        findings = [
            _make_finding(file_path="/repo/a.py", line_number=1, algorithm="RSA-2048"),
            _make_finding(file_path="/repo/b.py", line_number=5, algorithm="AES-256"),
        ]
        report = generate_cbom(_make_scan_result(findings))
        assert len(report.entries) == 2
        assert report.summary.total_findings == 2

    def test_rsa_classified_migration_needed(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="RSA",
                        algorithm="RSA-2048",
                        key_size=2048,
                    )
                ]
            )
        )
        entry = report.entries[0]
        assert entry.algorithm_family == AlgorithmFamily.RSA
        assert entry.pq_readiness == PQReadiness.MIGRATION_NEEDED

    def test_ecc_classified_migration_needed(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="ECC",
                        algorithm="ECDSA",
                        key_size=256,
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.MIGRATION_NEEDED

    def test_aes256_classified_quantum_safe(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="AES",
                        algorithm="AES-256",
                        key_size=256,
                        file_path="/repo/storage/encrypt.py",
                        usage_context="AES-GCM mode",
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.QUANTUM_SAFE

    def test_aes128_classified_migration_needed(self) -> None:
        """AES-128 should be migration-needed due to Grover's halving."""
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="AES",
                        algorithm="AES-128",
                        key_size=128,
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.MIGRATION_NEEDED

    def test_sha1_classified_critical(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="SHA-1",
                        algorithm="SHA-1",
                        key_size=None,
                        usage_context="SHA-1 hash usage",
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.CRITICAL

    def test_md5_classified_critical(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="MD5",
                        algorithm="MD5",
                        key_size=None,
                        usage_context="MD5 hash usage",
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.CRITICAL

    def test_des_classified_critical(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="DES",
                        algorithm="DES",
                        key_size=None,
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.CRITICAL

    def test_triple_des_classified_critical(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="3DES",
                        algorithm="3DES",
                        key_size=None,
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.CRITICAL

    def test_mlkem_classified_quantum_safe(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="ML-KEM",
                        algorithm="ML-KEM",
                        key_size=None,
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.QUANTUM_SAFE

    def test_mldsa_classified_quantum_safe(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="ML-DSA",
                        algorithm="ML-DSA",
                        key_size=None,
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.QUANTUM_SAFE

    def test_chacha20_classified_quantum_safe(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="ChaCha20",
                        algorithm="ChaCha20",
                        key_size=None,
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.QUANTUM_SAFE

    def test_dh_classified_migration_needed(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="DH",
                        algorithm="DH-2048",
                        key_size=2048,
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.MIGRATION_NEEDED

    def test_unknown_family_defaults_to_migration_needed(self) -> None:
        """Unknown algorithm family falls back to RSA → migration-needed."""
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        algorithm_family="UNKNOWN_ALGO",
                        algorithm="UNKNOWN_ALGO",
                    )
                ]
            )
        )
        assert report.entries[0].pq_readiness == PQReadiness.MIGRATION_NEEDED

    def test_component_is_relative_path(self) -> None:
        report = generate_cbom(
            _make_scan_result(
                [
                    _make_finding(
                        file_path="/repo/backend/auth/jwt.py",
                    )
                ]
            )
        )
        entry = report.entries[0]
        assert entry.component == "backend/auth/jwt.py"
        assert entry.location == "backend/auth/jwt.py:42"

    def test_entry_has_deterministic_id(self) -> None:
        """Same finding should produce the same ID across calls."""
        f = _make_finding()
        r1 = generate_cbom(_make_scan_result([f]))
        r2 = generate_cbom(_make_scan_result([f]))
        assert r1.entries[0].id == r2.entries[0].id

    def test_scan_id_contains_date(self) -> None:
        report = generate_cbom(_make_scan_result())
        assert report.scan_id.startswith("scan-")
        # scan_id format: scan-YYYYMMDD-<hash>
        parts = report.scan_id.split("-")
        assert len(parts) == 3
        assert len(parts[1]) == 8  # YYYYMMDD
        assert parts[1].isdigit()

    def test_summary_by_readiness(self) -> None:
        findings = [
            _make_finding(algorithm_family="RSA", algorithm="RSA-2048"),
            _make_finding(
                algorithm_family="SHA-1", algorithm="SHA-1", key_size=None, line_number=10
            ),
            _make_finding(
                algorithm_family="AES", algorithm="AES-256", key_size=256, line_number=20
            ),
        ]
        report = generate_cbom(_make_scan_result(findings))
        s = report.summary
        assert s.by_readiness.get("migration-needed", 0) == 1
        assert s.by_readiness.get("critical", 0) == 1
        assert s.by_readiness.get("quantum-safe", 0) == 1

    def test_summary_by_algorithm_family(self) -> None:
        findings = [
            _make_finding(algorithm_family="RSA"),
            _make_finding(algorithm_family="RSA", line_number=10),
            _make_finding(
                algorithm_family="AES", algorithm="AES-256", key_size=256, line_number=20
            ),
        ]
        report = generate_cbom(_make_scan_result(findings))
        assert report.summary.by_algorithm_family["RSA"] == 2
        assert report.summary.by_algorithm_family["AES"] == 1

    def test_empty_findings(self) -> None:
        report = generate_cbom(_make_scan_result([]))
        assert report.entries == []
        assert report.summary.total_findings == 0
        assert report.summary.by_readiness == {}

    def test_confidence_preserved(self) -> None:
        report = generate_cbom(_make_scan_result([_make_finding(confidence=0.72)]))
        assert report.entries[0].confidence == 0.72

    def test_detected_by_preserved(self) -> None:
        report = generate_cbom(_make_scan_result([_make_finding(detected_by="ast-python")]))
        assert report.entries[0].detected_by == "ast-python"


# ------------------------------------------------------------------
# Tests: exposure inference
# ------------------------------------------------------------------


class TestInferExposure:
    def test_nginx_is_external(self) -> None:
        assert _infer_exposure("nginx/nginx.conf", "ssl_ciphers") == ExposureLevel.EXTERNAL

    def test_tls_config_is_external(self) -> None:
        assert _infer_exposure("config/tls.yaml", "TLS config") == ExposureLevel.EXTERNAL

    def test_ssl_context_is_external(self) -> None:
        assert _infer_exposure("app.py", "TLS cipher suite") == ExposureLevel.EXTERNAL

    def test_jwt_is_signing(self) -> None:
        assert _infer_exposure("auth/jwt.py", "key generation") == ExposureLevel.SIGNING

    def test_hash_is_signing(self) -> None:
        assert _infer_exposure("utils/hash.py", "SHA-1 hash usage") == ExposureLevel.SIGNING

    def test_storage_encrypt_is_storage(self) -> None:
        assert _infer_exposure("storage/encrypt.py", "AES-GCM mode") == ExposureLevel.STORAGE

    def test_generic_path_is_internal(self) -> None:
        assert _infer_exposure("lib/utils.py", "RSA key generation") == ExposureLevel.INTERNAL

    def test_backslash_paths_normalized(self) -> None:
        """Windows paths should still match."""
        assert _infer_exposure("nginx\\conf\\ssl.conf", "config") == ExposureLevel.EXTERNAL


# ------------------------------------------------------------------
# Tests: lifetime inference
# ------------------------------------------------------------------


class TestInferLifetime:
    def test_jwt_is_30d(self) -> None:
        assert _infer_lifetime("auth/jwt.py", "token signing") == "30d"

    def test_medical_is_10y(self) -> None:
        assert _infer_lifetime("records/patient.py", "encrypt medical data") == "10y"

    def test_financial_is_7y(self) -> None:
        assert _infer_lifetime("billing/pay.py", "payment processing") == "7y"

    def test_session_is_session(self) -> None:
        assert _infer_lifetime("ws/conn.py", "session key") == "session"

    def test_archive_is_10y(self) -> None:
        assert _infer_lifetime("backup/archive.py", "long-term storage") == "10y"

    def test_unknown_defaults_1y(self) -> None:
        assert _infer_lifetime("foo/bar.py", "general purpose") == "1y"


# ------------------------------------------------------------------
# Tests: PQ readiness classification
# ------------------------------------------------------------------


class TestClassifyPQReadiness:
    def test_rsa_any_size(self) -> None:
        assert _classify_pq_readiness(AlgorithmFamily.RSA, 2048) == PQReadiness.MIGRATION_NEEDED
        assert _classify_pq_readiness(AlgorithmFamily.RSA, 4096) == PQReadiness.MIGRATION_NEEDED

    def test_ecc(self) -> None:
        assert _classify_pq_readiness(AlgorithmFamily.ECC, 256) == PQReadiness.MIGRATION_NEEDED

    def test_aes_256_safe(self) -> None:
        assert _classify_pq_readiness(AlgorithmFamily.AES, 256) == PQReadiness.QUANTUM_SAFE

    def test_aes_128_needs_migration(self) -> None:
        assert _classify_pq_readiness(AlgorithmFamily.AES, 128) == PQReadiness.MIGRATION_NEEDED

    def test_aes_no_key_size_safe(self) -> None:
        """AES without explicit key size defaults to quantum-safe (family default)."""
        assert _classify_pq_readiness(AlgorithmFamily.AES, None) == PQReadiness.QUANTUM_SAFE

    def test_sha1_critical(self) -> None:
        assert _classify_pq_readiness(AlgorithmFamily.SHA1, None) == PQReadiness.CRITICAL

    def test_md5_critical(self) -> None:
        assert _classify_pq_readiness(AlgorithmFamily.MD5, None) == PQReadiness.CRITICAL

    def test_mlkem_safe(self) -> None:
        assert _classify_pq_readiness(AlgorithmFamily.MLKEM, None) == PQReadiness.QUANTUM_SAFE

    def test_chacha20_safe(self) -> None:
        assert _classify_pq_readiness(AlgorithmFamily.CHACHA20, None) == PQReadiness.QUANTUM_SAFE


# ------------------------------------------------------------------
# Tests: algorithm family mapping
# ------------------------------------------------------------------


class TestMapAlgorithmFamily:
    def test_direct_match(self) -> None:
        assert _map_algorithm_family("RSA") == AlgorithmFamily.RSA
        assert _map_algorithm_family("AES") == AlgorithmFamily.AES
        assert _map_algorithm_family("SHA-1") == AlgorithmFamily.SHA1
        assert _map_algorithm_family("ML-KEM") == AlgorithmFamily.MLKEM

    def test_all_families_mappable(self) -> None:
        """Every AlgorithmFamily .value should map back to itself."""
        for member in AlgorithmFamily:
            assert _map_algorithm_family(member.value) == member

    def test_unknown_returns_rsa(self) -> None:
        """Unknown family string should fall back to RSA (conservative)."""
        assert _map_algorithm_family("TOTALLY_UNKNOWN") == AlgorithmFamily.RSA


# ------------------------------------------------------------------
# Tests: finding ID determinism
# ------------------------------------------------------------------


class TestFindingId:
    def test_deterministic(self) -> None:
        a = _make_finding_id("a.py", 10, "RSA-2048")
        b = _make_finding_id("a.py", 10, "RSA-2048")
        assert a == b

    def test_different_inputs_different_ids(self) -> None:
        a = _make_finding_id("a.py", 10, "RSA-2048")
        b = _make_finding_id("a.py", 11, "RSA-2048")
        assert a != b

    def test_format(self) -> None:
        fid = _make_finding_id("x.py", 1, "AES")
        assert fid.startswith("finding-")
        assert len(fid) == len("finding-") + 12  # 12 hex chars


# ------------------------------------------------------------------
# Tests: component normalization
# ------------------------------------------------------------------


class TestNormalizeComponent:
    def test_strips_target_prefix(self) -> None:
        assert _normalize_component("/repo/src/main.py", "/repo") == "src/main.py"

    def test_forward_slashes(self) -> None:
        result = _normalize_component("/repo\\src\\main.py", "/repo")
        assert "\\" not in result
