"""Tests for the HNDL risk scoring engine and recommendations."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from kyra.cbom.schema import (
    AlgorithmFamily,
    CBOMEntry,
    CBOMReport,
    CBOMSummary,
    ExposureLevel,
    PQReadiness,
)
from kyra.risk.engine import (
    RiskLevel,
    RiskReport,
    analyze_cbom,
    overall_risk,
    score_entry,
    score_to_level,
)
from kyra.risk.recommendations import (
    format_with_urgency,
    get_recommendation,
)

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_NOW = datetime.now(tz=timezone.utc)


def _make_entry(
    algorithm: str = "RSA-2048",
    family: AlgorithmFamily = AlgorithmFamily.RSA,
    key_size: int | None = 2048,
    exposure: ExposureLevel = ExposureLevel.EXTERNAL,
    lifetime: str = "30d",
    readiness: PQReadiness = PQReadiness.MIGRATION_NEEDED,
    entry_id: str = "test-001",
) -> CBOMEntry:
    return CBOMEntry(
        id=entry_id,
        component="test/file.py",
        algorithm=algorithm,
        algorithm_family=family,
        key_size=key_size,
        usage_context="Test context",
        exposure_level=exposure,
        data_lifetime=lifetime,
        pq_readiness=readiness,
        location="test/file.py:1",
        confidence=0.95,
        detected_by="test",
        first_seen=_NOW,
        last_seen=_NOW,
    )


def _make_cbom_report(entries: list[CBOMEntry]) -> CBOMReport:
    return CBOMReport(
        scan_id="scan-test-001",
        timestamp=_NOW,
        target="/repo",
        entries=entries,
        summary=CBOMSummary(
            total_findings=len(entries),
            by_readiness={},
            by_algorithm_family={},
            by_exposure={},
        ),
    )


# ------------------------------------------------------------------
# Tests: score_to_level thresholds
# ------------------------------------------------------------------


class TestScoreToLevel:
    def test_low(self) -> None:
        assert score_to_level(0.0) == RiskLevel.LOW
        assert score_to_level(0.19) == RiskLevel.LOW

    def test_medium(self) -> None:
        assert score_to_level(0.2) == RiskLevel.MEDIUM
        assert score_to_level(0.49) == RiskLevel.MEDIUM

    def test_high(self) -> None:
        assert score_to_level(0.5) == RiskLevel.HIGH
        assert score_to_level(0.79) == RiskLevel.HIGH

    def test_critical(self) -> None:
        assert score_to_level(0.8) == RiskLevel.CRITICAL
        assert score_to_level(1.0) == RiskLevel.CRITICAL


# ------------------------------------------------------------------
# Tests: score_entry — individual risk calculations
# ------------------------------------------------------------------


class TestScoreEntry:
    def test_rsa_2048_short_lived_external(self) -> None:
        """RSA-2048, 30d lifetime, external exposure.

        algorithm_risk = 0.9 (RSA-2048)
        lifetime_factor = 0.4 (30d → < 365d bucket)
        exposure_factor = 0.9 (external)
        HNDL = 0.9 × 0.4 × 0.9 = 0.324 → MEDIUM
        """
        entry = _make_entry(algorithm="RSA-2048", lifetime="30d", exposure=ExposureLevel.EXTERNAL)
        result = score_entry(entry)

        assert result.algorithm_risk == 0.9
        assert result.lifetime_factor == 0.4
        assert result.exposure_factor == 0.9
        assert result.hndl_score == 0.324
        assert result.risk_level == RiskLevel.MEDIUM

    def test_rsa_2048_very_short_tokens(self) -> None:
        """RSA-2048, session lifetime, external — LOW risk.

        0.9 × 0.1 × 0.9 = 0.081 → LOW
        """
        entry = _make_entry(
            algorithm="RSA-2048",
            lifetime="session",
            exposure=ExposureLevel.EXTERNAL,
        )
        result = score_entry(entry)

        assert result.hndl_score == 0.081
        assert result.risk_level == RiskLevel.LOW

    def test_ecdh_long_lived_external(self) -> None:
        """ECDH-P256, 5y lifetime, external — HIGH risk.

        0.9 × 0.7 × 0.9 = 0.567 → HIGH
        """
        entry = _make_entry(
            algorithm="ECDH-P256",
            family=AlgorithmFamily.ECC,
            lifetime="5y",
            exposure=ExposureLevel.EXTERNAL,
        )
        result = score_entry(entry)

        assert result.hndl_score == 0.567
        assert result.risk_level == RiskLevel.HIGH

    def test_rsa_very_long_lived_external(self) -> None:
        """RSA-2048, 10y lifetime, external.

        0.9 × 0.9 × 0.9 = 0.729 → HIGH (just under 0.8)
        """
        entry = _make_entry(algorithm="RSA-2048", lifetime="10y", exposure=ExposureLevel.EXTERNAL)
        result = score_entry(entry)

        assert result.hndl_score == 0.729
        assert result.risk_level == RiskLevel.HIGH

    def test_aes_256_always_low(self) -> None:
        """AES-256 should always be low risk regardless of other factors.

        0.05 × 0.9 × 0.9 = 0.0405 → LOW
        """
        entry = _make_entry(
            algorithm="AES-256",
            family=AlgorithmFamily.AES,
            key_size=256,
            lifetime="10y",
            exposure=ExposureLevel.EXTERNAL,
            readiness=PQReadiness.QUANTUM_SAFE,
        )
        result = score_entry(entry)

        assert result.hndl_score < 0.2
        assert result.risk_level == RiskLevel.LOW

    def test_aes_128_higher_than_256(self) -> None:
        """AES-128 should have meaningfully higher risk than AES-256."""
        e128 = _make_entry(
            algorithm="AES-128",
            family=AlgorithmFamily.AES,
            key_size=128,
            lifetime="5y",
            exposure=ExposureLevel.EXTERNAL,
        )
        e256 = _make_entry(
            algorithm="AES-256",
            family=AlgorithmFamily.AES,
            key_size=256,
            lifetime="5y",
            exposure=ExposureLevel.EXTERNAL,
        )
        s128 = score_entry(e128)
        s256 = score_entry(e256)

        assert s128.hndl_score > s256.hndl_score
        assert s128.algorithm_risk == 0.3
        assert s256.algorithm_risk == 0.05

    def test_sha1_algorithm_risk_max(self) -> None:
        """SHA-1 should have algorithm_risk = 1.0."""
        entry = _make_entry(
            algorithm="SHA-1",
            family=AlgorithmFamily.SHA1,
            key_size=None,
            lifetime="7y",
            exposure=ExposureLevel.SIGNING,
            readiness=PQReadiness.CRITICAL,
        )
        result = score_entry(entry)
        assert result.algorithm_risk == 1.0

    def test_md5_algorithm_risk_max(self) -> None:
        entry = _make_entry(
            algorithm="MD5",
            family=AlgorithmFamily.MD5,
            key_size=None,
            lifetime="1y",
            exposure=ExposureLevel.INTERNAL,
        )
        result = score_entry(entry)
        assert result.algorithm_risk == 1.0

    def test_mlkem_near_zero_risk(self) -> None:
        """ML-KEM should have near-zero HNDL risk."""
        entry = _make_entry(
            algorithm="ML-KEM",
            family=AlgorithmFamily.MLKEM,
            key_size=None,
            lifetime="10y",
            exposure=ExposureLevel.EXTERNAL,
            readiness=PQReadiness.QUANTUM_SAFE,
        )
        result = score_entry(entry)

        assert result.algorithm_risk == 0.02
        assert result.hndl_score < 0.05
        assert result.risk_level == RiskLevel.LOW

    def test_internal_exposure_reduces_risk(self) -> None:
        ext = score_entry(_make_entry(exposure=ExposureLevel.EXTERNAL))
        intl = score_entry(_make_entry(exposure=ExposureLevel.INTERNAL))

        assert intl.hndl_score < ext.hndl_score
        assert intl.exposure_factor == 0.3
        assert ext.exposure_factor == 0.9

    def test_permanent_lifetime_max_factor(self) -> None:
        entry = _make_entry(lifetime="permanent")
        result = score_entry(entry)
        assert result.lifetime_factor == 1.0

    def test_session_lifetime_min_factor(self) -> None:
        entry = _make_entry(lifetime="session")
        result = score_entry(entry)
        assert result.lifetime_factor == 0.1

    def test_score_is_rounded(self) -> None:
        entry = _make_entry()
        result = score_entry(entry)
        score_str = str(result.hndl_score)
        if "." in score_str:
            decimals = len(score_str.split(".")[1])
            assert decimals <= 4


# ------------------------------------------------------------------
# Tests: recommendations
# ------------------------------------------------------------------


class TestRecommendations:
    def test_rsa_recommends_pqc(self) -> None:
        rec = get_recommendation(_make_entry(family=AlgorithmFamily.RSA))
        assert "ML-KEM" in rec or "ML-DSA" in rec

    def test_ecc_recommends_pqc(self) -> None:
        rec = get_recommendation(_make_entry(family=AlgorithmFamily.ECC))
        assert "ML-KEM" in rec

    def test_dh_recommends_ml_kem(self) -> None:
        rec = get_recommendation(_make_entry(family=AlgorithmFamily.DH))
        assert "ML-KEM" in rec

    def test_sha1_recommends_sha256(self) -> None:
        rec = get_recommendation(
            _make_entry(
                family=AlgorithmFamily.SHA1,
                algorithm="SHA-1",
                key_size=None,
            )
        )
        assert "SHA-256" in rec

    def test_md5_recommends_sha256(self) -> None:
        rec = get_recommendation(
            _make_entry(
                family=AlgorithmFamily.MD5,
                algorithm="MD5",
                key_size=None,
            )
        )
        assert "SHA-256" in rec

    def test_des_recommends_aes(self) -> None:
        rec = get_recommendation(
            _make_entry(
                family=AlgorithmFamily.DES,
                algorithm="DES",
                key_size=None,
            )
        )
        assert "AES-256" in rec

    def test_tdes_recommends_aes(self) -> None:
        rec = get_recommendation(
            _make_entry(
                family=AlgorithmFamily.TDES,
                algorithm="3DES",
                key_size=None,
            )
        )
        assert "AES-256" in rec

    def test_aes128_recommends_upgrade(self) -> None:
        rec = get_recommendation(
            _make_entry(
                family=AlgorithmFamily.AES,
                algorithm="AES-128",
                key_size=128,
            )
        )
        assert "AES-256" in rec

    def test_aes256_no_action(self) -> None:
        rec = get_recommendation(
            _make_entry(
                family=AlgorithmFamily.AES,
                algorithm="AES-256",
                key_size=256,
            )
        )
        assert "No action needed" in rec

    def test_mlkem_no_action(self) -> None:
        rec = get_recommendation(
            _make_entry(
                family=AlgorithmFamily.MLKEM,
                algorithm="ML-KEM",
                key_size=None,
            )
        )
        assert "No action needed" in rec

    def test_chacha20_no_action(self) -> None:
        rec = get_recommendation(
            _make_entry(
                family=AlgorithmFamily.CHACHA20,
                algorithm="ChaCha20",
                key_size=None,
            )
        )
        assert "No action needed" in rec

    def test_format_with_urgency_low(self) -> None:
        assert "low priority" in format_with_urgency("Migrate to ML-KEM", "LOW")

    def test_format_with_urgency_medium(self) -> None:
        assert "plan migration" in format_with_urgency("Migrate to ML-KEM", "MEDIUM")

    def test_format_with_urgency_high(self) -> None:
        assert "migrate within 12 months" in format_with_urgency("Migrate to ML-KEM", "HIGH")

    def test_format_with_urgency_critical(self) -> None:
        assert "immediate action required" in format_with_urgency(
            "Replace with SHA-256",
            "CRITICAL",
        )

    def test_format_preserves_no_action(self) -> None:
        text = format_with_urgency("No action needed (quantum-safe)", "HIGH")
        assert text == "No action needed (quantum-safe)"

    def test_scored_finding_has_urgency(self) -> None:
        entry = _make_entry(
            algorithm="ECDH-P256",
            family=AlgorithmFamily.ECC,
            lifetime="5y",
            exposure=ExposureLevel.EXTERNAL,
        )
        result = score_entry(entry)
        assert "migrate within 12 months" in result.recommendation

    def test_safe_algo_no_urgency(self) -> None:
        entry = _make_entry(
            algorithm="AES-256",
            family=AlgorithmFamily.AES,
            key_size=256,
            lifetime="1y",
            exposure=ExposureLevel.INTERNAL,
        )
        result = score_entry(entry)
        assert result.recommendation == "No action needed (quantum-safe)"


# ------------------------------------------------------------------
# Tests: analyze_cbom → RiskReport
# ------------------------------------------------------------------


class TestAnalyzeCBOM:
    def test_returns_risk_report(self) -> None:
        result = analyze_cbom(_make_cbom_report([_make_entry()]))
        assert isinstance(result, RiskReport)

    def test_finding_count_matches(self) -> None:
        entries = [
            _make_entry(entry_id="a"),
            _make_entry(
                entry_id="b",
                algorithm="AES-256",
                family=AlgorithmFamily.AES,
                key_size=256,
            ),
        ]
        result = analyze_cbom(_make_cbom_report(entries))
        assert result.total_findings == 2
        assert len(result.findings) == 2

    def test_overall_risk_is_average(self) -> None:
        entries = [
            _make_entry(
                entry_id="a",
                algorithm="AES-256",
                family=AlgorithmFamily.AES,
                key_size=256,
                lifetime="1y",
                exposure=ExposureLevel.INTERNAL,
            ),
            _make_entry(
                entry_id="b",
                algorithm="RSA-2048",
                family=AlgorithmFamily.RSA,
                lifetime="5y",
                exposure=ExposureLevel.EXTERNAL,
            ),
        ]
        result = analyze_cbom(_make_cbom_report(entries))

        # AES-256: 0.05 × 0.4 × 0.3 = 0.006
        # RSA-2048: 0.9 × 0.7 × 0.9 = 0.567
        # Average: (0.006 + 0.567) / 2 = 0.2865
        assert result.overall_risk == 0.2865
        assert result.overall_level == RiskLevel.MEDIUM

    def test_counts_by_level(self) -> None:
        entries = [
            _make_entry(entry_id="a", lifetime="session"),
            _make_entry(entry_id="b", lifetime="30d"),
            _make_entry(entry_id="c", lifetime="5y", exposure=ExposureLevel.EXTERNAL),
        ]
        result = analyze_cbom(_make_cbom_report(entries))

        assert "LOW" in result.counts_by_level
        assert "MEDIUM" in result.counts_by_level
        assert "HIGH" in result.counts_by_level

    def test_empty_cbom(self) -> None:
        result = analyze_cbom(_make_cbom_report([]))
        assert result.total_findings == 0
        assert result.overall_risk == 0.0
        assert result.overall_level == RiskLevel.LOW
        assert result.findings == []
        assert result.counts_by_level == {}


# ------------------------------------------------------------------
# Tests: overall_risk
# ------------------------------------------------------------------


class TestOverallRisk:
    def test_empty(self) -> None:
        avg, level = overall_risk([])
        assert avg == 0.0
        assert level == RiskLevel.LOW

    def test_single(self) -> None:
        scored = score_entry(_make_entry(lifetime="30d", exposure=ExposureLevel.EXTERNAL))
        avg, level = overall_risk([scored])
        assert avg == scored.hndl_score

    def test_average_of_two(self) -> None:
        s1 = score_entry(
            _make_entry(
                algorithm="AES-256",
                family=AlgorithmFamily.AES,
                key_size=256,
                lifetime="1y",
                exposure=ExposureLevel.INTERNAL,
            )
        )
        s2 = score_entry(
            _make_entry(
                algorithm="RSA-2048",
                lifetime="5y",
                exposure=ExposureLevel.EXTERNAL,
            )
        )
        avg, _ = overall_risk([s1, s2])
        expected = round((s1.hndl_score + s2.hndl_score) / 2, 4)
        assert avg == expected


# ------------------------------------------------------------------
# Tests: serialization
# ------------------------------------------------------------------


class TestSerialization:
    def test_scored_finding_to_dict(self) -> None:
        scored = score_entry(_make_entry())
        d = scored.to_dict()

        assert d["id"] == "test-001"
        assert d["algorithm"] == "RSA-2048"
        assert d["risk_score"] == scored.hndl_score
        assert d["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert "algorithm_risk" in d["factors"]
        assert "lifetime_factor" in d["factors"]
        assert "exposure_factor" in d["factors"]
        assert isinstance(d["recommendation"], str)

    def test_risk_report_to_dict(self) -> None:
        entries = [
            _make_entry(entry_id="a"),
            _make_entry(
                entry_id="b",
                algorithm="SHA-1",
                family=AlgorithmFamily.SHA1,
                key_size=None,
            ),
        ]
        result = analyze_cbom(_make_cbom_report(entries))
        d = result.to_dict()

        assert "overall_risk" in d
        assert "overall_level" in d
        assert "total_findings" in d
        assert "counts_by_level" in d
        assert "findings" in d
        assert len(d["findings"]) == 2

    def test_json_serializable(self) -> None:
        """The full report dict must be JSON-serializable."""
        report = analyze_cbom(_make_cbom_report([_make_entry()]))
        d = report.to_dict()
        text = json.dumps(d)
        parsed = json.loads(text)

        assert isinstance(parsed["overall_risk"], float)
        finding = parsed["findings"][0]
        assert "algorithm" in finding
        assert "risk_score" in finding
        assert "risk_level" in finding
        assert "recommendation" in finding
