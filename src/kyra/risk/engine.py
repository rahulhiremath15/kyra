"""HNDL Risk engine — calculates risk scores for CBOM entries.

Pipeline:  CBOMReport → analyze_cbom() → RiskReport

Each CBOMEntry is scored using the formula:

    HNDL_RISK = algorithm_risk × lifetime_factor × exposure_factor

The three factors come from ``kyra.risk.factors``.  The upgrade
recommendation comes from ``kyra.risk.recommendations``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from kyra.cbom.schema import CBOMEntry, CBOMReport
from kyra.risk.factors import (
    get_algorithm_risk,
    get_exposure_factor,
    parse_lifetime_to_factor,
)
from kyra.risk.recommendations import format_with_urgency, get_recommendation

# ------------------------------------------------------------------
# Data types
# ------------------------------------------------------------------


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ScoredFinding:
    """A single CBOM entry annotated with its HNDL risk score."""

    entry: CBOMEntry
    algorithm_risk: float
    lifetime_factor: float
    exposure_factor: float
    hndl_score: float
    risk_level: RiskLevel
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the JSON shape specified in the task."""
        return {
            "id": self.entry.id,
            "component": self.entry.component,
            "algorithm": self.entry.algorithm,
            "algorithm_family": self.entry.algorithm_family.value,
            "location": self.entry.location,
            "risk_score": self.hndl_score,
            "risk_level": self.risk_level.value,
            "factors": {
                "algorithm_risk": self.algorithm_risk,
                "lifetime_factor": self.lifetime_factor,
                "exposure_factor": self.exposure_factor,
            },
            "recommendation": self.recommendation,
        }


@dataclass
class RiskReport:
    """Aggregated risk analysis over a full CBOM."""

    overall_risk: float
    overall_level: RiskLevel
    findings: list[ScoredFinding]
    total_findings: int
    counts_by_level: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the JSON shape specified in the task."""
        return {
            "overall_risk": self.overall_risk,
            "overall_level": self.overall_level.value,
            "total_findings": self.total_findings,
            "counts_by_level": self.counts_by_level,
            "findings": [f.to_dict() for f in self.findings],
        }


# ------------------------------------------------------------------
# Scoring logic
# ------------------------------------------------------------------


def score_to_level(score: float) -> RiskLevel:
    """Map a 0.0–1.0 HNDL score to a risk level."""
    if score >= 0.8:
        return RiskLevel.CRITICAL
    if score >= 0.5:
        return RiskLevel.HIGH
    if score >= 0.2:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def score_entry(entry: CBOMEntry) -> ScoredFinding:
    """Calculate HNDL risk for a single CBOM entry.

    Formula: ``HNDL_RISK = algorithm_risk × lifetime_factor × exposure_factor``
    """
    algo_risk = get_algorithm_risk(entry.algorithm, entry.algorithm_family)
    lifetime = parse_lifetime_to_factor(entry.data_lifetime)
    exposure = get_exposure_factor(entry.exposure_level.value)

    hndl_score = round(algo_risk * lifetime * exposure, 4)
    risk_level = score_to_level(hndl_score)

    base_rec = get_recommendation(entry)
    recommendation = format_with_urgency(base_rec, risk_level.value)

    return ScoredFinding(
        entry=entry,
        algorithm_risk=algo_risk,
        lifetime_factor=lifetime,
        exposure_factor=exposure,
        hndl_score=hndl_score,
        risk_level=risk_level,
        recommendation=recommendation,
    )


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------


def analyze_cbom(report: CBOMReport) -> RiskReport:
    """Score every entry in a CBOMReport and return a RiskReport.

    This is the main entry point for risk analysis.
    """
    scored = [score_entry(entry) for entry in report.entries]
    avg_score, avg_level = overall_risk(scored)

    counts: dict[str, int] = {}
    for level in RiskLevel:
        count = sum(1 for f in scored if f.risk_level == level)
        if count > 0:
            counts[level.value] = count

    return RiskReport(
        overall_risk=avg_score,
        overall_level=avg_level,
        findings=scored,
        total_findings=len(scored),
        counts_by_level=counts,
    )


def overall_risk(findings: list[ScoredFinding]) -> tuple[float, RiskLevel]:
    """Calculate overall risk as the average of individual scores."""
    if not findings:
        return 0.0, RiskLevel.LOW

    avg_score = sum(f.hndl_score for f in findings) / len(findings)
    return round(avg_score, 4), score_to_level(avg_score)
