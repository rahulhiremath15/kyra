"""Report exporters — JSON, CSV, and CycloneDX output for KYRA reports.

Each exporter takes a CBOMReport and a RiskReport and returns a string.
File-writing is handled by the caller (CLI layer).
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from kyra.cbom.schema import CBOMReport
from kyra.risk.engine import RiskReport, ScoredFinding


def _build_finding_row(sf: ScoredFinding) -> dict[str, Any]:
    """Build a flat dict for one scored finding (shared by JSON and CSV)."""
    entry = sf.entry
    return {
        "component_name": entry.component,
        "algorithm": entry.algorithm,
        "algorithm_family": entry.algorithm_family.value,
        "key_size": entry.key_size,
        "protocol_context": entry.usage_context,
        "pq_readiness_state": entry.pq_readiness.value,
        "risk_level": sf.risk_level.value,
        "recommendation": sf.recommendation,
        "location": entry.location,
        "hndl_score": sf.hndl_score,
    }


# ------------------------------------------------------------------
# JSON exporter
# ------------------------------------------------------------------


def export_json(
    cbom: CBOMReport,
    risk: RiskReport,
    *,
    indent: int = 2,
) -> str:
    """Export a full KYRA report as a JSON string."""
    payload: dict[str, Any] = {
        "kyra_version": "0.1.0",
        "timestamp": cbom.timestamp.isoformat(),
        "target": cbom.target,
        "scan_id": cbom.scan_id,
        "overall_risk": risk.overall_risk,
        "overall_level": risk.overall_level.value,
        "total_findings": risk.total_findings,
        "counts_by_level": risk.counts_by_level,
        "findings": [_build_finding_row(sf) for sf in risk.findings],
    }
    return json.dumps(payload, indent=indent, default=str)


# ------------------------------------------------------------------
# CSV exporter
# ------------------------------------------------------------------

_CSV_COLUMNS = [
    "component_name",
    "algorithm",
    "algorithm_family",
    "key_size",
    "protocol_context",
    "pq_readiness_state",
    "risk_level",
    "recommendation",
    "location",
    "hndl_score",
]


def export_csv(cbom: CBOMReport, risk: RiskReport) -> str:
    """Export a KYRA report as a CSV string.

    Uses ``lineterminator='\\n'`` and is safe to write with
    ``open(path, 'w', newline='')`` on all platforms.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for sf in risk.findings:
        row = _build_finding_row(sf)
        row["key_size"] = row["key_size"] if row["key_size"] is not None else ""
        writer.writerow(row)
    return buf.getvalue()


# ------------------------------------------------------------------
# CycloneDX exporter
# ------------------------------------------------------------------


def export_cyclonedx(cbom: CBOMReport, risk: RiskReport) -> str:
    """Export a simplified CycloneDX 1.6 BOM with cryptographic properties.

    Returns a JSON string conforming to a minimal subset of the CycloneDX
    specification focused on cryptographic inventory.
    """
    components: list[dict[str, Any]] = []

    # Index scored findings by entry ID for O(1) lookup.
    scored_by_id: dict[str, ScoredFinding] = {sf.entry.id: sf for sf in risk.findings}

    for entry in cbom.entries:
        sf = scored_by_id.get(entry.id)
        risk_level = sf.risk_level.value if sf else "UNKNOWN"
        recommendation = sf.recommendation if sf else ""

        component: dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": entry.id,
            "name": entry.algorithm,
            "cryptoProperties": {
                "algorithmFamily": entry.algorithm_family.value,
                "keySize": entry.key_size,
                "protocolContext": entry.usage_context,
                "pqReadinessState": entry.pq_readiness.value,
            },
            "properties": [
                {"name": "kyra:component_name", "value": entry.component},
                {"name": "kyra:risk_level", "value": risk_level},
                {"name": "kyra:recommendation", "value": recommendation},
            ],
        }
        components.append(component)

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": f"urn:uuid:{cbom.scan_id}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": "kyra", "version": "0.1.0"}],
        },
        "components": components,
    }
    return json.dumps(bom, indent=2, default=str)
