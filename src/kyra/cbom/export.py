"""CBOM export — serialize CBOMReport to JSON and CSV formats."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from kyra.cbom.schema import CBOMReport


def to_json(report: CBOMReport, *, indent: int = 2) -> str:
    """Serialize a CBOMReport to a JSON string."""
    return report.model_dump_json(indent=indent)


def to_dict(report: CBOMReport) -> dict[str, Any]:
    """Serialize a CBOMReport to a plain dict (JSON-compatible)."""
    return json.loads(report.model_dump_json())  # type: ignore[no-any-return]


_CSV_COLUMNS = [
    "id",
    "component",
    "algorithm",
    "algorithm_family",
    "key_size",
    "usage_context",
    "exposure_level",
    "data_lifetime",
    "pq_readiness",
    "location",
    "confidence",
    "detected_by",
    "first_seen",
    "last_seen",
]


def to_csv(report: CBOMReport) -> str:
    """Serialize CBOM entries to a CSV string.

    One row per CBOMEntry.  Header row included.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()

    for entry in report.entries:
        row = {
            "id": entry.id,
            "component": entry.component,
            "algorithm": entry.algorithm,
            "algorithm_family": entry.algorithm_family.value,
            "key_size": entry.key_size if entry.key_size is not None else "",
            "usage_context": entry.usage_context,
            "exposure_level": entry.exposure_level.value,
            "data_lifetime": entry.data_lifetime,
            "pq_readiness": entry.pq_readiness.value,
            "location": entry.location,
            "confidence": entry.confidence,
            "detected_by": entry.detected_by,
            "first_seen": entry.first_seen.isoformat(),
            "last_seen": entry.last_seen.isoformat(),
        }
        writer.writerow(row)

    return buf.getvalue()


def write_file(
    report: CBOMReport,
    output_path: str | Path,
    *,
    fmt: str = "json",
) -> Path:
    """Write a CBOMReport to a file.

    Parameters
    ----------
    report:
        The CBOM report to export.
    output_path:
        Destination file path.
    fmt:
        Output format — ``"json"`` or ``"csv"``.

    Returns
    -------
    Path
        The written file path.
    """
    path = Path(output_path)
    if fmt == "csv":
        content = to_csv(report)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
    else:
        content = to_json(report)
        path.write_text(content, encoding="utf-8")
    return path
