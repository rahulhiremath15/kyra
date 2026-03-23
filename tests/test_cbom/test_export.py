"""Tests for CBOM export (JSON and CSV)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from kyra.cbom.export import to_csv, to_dict, to_json, write_file
from kyra.cbom.generator import generate_cbom
from kyra.scanner.detectors.base import RawFinding
from kyra.scanner.engine import ScanResult


def _quick_report():
    """Build a small CBOMReport for export testing."""
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
    return generate_cbom(scan)


class TestJsonExport:
    def test_valid_json(self) -> None:
        report = _quick_report()
        text = to_json(report)
        parsed = json.loads(text)
        assert parsed["version"] == "1.0.0"
        assert len(parsed["entries"]) == 2

    def test_to_dict_roundtrip(self) -> None:
        report = _quick_report()
        d = to_dict(report)
        assert isinstance(d, dict)
        assert d["summary"]["total_findings"] == 2

    def test_json_entries_have_required_keys(self) -> None:
        report = _quick_report()
        parsed = json.loads(to_json(report))
        entry = parsed["entries"][0]
        required = {
            "id",
            "component",
            "algorithm",
            "algorithm_family",
            "usage_context",
            "exposure_level",
            "data_lifetime",
            "pq_readiness",
            "location",
            "confidence",
            "detected_by",
            "first_seen",
            "last_seen",
        }
        assert required.issubset(entry.keys())


class TestCsvExport:
    def test_valid_csv(self) -> None:
        report = _quick_report()
        text = to_csv(report)
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) == 2

    def test_csv_header(self) -> None:
        report = _quick_report()
        text = to_csv(report)
        header = text.splitlines()[0]
        assert "id" in header
        assert "algorithm" in header
        assert "pq_readiness" in header

    def test_csv_values(self) -> None:
        report = _quick_report()
        reader = csv.DictReader(io.StringIO(to_csv(report)))
        rows = list(reader)
        rsa_row = [r for r in rows if r["algorithm"] == "RSA-2048"][0]
        assert rsa_row["algorithm_family"] == "RSA"
        assert rsa_row["pq_readiness"] == "migration-needed"
        assert rsa_row["confidence"] == "0.85"


class TestWriteFile:
    def test_write_json(self, tmp_path: Path) -> None:
        report = _quick_report()
        out = write_file(report, tmp_path / "cbom.json", fmt="json")
        assert out.exists()
        parsed = json.loads(out.read_text(encoding="utf-8"))
        assert len(parsed["entries"]) == 2

    def test_write_csv(self, tmp_path: Path) -> None:
        report = _quick_report()
        out = write_file(report, tmp_path / "cbom.csv", fmt="csv")
        assert out.exists()
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 3  # header + 2 data rows

    def test_empty_report(self, tmp_path: Path) -> None:
        empty_scan = ScanResult(
            target="/repo",
            findings=[],
            files_scanned=0,
            files_skipped=0,
            duration_s=0.0,
        )
        report = generate_cbom(empty_scan)
        out = write_file(report, tmp_path / "empty.json", fmt="json")
        parsed = json.loads(out.read_text(encoding="utf-8"))
        assert parsed["entries"] == []
        assert parsed["summary"]["total_findings"] == 0
