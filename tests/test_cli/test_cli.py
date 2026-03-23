"""Tests for the KYRA CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kyra.cli.main import app

runner = CliRunner()


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def crypto_repo(tmp_path: Path) -> Path:
    """Minimal repo with known crypto patterns for CLI testing."""
    auth = tmp_path / "auth"
    auth.mkdir()
    (auth / "jwt.py").write_text(
        "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n",
        encoding="utf-8",
    )

    utils = tmp_path / "utils"
    utils.mkdir()
    (utils / "hash.py").write_text(
        "import hashlib\ndigest = hashlib.sha1(b'data').hexdigest()\n",
        encoding="utf-8",
    )

    storage = tmp_path / "storage"
    storage.mkdir()
    (storage / "encrypt.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "# AES-256 encryption\n"
        "aesgcm = AESGCM(key)\n",
        encoding="utf-8",
    )

    return tmp_path


@pytest.fixture
def empty_repo(tmp_path: Path) -> Path:
    """Repo with no crypto patterns."""
    (tmp_path / "readme.txt").write_text("Hello world\n", encoding="utf-8")
    return tmp_path


# ------------------------------------------------------------------
# kyra scan
# ------------------------------------------------------------------


class TestScanCommand:
    def test_scan_prints_summary(self, crypto_repo: Path):
        result = runner.invoke(app, ["scan", str(crypto_repo)])
        assert result.exit_code == 0
        assert "Files scanned" in result.output
        assert "Findings" in result.output

    def test_scan_detects_findings(self, crypto_repo: Path):
        result = runner.invoke(app, ["scan", str(crypto_repo)])
        assert result.exit_code == 0
        assert "RSA" in result.output
        assert "SHA-1" in result.output

    def test_scan_default_cwd(self, crypto_repo: Path, monkeypatch):
        monkeypatch.chdir(crypto_repo)
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 0
        assert "Files scanned" in result.output

    def test_scan_nonexistent_path(self):
        result = runner.invoke(app, ["scan", "/nonexistent/path/xyz"])
        assert result.exit_code == 1

    def test_scan_empty_repo(self, empty_repo: Path):
        result = runner.invoke(app, ["scan", str(empty_repo)])
        assert result.exit_code == 0
        assert "Files scanned" in result.output

    def test_scan_with_output_json(self, crypto_repo: Path, tmp_path: Path):
        out_file = tmp_path / "out" / "result.json"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        result = runner.invoke(app, ["scan", str(crypto_repo), "-o", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert "entries" in data
        assert "summary" in data

    def test_scan_with_output_csv(self, crypto_repo: Path, tmp_path: Path):
        out_file = tmp_path / "out" / "result.csv"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        result = runner.invoke(app, ["scan", str(crypto_repo), "-o", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "algorithm" in content  # CSV header


# ------------------------------------------------------------------
# kyra cbom generate
# ------------------------------------------------------------------


class TestCBOMGenerateCommand:
    def test_cbom_generate_prints_summary(self, crypto_repo: Path):
        result = runner.invoke(app, ["cbom", "generate", str(crypto_repo)])
        assert result.exit_code == 0
        assert "CBOM Summary" in result.output
        assert "Total entries" in result.output

    def test_cbom_generate_shows_entries(self, crypto_repo: Path):
        result = runner.invoke(app, ["cbom", "generate", str(crypto_repo)])
        assert result.exit_code == 0
        assert "RSA" in result.output

    def test_cbom_generate_with_output(self, crypto_repo: Path, tmp_path: Path):
        out_file = tmp_path / "cbom.json"
        result = runner.invoke(app, ["cbom", "generate", str(crypto_repo), "-o", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["version"] == "1.0.0"
        assert len(data["entries"]) > 0

    def test_cbom_generate_csv_format(self, crypto_repo: Path, tmp_path: Path):
        out_file = tmp_path / "cbom.csv"
        result = runner.invoke(
            app, ["cbom", "generate", str(crypto_repo), "-f", "csv", "-o", str(out_file)]
        )
        assert result.exit_code == 0
        assert out_file.exists()

    def test_cbom_generate_empty_repo(self, empty_repo: Path):
        result = runner.invoke(app, ["cbom", "generate", str(empty_repo)])
        assert result.exit_code == 0
        assert "Total entries" in result.output


# ------------------------------------------------------------------
# kyra risk analyze
# ------------------------------------------------------------------


class TestRiskAnalyzeCommand:
    def test_risk_analyze_shows_score(self, crypto_repo: Path):
        result = runner.invoke(app, ["risk", "analyze", str(crypto_repo)])
        assert result.exit_code == 0
        assert "Readiness Score" in result.output
        assert "/ 100" in result.output

    def test_risk_analyze_groups_by_severity(self, crypto_repo: Path):
        result = runner.invoke(app, ["risk", "analyze", str(crypto_repo)])
        assert result.exit_code == 0
        # At least one severity level should appear
        has_level = any(level in result.output for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        assert has_level

    def test_risk_analyze_shows_recommendations(self, crypto_repo: Path):
        result = runner.invoke(app, ["risk", "analyze", str(crypto_repo)])
        assert result.exit_code == 0
        # RSA finding should have a migration recommendation
        assert "RSA" in result.output

    def test_fail_on_risk_triggers_exit(self, crypto_repo: Path):
        result = runner.invoke(app, ["risk", "analyze", str(crypto_repo), "--fail-on-risk", "low"])
        # crypto_repo has findings at various levels, so this should fail
        assert result.exit_code == 1

    def test_fail_on_risk_critical_only(self, empty_repo: Path):
        result = runner.invoke(
            app, ["risk", "analyze", str(empty_repo), "--fail-on-risk", "critical"]
        )
        # No findings → no failure
        assert result.exit_code == 0

    def test_fail_on_risk_invalid_level(self, crypto_repo: Path):
        result = runner.invoke(
            app, ["risk", "analyze", str(crypto_repo), "--fail-on-risk", "extreme"]
        )
        assert result.exit_code == 2

    def test_risk_analyze_empty_repo(self, empty_repo: Path):
        result = runner.invoke(app, ["risk", "analyze", str(empty_repo)])
        assert result.exit_code == 0
        assert "100 / 100" in result.output


# ------------------------------------------------------------------
# kyra report
# ------------------------------------------------------------------


class TestReportCommand:
    def test_report_full_output(self, crypto_repo: Path):
        result = runner.invoke(app, ["report", str(crypto_repo)])
        assert result.exit_code == 0
        assert "Readiness Score" in result.output
        assert "Files scanned" in result.output

    def test_report_grouping(self, crypto_repo: Path):
        result = runner.invoke(app, ["report", str(crypto_repo)])
        assert result.exit_code == 0
        has_level = any(level in result.output for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        assert has_level

    def test_report_with_output(self, crypto_repo: Path, tmp_path: Path):
        out_file = tmp_path / "report.json"
        result = runner.invoke(app, ["report", str(crypto_repo), "-o", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()

    def test_report_empty_repo(self, empty_repo: Path):
        result = runner.invoke(app, ["report", str(empty_repo)])
        assert result.exit_code == 0
        assert "100 / 100" in result.output


# ------------------------------------------------------------------
# Edge cases and error handling
# ------------------------------------------------------------------


class TestEdgeCases:
    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # Typer exits with code 0 or 2 when showing help (no_args_is_help=True)
        assert result.exit_code in (0, 2)
        assert "Usage" in result.output or "kyra" in result.output

    def test_scan_file_not_directory(self, tmp_path: Path):
        f = tmp_path / "file.txt"
        f.write_text("hello", encoding="utf-8")
        result = runner.invoke(app, ["scan", str(f)])
        assert result.exit_code == 1

    def test_large_repo_does_not_crash(self, tmp_path: Path):
        """Ensure the CLI handles a directory with many files."""
        for i in range(100):
            (tmp_path / f"file_{i}.py").write_text(
                f"# file {i}\nimport hashlib\nhashlib.sha256(b'')\n",
                encoding="utf-8",
            )
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "Files scanned" in result.output
