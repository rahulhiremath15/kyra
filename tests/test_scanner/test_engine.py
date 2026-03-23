"""Tests for the scanner engine."""

from __future__ import annotations

from pathlib import Path

from kyra.scanner.engine import ScannerEngine, ScanResult


class TestScannerEngine:
    """Integration tests for the full scan pipeline."""

    def test_scan_returns_result(self, tmp_repo: Path) -> None:
        """Engine should return a ScanResult with findings."""
        engine = ScannerEngine()
        result = engine.scan(tmp_repo)
        assert isinstance(result, ScanResult)
        assert result.files_scanned > 0
        assert result.duration_s >= 0

    def test_finds_rsa_in_jwt(self, tmp_repo: Path) -> None:
        """Should detect RSA.generate(2048) in jwt.py."""
        engine = ScannerEngine()
        result = engine.scan(tmp_repo)
        rsa_findings = [
            f for f in result.findings if f.algorithm_family == "RSA" and "jwt.py" in f.file_path
        ]
        assert len(rsa_findings) >= 1
        assert rsa_findings[0].key_size == 2048

    def test_finds_sha1_in_hash(self, tmp_repo: Path) -> None:
        """Should detect sha1 in hash.py."""
        engine = ScannerEngine()
        result = engine.scan(tmp_repo)
        sha1_findings = [
            f for f in result.findings if f.algorithm_family == "SHA-1" and "hash.py" in f.file_path
        ]
        assert len(sha1_findings) >= 1

    def test_finds_ecdhe_in_nginx(self, tmp_repo: Path) -> None:
        """Should detect ECDHE in nginx.conf."""
        engine = ScannerEngine()
        result = engine.scan(tmp_repo)
        ecc_findings = [
            f
            for f in result.findings
            if f.algorithm_family == "ECC" and "nginx.conf" in f.file_path
        ]
        assert len(ecc_findings) >= 1

    def test_finds_aes_in_encrypt(self, tmp_repo: Path) -> None:
        """Should detect AES-GCM / AES-256 in encrypt.py."""
        engine = ScannerEngine()
        result = engine.scan(tmp_repo)
        aes_findings = [
            f
            for f in result.findings
            if f.algorithm_family == "AES" and "encrypt.py" in f.file_path
        ]
        assert len(aes_findings) >= 1

    def test_finds_mlkem_pqc(self, tmp_repo: Path) -> None:
        """Should detect ML-KEM (post-quantum) in hybrid.py."""
        engine = ScannerEngine()
        result = engine.scan(tmp_repo)
        pqc_findings = [
            f
            for f in result.findings
            if f.algorithm_family == "ML-KEM" and "hybrid.py" in f.file_path
        ]
        assert len(pqc_findings) >= 1

    def test_skips_gitignored_files(self, tmp_repo: Path) -> None:
        """Findings should NOT come from gitignored files like debug.log."""
        engine = ScannerEngine()
        result = engine.scan(tmp_repo)
        log_findings = [f for f in result.findings if "debug.log" in f.file_path]
        assert len(log_findings) == 0

    def test_skips_private_keys(self, tmp_repo: Path) -> None:
        """Private key files should be skipped entirely."""
        engine = ScannerEngine()
        # Scan without gitignore so we'd potentially hit secrets/server.key
        result = engine.scan(tmp_repo, respect_gitignore=False)
        key_findings = [f for f in result.findings if "server.key" in f.file_path]
        assert len(key_findings) == 0

    def test_skips_binary_files(self, tmp_repo: Path) -> None:
        """Binary files like .png should produce no findings."""
        engine = ScannerEngine()
        result = engine.scan(tmp_repo)
        png_findings = [f for f in result.findings if "image.png" in f.file_path]
        assert len(png_findings) == 0

    def test_deduplication(self, tmp_path: Path) -> None:
        """When two rules match the same family at the same line, keep highest confidence."""
        (tmp_path / "test.py").write_text(
            "# RSA-2048 key using RSA.generate(2048)\n",
            encoding="utf-8",
        )
        engine = ScannerEngine()
        result = engine.scan(tmp_path)
        rsa_line1 = [
            f for f in result.findings if f.algorithm_family == "RSA" and f.line_number == 1
        ]
        # Should be deduplicated to exactly one finding at line 1.
        assert len(rsa_line1) == 1
        # Should keep the one with higher confidence.
        assert rsa_line1[0].confidence == 0.85  # RSA.generate rule

    def test_progress_callback(self, tmp_repo: Path) -> None:
        """on_file_scanned callback should be invoked for each file."""
        progress: list[tuple[Path, int]] = []

        def on_scanned(path: Path, count: int) -> None:
            progress.append((path, count))

        engine = ScannerEngine(on_file_scanned=on_scanned)
        result = engine.scan(tmp_repo)
        assert len(progress) == result.files_scanned
        # Every callback should have a valid Path
        for path, count in progress:
            assert isinstance(path, Path)
            assert count >= 0

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Scanning an empty directory should return zero findings."""
        engine = ScannerEngine()
        result = engine.scan(tmp_path)
        assert result.findings == []
        assert result.files_scanned == 0

    def test_nonexistent_target(self) -> None:
        """Scanning a nonexistent path should return empty result."""
        engine = ScannerEngine()
        result = engine.scan("/this/path/does/not/exist")
        assert result.findings == []
        assert result.files_scanned == 0

    def test_result_sorted_by_file_and_line(self, tmp_repo: Path) -> None:
        """Findings should be sorted by (file_path, line_number)."""
        engine = ScannerEngine()
        result = engine.scan(tmp_repo)
        pairs = [(f.file_path, f.line_number) for f in result.findings]
        assert pairs == sorted(pairs)

    def test_findings_have_required_fields(self, tmp_repo: Path) -> None:
        """Every finding should have all required fields populated."""
        engine = ScannerEngine()
        result = engine.scan(tmp_repo)
        for f in result.findings:
            assert f.file_path != ""
            assert f.line_number > 0
            assert f.algorithm != ""
            assert f.algorithm_family != ""
            assert 0.0 <= f.confidence <= 1.0
            assert f.detected_by == "regex"
            assert f.raw_match != ""
