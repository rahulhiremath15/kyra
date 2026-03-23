"""Tests for the file walker."""

from __future__ import annotations

from pathlib import Path

from kyra.scanner.file_walker import walk_files


class TestWalkFiles:
    """Tests for walk_files generator."""

    def test_finds_text_files(self, tmp_repo: Path) -> None:
        """Walker should find .py and .conf files."""
        files = list(walk_files(tmp_repo))
        names = {f.name for f in files}
        assert "jwt.py" in names
        assert "hash.py" in names
        assert "nginx.conf" in names
        assert "encrypt.py" in names

    def test_skips_binary_files(self, tmp_repo: Path) -> None:
        """Walker should skip files with binary extensions."""
        files = list(walk_files(tmp_repo))
        names = {f.name for f in files}
        assert "image.png" not in names

    def test_respects_gitignore(self, tmp_repo: Path) -> None:
        """Files matched by .gitignore should be excluded."""
        files = list(walk_files(tmp_repo))
        names = {f.name for f in files}
        # secrets/ is in .gitignore
        assert "server.key" not in names
        # *.log is in .gitignore
        assert "debug.log" not in names

    def test_gitignore_can_be_disabled(self, tmp_repo: Path) -> None:
        """When respect_gitignore=False, .gitignore is not honoured."""
        files = list(walk_files(tmp_repo, respect_gitignore=False))
        names = {f.name for f in files}
        # debug.log would normally be ignored
        assert "debug.log" in names

    def test_skips_empty_files(self, tmp_repo: Path) -> None:
        """Zero-byte files should be skipped."""
        files = list(walk_files(tmp_repo))
        names = {f.name for f in files}
        assert "empty.py" not in names

    def test_skips_oversized_files(self, tmp_path: Path) -> None:
        """Files larger than max_file_size should be skipped."""
        big = tmp_path / "big.py"
        big.write_text("x = 1\n" * 100_000, encoding="utf-8")  # ~600 KB

        files = list(walk_files(tmp_path, max_file_size=1024))
        names = {f.name for f in files}
        assert "big.py" not in names

    def test_skips_always_skip_dirs(self, tmp_path: Path) -> None:
        """Directories like .git and node_modules should always be skipped."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("RSA-2048\n", encoding="utf-8")

        nm_dir = tmp_path / "node_modules"
        nm_dir.mkdir()
        (nm_dir / "pkg.js").write_text("AES-256\n", encoding="utf-8")

        (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

        files = list(walk_files(tmp_path))
        names = {f.name for f in files}
        assert "config" not in names
        assert "pkg.js" not in names
        assert "app.py" in names

    def test_max_depth(self, tmp_path: Path) -> None:
        """Walker should stop at max_depth."""
        deep = tmp_path
        for i in range(5):
            deep = deep / f"level{i}"
            deep.mkdir()
        (deep / "deep.py").write_text("x = 1\n", encoding="utf-8")

        # Depth 2 should not reach level4/deep.py
        files = list(walk_files(tmp_path, max_depth=2))
        names = {f.name for f in files}
        assert "deep.py" not in names

        # Depth 10 should reach it
        files = list(walk_files(tmp_path, max_depth=10))
        names = {f.name for f in files}
        assert "deep.py" in names

    def test_nonexistent_directory(self) -> None:
        """Walking a path that doesn't exist should yield nothing."""
        files = list(walk_files("/nonexistent/path/that/does/not/exist"))
        assert files == []

    def test_symlink_outside_root_skipped(self, tmp_path: Path) -> None:
        """Symlinks pointing outside the scan root should be skipped."""
        import os
        import sys

        if sys.platform == "win32":
            # Symlinks on Windows require elevated privileges in many configs.
            # Skip this test on Windows.
            return

        target_outside = tmp_path.parent / "outside_target"
        target_outside.mkdir(exist_ok=True)
        (target_outside / "secret.py").write_text("RSA-2048\n", encoding="utf-8")

        scan_root = tmp_path / "repo"
        scan_root.mkdir()
        (scan_root / "app.py").write_text("print(1)\n", encoding="utf-8")
        os.symlink(str(target_outside), str(scan_root / "evil_link"))

        files = list(walk_files(scan_root))
        names = {f.name for f in files}
        assert "secret.py" not in names
        assert "app.py" in names
