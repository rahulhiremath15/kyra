"""Scanner engine — orchestrates file walking, detector execution, and deduplication.

This is the top-level entry point for scanning.  It:

1. Walks the target directory (via file_walker).
2. Reads each file once (read-only).
3. Dispatches to all registered detectors.
4. Deduplicates overlapping findings.
5. Returns a structured list of RawFinding objects.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from kyra.scanner.detectors.base import BaseDetector, RawFinding
from kyra.scanner.detectors.regex import RegexDetector
from kyra.scanner.file_walker import walk_files

# Private key PEM headers — files containing these are metadata-only.
# We record their existence but never store their content.
_PRIVATE_KEY_MARKERS: tuple[bytes, ...] = (
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)

# Per-file read timeout isn't natively supported in sync Python I/O, so we
# cap by file size instead (handled in file_walker).  This constant is a
# soft upper bound on wall-clock seconds the engine spends on a single file
# before it gives up on that file's detectors.
_PER_FILE_SOFT_TIMEOUT_S = 5.0


@dataclass
class ScanResult:
    """Aggregated output from a scan run."""

    target: str
    findings: list[RawFinding]
    files_scanned: int
    files_skipped: int
    duration_s: float
    errors: list[str] = field(default_factory=list)


@dataclass
class _FileStats:
    scanned: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


class ScannerEngine:
    """Orchestrates a full scan over a directory.

    Usage::

        engine = ScannerEngine()
        result = engine.scan("/path/to/repo")
        for f in result.findings:
            print(f.file_path, f.algorithm, f.confidence)
    """

    def __init__(
        self,
        *,
        detectors: list[BaseDetector] | None = None,
        on_file_scanned: Callable[[Path, int], None] | None = None,
    ) -> None:
        """Create a scanner engine.

        Parameters
        ----------
        detectors:
            List of detectors to use.  If ``None``, uses the default set
            (regex detector with built-in rules).
        on_file_scanned:
            Optional callback invoked after each file is scanned.
            Receives ``(file_path, findings_count)``.  Useful for progress
            reporting.
        """
        if detectors is None:
            self._detectors: list[BaseDetector] = [RegexDetector()]
        else:
            self._detectors = list(detectors)

        self._on_file_scanned = on_file_scanned
        self._content_hashes: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        target: str | Path,
        *,
        respect_gitignore: bool = True,
    ) -> ScanResult:
        """Scan *target* directory and return aggregated results.

        This is the main entry point.  It walks the file tree, reads each
        file, dispatches to detectors, deduplicates, and returns a
        ``ScanResult``.
        """
        target_path = Path(target).resolve()
        start = time.monotonic()
        stats = _FileStats()
        all_findings: list[RawFinding] = []

        for file_path in walk_files(target_path, respect_gitignore=respect_gitignore):
            findings = self._scan_single_file(file_path, stats)
            all_findings.extend(findings)

        deduped = _deduplicate(all_findings)

        duration = time.monotonic() - start
        return ScanResult(
            target=str(target_path),
            findings=deduped,
            files_scanned=stats.scanned,
            files_skipped=stats.skipped,
            duration_s=round(duration, 3),
            errors=stats.errors,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _scan_single_file(self, file_path: Path, stats: _FileStats) -> list[RawFinding]:
        """Read a single file and run all applicable detectors on it."""
        # Read the raw bytes first — we need them for private-key detection
        # and content hashing.
        try:
            raw_bytes = file_path.read_bytes()
        except OSError as exc:
            stats.errors.append(f"read error: {file_path}: {exc}")
            stats.skipped += 1
            return []

        # Safety: if the file contains a private key, record metadata only.
        if _contains_private_key(raw_bytes):
            stats.skipped += 1
            return []

        # Decode to text.  Replace errors so we never crash on encoding issues.
        try:
            content = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            stats.skipped += 1
            return []

        # Content hash for future caching (not used for skipping yet — that
        # requires persistent storage, which is a Week 3 task).
        content_hash = hashlib.sha256(raw_bytes).hexdigest()
        self._content_hashes[str(file_path)] = content_hash

        file_str = str(file_path)
        findings: list[RawFinding] = []
        file_start = time.monotonic()

        for detector in self._detectors:
            # Respect per-file soft timeout.
            if time.monotonic() - file_start > _PER_FILE_SOFT_TIMEOUT_S:
                stats.errors.append(f"timeout: {file_path} (skipped remaining detectors)")
                break

            if not detector.can_handle(file_str):
                continue

            try:
                results = detector.scan_file(file_str, content)
                findings.extend(results)
            except Exception as exc:
                stats.errors.append(f"detector {detector.name} failed on {file_path}: {exc}")

        stats.scanned += 1

        if self._on_file_scanned is not None:
            self._on_file_scanned(file_path, len(findings))

        return findings


def _contains_private_key(raw: bytes) -> bool:
    """Return True if the first 4 KB contains a private key PEM header.

    We only check the beginning — private keys start at the top of the file.
    This avoids scanning the entire content of large files.
    """
    head = raw[:4096]
    return any(marker in head for marker in _PRIVATE_KEY_MARKERS)


def _deduplicate(findings: list[RawFinding]) -> list[RawFinding]:
    """Remove duplicate findings at the same location with the same algorithm.

    When multiple rules or detectors match the same crypto at the same
    file:line, keep the finding with the highest confidence.
    """
    best: dict[tuple[str, int, str], RawFinding] = {}
    for f in findings:
        key = (f.file_path, f.line_number, f.algorithm_family)
        existing = best.get(key)
        if existing is None or f.confidence > existing.confidence:
            best[key] = f
    return sorted(best.values(), key=lambda f: (f.file_path, f.line_number))
