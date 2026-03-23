"""Base detector interface for scanner plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class RawFinding:
    """A raw cryptographic finding before CBOM structuring."""

    file_path: str
    line_number: int
    algorithm: str
    algorithm_family: str
    key_size: int | None
    usage_context: str
    confidence: float
    detected_by: str
    raw_match: str  # The matched text snippet


class BaseDetector(ABC):
    """Abstract base for all cryptographic detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Detector identifier (e.g., 'regex', 'ast-python', 'config-parser')."""
        ...

    @abstractmethod
    def scan_file(self, file_path: str, content: str) -> list[RawFinding]:
        """Scan a single file's content and return findings.

        Args:
            file_path: Path to the file being scanned.
            content: The file's text content (already read).

        Returns:
            List of raw findings detected in this file.
        """
        ...

    def can_handle(self, file_path: str) -> bool:
        """Return True if this detector should process the given file.

        Override in subclasses for file-type-specific detectors.
        Default: handle all files.
        """
        return True
