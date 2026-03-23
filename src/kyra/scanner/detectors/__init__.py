"""Scanner detector plugins."""

from kyra.scanner.detectors.base import BaseDetector, RawFinding
from kyra.scanner.detectors.regex import RegexDetector

__all__ = ["BaseDetector", "RawFinding", "RegexDetector"]
