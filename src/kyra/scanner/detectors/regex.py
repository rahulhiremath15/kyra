"""Regex-based cryptographic pattern detector.

Loads rules from YAML files, compiles patterns once, and runs them against
file content to produce RawFinding objects.

This is the workhorse detector — language-agnostic, fast, and covers the
majority of common cryptographic patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from kyra.scanner.detectors.base import BaseDetector, RawFinding


@dataclass(frozen=True)
class RegexRule:
    """A single compiled detection rule."""

    id: str
    pattern: re.Pattern[str]
    algorithm_family: str
    confidence: float
    description: str
    # Maps semantic name → capture group index (e.g. {"key_size": 1}).
    capture_groups: dict[str, int]


class RegexDetector(BaseDetector):
    """Detects cryptographic usage via regex pattern matching.

    Rules are loaded from YAML files at construction time and compiled
    into ``re.Pattern`` objects for performance.  Each rule defines:

    - A regex pattern (YAML field ``pattern``)
    - An algorithm family (``algorithm_family``)
    - A confidence score (``confidence``)
    - Optional capture groups for extracting key sizes etc.
    """

    def __init__(self, rules_dirs: list[str | Path] | None = None) -> None:
        """Load and compile rules from *rules_dirs*.

        If *rules_dirs* is ``None``, uses the default rules shipped with KYRA
        (``scanner/rules/common/``).
        """
        if rules_dirs is None:
            default_dir = Path(__file__).resolve().parent.parent / "rules" / "common"
            rules_dirs = [default_dir]

        self._rules: list[RegexRule] = []
        for d in rules_dirs:
            self._load_rules_from_dir(Path(d))

    # ------------------------------------------------------------------
    # BaseDetector interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "regex"

    def scan_file(self, file_path: str, content: str) -> list[RawFinding]:
        """Run all compiled regex rules against *content*.

        Scans line-by-line to capture line numbers.  For each match the
        detector emits a ``RawFinding`` with the matched text, algorithm
        family, optional extracted key size, and confidence score.
        """
        findings: list[RawFinding] = []
        lines = content.splitlines()

        for line_number, line in enumerate(lines, start=1):
            for rule in self._rules:
                for m in rule.pattern.finditer(line):
                    key_size = self._extract_key_size(m, rule.capture_groups)
                    algorithm = self._build_algorithm_label(rule.algorithm_family, key_size)

                    findings.append(
                        RawFinding(
                            file_path=file_path,
                            line_number=line_number,
                            algorithm=algorithm,
                            algorithm_family=rule.algorithm_family,
                            key_size=key_size,
                            usage_context=rule.description,
                            confidence=rule.confidence,
                            detected_by=self.name,
                            raw_match=m.group(0),
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _load_rules_from_dir(self, directory: Path) -> None:
        """Load every YAML file in *directory* and compile rules."""
        if not directory.is_dir():
            return
        for yaml_file in sorted(directory.glob("*.yaml")):
            self._load_rules_file(yaml_file)

    def _load_rules_file(self, path: Path) -> None:
        """Parse a single YAML rules file and append compiled rules."""
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return

        raw = yaml.safe_load(text)
        if not isinstance(raw, list):
            return

        for entry in raw:
            rule = self._compile_rule(entry)
            if rule is not None:
                self._rules.append(rule)

    @staticmethod
    def _compile_rule(entry: dict[str, Any]) -> RegexRule | None:
        """Compile a single YAML rule dict into a RegexRule.

        Returns ``None`` if the rule is malformed or the regex fails to
        compile, logging the issue rather than crashing the scanner.
        """
        required = ("id", "pattern", "algorithm_family", "confidence")
        if not all(k in entry for k in required):
            return None

        try:
            compiled = re.compile(entry["pattern"])
        except re.error:
            # Bad regex in a rule file should not crash the scanner.
            return None

        capture_groups: dict[str, int] = {}
        if "capture_groups" in entry and isinstance(entry["capture_groups"], dict):
            for name, group_idx in entry["capture_groups"].items():
                if isinstance(group_idx, int):
                    capture_groups[name] = group_idx

        return RegexRule(
            id=entry["id"],
            pattern=compiled,
            algorithm_family=entry["algorithm_family"],
            confidence=entry["confidence"],
            description=entry.get("description", ""),
            capture_groups=capture_groups,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_key_size(match: re.Match[str], capture_groups: dict[str, int]) -> int | None:
        """Pull a key_size integer out of a regex match, if the rule defines one."""
        group_idx = capture_groups.get("key_size")
        if group_idx is None:
            return None
        try:
            raw = match.group(group_idx)
            if raw is not None:
                return int(raw)
        except (IndexError, ValueError, TypeError):
            pass
        return None

    @staticmethod
    def _build_algorithm_label(family: str, key_size: int | None) -> str:
        """Build a human-readable algorithm string like 'RSA-2048'."""
        if key_size is not None:
            return f"{family}-{key_size}"
        return family

    # ------------------------------------------------------------------
    # Introspection (useful for tests and debugging)
    # ------------------------------------------------------------------

    @property
    def rules(self) -> list[RegexRule]:
        """Return loaded rules (read-only access)."""
        return list(self._rules)

    @property
    def rule_count(self) -> int:
        return len(self._rules)
