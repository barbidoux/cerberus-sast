"""
Feedback Loop for Phase II spec updates.

Analyzes FALSE_POSITIVE verdicts to extract missed sanitizers
and other spec corrections for improved future detection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cerberus.models.base import TaintLabel, Verdict
from cerberus.models.finding import Finding
from cerberus.models.spec import TaintSpec


@dataclass
class FeedbackConfig:
    """Configuration for the Feedback Loop."""

    min_confidence: float = 0.5  # Minimum confidence for extracting updates
    extract_sanitizers: bool = True
    extract_sources: bool = False  # Future: extract missed sources
    extract_sinks: bool = False  # Future: extract missed sinks


@dataclass
class SpecUpdate:
    """Updates to be applied to Phase II specifications."""

    sanitizers: list[TaintSpec] = field(default_factory=list)
    sources: list[TaintSpec] = field(default_factory=list)
    sinks: list[TaintSpec] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Get total number of updates."""
        return len(self.sanitizers) + len(self.sources) + len(self.sinks)


@dataclass
class FeedbackResult:
    """Result from feedback analysis."""

    success: bool
    updates: SpecUpdate = field(default_factory=SpecUpdate)
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def update_count(self) -> int:
        """Get total number of updates."""
        return self.updates.total


class FeedbackLoop:
    """
    Feedback Loop for improving Phase II specifications.

    Analyzes FALSE_POSITIVE verdicts from the Council to extract:
    - Missed sanitizers that should be added to specs
    - Other corrections for improved detection
    """

    def __init__(
        self,
        config: Optional[FeedbackConfig] = None,
    ) -> None:
        """
        Initialize the Feedback Loop.

        Args:
            config: Feedback configuration.
        """
        self.config = config or FeedbackConfig()

    def analyze(self, finding: Finding) -> FeedbackResult:
        """
        Analyze a finding for spec updates.

        Args:
            finding: The finding to analyze.

        Returns:
            FeedbackResult with extracted spec updates.
        """
        updates = SpecUpdate()

        # Skip unverified or non-FALSE_POSITIVE findings
        if not finding.verification:
            return FeedbackResult(success=True, updates=updates)

        if finding.verification.verdict != Verdict.FALSE_POSITIVE:
            return FeedbackResult(success=True, updates=updates)

        # Skip low confidence verdicts
        if finding.verification.confidence < self.config.min_confidence:
            return FeedbackResult(success=True, updates=updates)

        # Extract sanitizers from defender's defense
        if self.config.extract_sanitizers:
            sanitizers = self._extract_sanitizers(finding)
            updates.sanitizers.extend(sanitizers)

        return FeedbackResult(
            success=True,
            updates=updates,
            metadata={
                "verdict": finding.verification.verdict.value,
                "confidence": finding.verification.confidence,
            },
        )

    def analyze_batch(self, findings: list[Finding]) -> FeedbackResult:
        """
        Analyze multiple findings and combine updates.

        Args:
            findings: List of findings to analyze.

        Returns:
            Combined FeedbackResult with deduplicated updates.
        """
        combined_updates = SpecUpdate()
        seen_sanitizers: set[tuple[str, int]] = set()

        for finding in findings:
            result = self.analyze(finding)
            if not result.success:
                continue

            # Add sanitizers, avoiding duplicates
            for sanitizer in result.updates.sanitizers:
                key = (sanitizer.method, sanitizer.line)
                if key not in seen_sanitizers:
                    seen_sanitizers.add(key)
                    combined_updates.sanitizers.append(sanitizer)

        return FeedbackResult(
            success=True,
            updates=combined_updates,
            metadata={"findings_analyzed": len(findings)},
        )

    def _extract_sanitizers(self, finding: Finding) -> list[TaintSpec]:
        """
        Extract sanitizer specs from a FALSE_POSITIVE finding.

        Uses:
        - Defender's defense_lines
        - Defender's sanitization description
        - Judge's missed_considerations
        - Code slice at defense lines

        Args:
            finding: The finding to extract from.

        Returns:
            List of TaintSpec for discovered sanitizers.
        """
        sanitizers: list[TaintSpec] = []
        verification = finding.verification

        # Get defense lines and file path
        defense_lines = verification.defender_lines or []
        file_path = self._get_file_path(finding)

        # Try to extract method names from defender reasoning
        method_names = self._extract_method_names(
            verification.defender_sanitization or "",
            verification.defender_reasoning,
            verification.missed_considerations or "",
        )

        # Create sanitizer specs for each defense line
        for line in defense_lines:
            # Try to find method name at this line from the slice
            method_name = self._find_method_at_line(finding, line)
            if not method_name and method_names:
                method_name = method_names[0]
            if not method_name:
                method_name = f"sanitizer_line_{line}"

            sanitizer = TaintSpec(
                method=method_name,
                file_path=file_path,
                line=line,
                label=TaintLabel.SANITIZER,
                confidence=verification.confidence * 0.9,  # Slightly lower confidence
                reason=f"Extracted from FALSE_POSITIVE: {verification.defender_sanitization}",
                vulnerability_types=[finding.vulnerability_type],
            )
            sanitizers.append(sanitizer)

        return sanitizers

    def _extract_method_names(self, *texts: str) -> list[str]:
        """
        Extract method names from text descriptions.

        Looks for patterns like:
        - function_name()
        - method_name at line
        - using function_name

        Args:
            texts: Text strings to extract from.

        Returns:
            List of extracted method names.
        """
        method_names: list[str] = []

        for text in texts:
            # Pattern: function_name()
            matches = re.findall(r'(\w+)\s*\(', text)
            method_names.extend(matches)

            # Pattern: function_name at line
            matches = re.findall(r'(\w+)\s+at\s+line', text, re.IGNORECASE)
            method_names.extend(matches)

            # Pattern: using function_name
            matches = re.findall(r'using\s+(\w+)', text, re.IGNORECASE)
            method_names.extend(matches)

        # Filter out common non-method words
        stopwords = {"line", "at", "the", "is", "in", "was", "not"}
        return [m for m in method_names if m.lower() not in stopwords]

    def _find_method_at_line(self, finding: Finding, line: int) -> Optional[str]:
        """
        Find method name at a specific line from the slice.

        Args:
            finding: The finding with code slice.
            line: The line number to check.

        Returns:
            Method name if found, None otherwise.
        """
        if not finding.slice:
            return None

        for trace_line in finding.slice.trace_lines:
            if trace_line.line_number == line:
                # Try to extract function call from code
                matches = re.findall(r'(\w+)\s*\(', trace_line.code)
                if matches:
                    # Return the first function call that isn't a common keyword
                    for match in matches:
                        if match.lower() not in {"if", "for", "while", "return", "print"}:
                            return match

        return None

    def _get_file_path(self, finding: Finding) -> Path:
        """Get file path from finding."""
        if finding.slice:
            return finding.slice.file_path
        if finding.trace:
            return finding.trace[0].location.file_path
        return Path("unknown")
