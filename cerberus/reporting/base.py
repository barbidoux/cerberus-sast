"""
Base Reporter for Cerberus SAST.

Provides the abstract base class for all report formatters.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cerberus.models.finding import Finding, ScanResult


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    include_code_snippets: bool = True
    include_verification: bool = True
    include_trace: bool = True
    max_findings: Optional[int] = None  # None = all findings
    min_severity: Optional[str] = None  # Filter by minimum severity
    min_confidence: float = 0.0  # Filter by minimum confidence
    output_path: Optional[Path] = None


@dataclass
class ReportMetadata:
    """Metadata for the report."""

    tool_name: str = "Cerberus SAST"
    tool_version: str = "1.0.0"
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: Optional[str] = None
    repository: Optional[str] = None
    custom: dict[str, Any] = field(default_factory=dict)


class BaseReporter(ABC):
    """
    Abstract base class for report generators.

    Subclasses implement specific output formats (SARIF, JSON, HTML, etc.).
    """

    def __init__(
        self,
        config: Optional[ReportConfig] = None,
        metadata: Optional[ReportMetadata] = None,
    ) -> None:
        """
        Initialize the reporter.

        Args:
            config: Report configuration.
            metadata: Report metadata.
        """
        self.config = config or ReportConfig()
        self.metadata = metadata or ReportMetadata()

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Get the format name (e.g., 'sarif', 'json', 'html')."""
        ...

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Get the default file extension (e.g., '.sarif', '.json', '.html')."""
        ...

    @abstractmethod
    def generate(self, scan_result: ScanResult) -> str:
        """
        Generate the report content.

        Args:
            scan_result: The scan result to report.

        Returns:
            The report as a string.
        """
        ...

    def write(self, scan_result: ScanResult, output_path: Optional[Path] = None) -> Path:
        """
        Generate and write the report to a file.

        Args:
            scan_result: The scan result to report.
            output_path: Output file path. If None, uses config or generates default.

        Returns:
            The path to the written file.
        """
        path = output_path or self.config.output_path
        if path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = Path(f"cerberus_report_{timestamp}{self.file_extension}")

        content = self.generate(scan_result)
        path.write_text(content, encoding="utf-8")

        return path

    def filter_findings(self, findings: list[Finding]) -> list[Finding]:
        """
        Filter findings based on configuration.

        Args:
            findings: List of findings to filter.

        Returns:
            Filtered list of findings.
        """
        filtered = findings

        # Filter by minimum severity
        if self.config.min_severity:
            severity_order = ["critical", "high", "medium", "low", "info"]
            min_idx = severity_order.index(self.config.min_severity.lower())
            filtered = [
                f for f in filtered
                if self._get_severity_index(f) <= min_idx
            ]

        # Filter by minimum confidence
        if self.config.min_confidence > 0:
            filtered = [
                f for f in filtered
                if self._get_confidence(f) >= self.config.min_confidence
            ]

        # Limit number of findings
        if self.config.max_findings is not None:
            filtered = filtered[:self.config.max_findings]

        return filtered

    def _get_severity_index(self, finding: Finding) -> int:
        """Get severity index for comparison."""
        severity_order = ["critical", "high", "medium", "low", "info"]
        sev = finding.severity.lower() if isinstance(finding.severity, str) else finding.severity.value.lower()
        try:
            return severity_order.index(sev)
        except ValueError:
            return len(severity_order)  # Unknown severity at end

    def _get_confidence(self, finding: Finding) -> float:
        """Get confidence score for a finding."""
        if finding.verification:
            return finding.verification.confidence
        return 1.0  # Unverified findings treated as high confidence


class ReporterRegistry:
    """Registry for available reporters."""

    _reporters: dict[str, type[BaseReporter]] = {}

    @classmethod
    def register(cls, name: str) -> Any:
        """Decorator to register a reporter."""
        def decorator(reporter_class: type[BaseReporter]) -> type[BaseReporter]:
            cls._reporters[name] = reporter_class
            return reporter_class
        return decorator

    @classmethod
    def get(cls, name: str) -> Optional[type[BaseReporter]]:
        """Get a reporter by name."""
        return cls._reporters.get(name)

    @classmethod
    def list_formats(cls) -> list[str]:
        """List available format names."""
        return list(cls._reporters.keys())

    @classmethod
    def create(
        cls,
        name: str,
        config: Optional[ReportConfig] = None,
        metadata: Optional[ReportMetadata] = None,
    ) -> Optional[BaseReporter]:
        """Create a reporter instance by name."""
        reporter_class = cls.get(name)
        if reporter_class:
            return reporter_class(config=config, metadata=metadata)
        return None
