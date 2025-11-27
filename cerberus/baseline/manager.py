"""
Baseline Manager for Cerberus SAST.

Manages baselines of findings for comparing scan results.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cerberus.models.finding import Finding


@dataclass
class BaselineConfig:
    """Configuration for baseline management."""

    # Fingerprinting settings
    use_file_path: bool = True
    use_line_number: bool = False  # Line numbers can shift
    use_vulnerability_type: bool = True
    use_method_names: bool = True

    # Comparison settings
    ignore_false_positives: bool = True


@dataclass
class BaselineEntry:
    """
    Single entry in a baseline.

    Represents a fingerprint of a finding for comparison.
    """

    fingerprint: str
    vulnerability_type: str
    file_path: str
    source_method: Optional[str] = None
    sink_method: Optional[str] = None
    severity: str = "unknown"
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "active"  # active, resolved, suppressed
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "fingerprint": self.fingerprint,
            "vulnerability_type": self.vulnerability_type,
            "file_path": self.file_path,
            "source_method": self.source_method,
            "sink_method": self.sink_method,
            "severity": self.severity,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "status": self.status,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BaselineEntry":
        """Deserialize from dictionary."""
        return cls(
            fingerprint=data["fingerprint"],
            vulnerability_type=data["vulnerability_type"],
            file_path=data["file_path"],
            source_method=data.get("source_method"),
            sink_method=data.get("sink_method"),
            severity=data.get("severity", "unknown"),
            first_seen=datetime.fromisoformat(data["first_seen"]) if "first_seen" in data else datetime.now(timezone.utc),
            last_seen=datetime.fromisoformat(data["last_seen"]) if "last_seen" in data else datetime.now(timezone.utc),
            status=data.get("status", "active"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Baseline:
    """
    Collection of baseline entries.

    Represents a snapshot of findings at a point in time.
    """

    name: str
    repository: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    entries: dict[str, BaselineEntry] = field(default_factory=dict)
    version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def count(self) -> int:
        """Get number of entries."""
        return len(self.entries)

    @property
    def active_count(self) -> int:
        """Get number of active entries."""
        return sum(1 for e in self.entries.values() if e.status == "active")

    def add_entry(self, entry: BaselineEntry) -> None:
        """Add an entry to the baseline."""
        self.entries[entry.fingerprint] = entry
        self.updated_at = datetime.now(timezone.utc)

    def has_entry(self, fingerprint: str) -> bool:
        """Check if fingerprint exists in baseline."""
        return fingerprint in self.entries

    def get_entry(self, fingerprint: str) -> Optional[BaselineEntry]:
        """Get entry by fingerprint."""
        return self.entries.get(fingerprint)

    def remove_entry(self, fingerprint: str) -> bool:
        """Remove entry from baseline."""
        if fingerprint in self.entries:
            del self.entries[fingerprint]
            self.updated_at = datetime.now(timezone.utc)
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "repository": self.repository,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version,
            "entries": {k: v.to_dict() for k, v in self.entries.items()},
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Baseline":
        """Deserialize from dictionary."""
        entries = {
            k: BaselineEntry.from_dict(v)
            for k, v in data.get("entries", {}).items()
        }
        return cls(
            name=data["name"],
            repository=data["repository"],
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(timezone.utc),
            updated_at=datetime.fromisoformat(data["updated_at"]) if "updated_at" in data else datetime.now(timezone.utc),
            version=data.get("version", "1.0"),
            entries=entries,
            metadata=data.get("metadata", {}),
        )

    def save(self, path: Path) -> None:
        """Save baseline to file."""
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> "Baseline":
        """Load baseline from file."""
        data = json.loads(path.read_text())
        return cls.from_dict(data)


@dataclass
class BaselineDiff:
    """
    Difference between current findings and baseline.
    """

    new_findings: list[Finding] = field(default_factory=list)
    existing_findings: list[Finding] = field(default_factory=list)
    resolved_fingerprints: list[str] = field(default_factory=list)

    @property
    def new_count(self) -> int:
        """Number of new findings."""
        return len(self.new_findings)

    @property
    def existing_count(self) -> int:
        """Number of existing findings."""
        return len(self.existing_findings)

    @property
    def resolved_count(self) -> int:
        """Number of resolved findings."""
        return len(self.resolved_fingerprints)

    @property
    def has_new(self) -> bool:
        """Check if there are new findings."""
        return self.new_count > 0


class BaselineManager:
    """
    Manages baseline operations.

    Handles:
    - Fingerprinting findings
    - Creating baselines from scan results
    - Comparing findings against baselines
    - Updating baselines
    """

    def __init__(self, config: Optional[BaselineConfig] = None) -> None:
        """
        Initialize the baseline manager.

        Args:
            config: Baseline configuration.
        """
        self.config = config or BaselineConfig()

    def fingerprint(self, finding: Finding) -> str:
        """
        Generate a fingerprint for a finding.

        Args:
            finding: The finding to fingerprint.

        Returns:
            SHA256 hash fingerprint.
        """
        parts = []

        if self.config.use_vulnerability_type:
            parts.append(f"type:{finding.vulnerability_type}")

        if self.config.use_file_path:
            if finding.sink:
                parts.append(f"sink_file:{finding.sink.file_path}")
            elif finding.source:
                parts.append(f"source_file:{finding.source.file_path}")

        if self.config.use_line_number:
            if finding.sink:
                parts.append(f"sink_line:{finding.sink.line}")

        if self.config.use_method_names:
            if finding.source:
                parts.append(f"source:{finding.source.method}")
            if finding.sink:
                parts.append(f"sink:{finding.sink.method}")

        fingerprint_string = "|".join(sorted(parts))
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]

    def create_baseline(
        self,
        name: str,
        repository: str,
        findings: list[Finding],
    ) -> Baseline:
        """
        Create a baseline from findings.

        Args:
            name: Baseline name.
            repository: Repository name.
            findings: List of findings to baseline.

        Returns:
            New Baseline instance.
        """
        baseline = Baseline(name=name, repository=repository)

        for finding in findings:
            # Skip false positives if configured
            if self.config.ignore_false_positives:
                if finding.verification and finding.verification.is_false_positive:
                    continue

            fingerprint = self.fingerprint(finding)
            severity = finding.severity if isinstance(finding.severity, str) else finding.severity.value

            entry = BaselineEntry(
                fingerprint=fingerprint,
                vulnerability_type=finding.vulnerability_type,
                file_path=str(finding.sink.file_path if finding.sink else "unknown"),
                source_method=finding.source.method if finding.source else None,
                sink_method=finding.sink.method if finding.sink else None,
                severity=severity,
            )
            baseline.add_entry(entry)

        return baseline

    def compare(
        self,
        findings: list[Finding],
        baseline: Baseline,
    ) -> BaselineDiff:
        """
        Compare findings against a baseline.

        Args:
            findings: Current findings.
            baseline: Baseline to compare against.

        Returns:
            BaselineDiff showing new vs. existing.
        """
        diff = BaselineDiff()
        current_fingerprints: set[str] = set()

        for finding in findings:
            # Skip false positives if configured
            if self.config.ignore_false_positives:
                if finding.verification and finding.verification.is_false_positive:
                    continue

            fingerprint = self.fingerprint(finding)
            current_fingerprints.add(fingerprint)

            if baseline.has_entry(fingerprint):
                # Existing finding - update last_seen
                entry = baseline.get_entry(fingerprint)
                if entry:
                    entry.last_seen = datetime.now(timezone.utc)
                diff.existing_findings.append(finding)
            else:
                diff.new_findings.append(finding)

        # Find resolved (in baseline but not in current)
        for fingerprint in baseline.entries:
            if fingerprint not in current_fingerprints:
                entry = baseline.entries[fingerprint]
                if entry.status == "active":
                    diff.resolved_fingerprints.append(fingerprint)

        return diff

    def update_baseline(
        self,
        baseline: Baseline,
        findings: list[Finding],
        mark_resolved: bool = True,
    ) -> Baseline:
        """
        Update a baseline with new findings.

        Args:
            baseline: Baseline to update.
            findings: Current findings.
            mark_resolved: Whether to mark missing entries as resolved.

        Returns:
            Updated baseline.
        """
        current_fingerprints: set[str] = set()

        for finding in findings:
            # Skip false positives if configured
            if self.config.ignore_false_positives:
                if finding.verification and finding.verification.is_false_positive:
                    continue

            fingerprint = self.fingerprint(finding)
            current_fingerprints.add(fingerprint)

            if baseline.has_entry(fingerprint):
                # Update last_seen
                entry = baseline.get_entry(fingerprint)
                if entry:
                    entry.last_seen = datetime.now(timezone.utc)
                    entry.status = "active"
            else:
                # New entry
                severity = finding.severity if isinstance(finding.severity, str) else finding.severity.value
                entry = BaselineEntry(
                    fingerprint=fingerprint,
                    vulnerability_type=finding.vulnerability_type,
                    file_path=str(finding.sink.file_path if finding.sink else "unknown"),
                    source_method=finding.source.method if finding.source else None,
                    sink_method=finding.sink.method if finding.sink else None,
                    severity=severity,
                )
                baseline.add_entry(entry)

        # Mark resolved
        if mark_resolved:
            for fingerprint, entry in baseline.entries.items():
                if fingerprint not in current_fingerprints:
                    entry.status = "resolved"

        baseline.updated_at = datetime.now(timezone.utc)
        return baseline
