"""Tests for the baseline manager."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cerberus.baseline import (
    Baseline,
    BaselineConfig,
    BaselineDiff,
    BaselineEntry,
    BaselineManager,
)
from cerberus.models.base import TaintLabel, Verdict
from cerberus.models.finding import Finding, VerificationResult
from cerberus.models.spec import TaintSpec


@pytest.fixture
def sample_source() -> TaintSpec:
    """Create a sample source spec."""
    return TaintSpec(
        method="get_user_input",
        file_path=Path("src/input.py"),
        line=10,
        label=TaintLabel.SOURCE,
    )


@pytest.fixture
def sample_sink() -> TaintSpec:
    """Create a sample sink spec."""
    return TaintSpec(
        method="execute_query",
        file_path=Path("src/db.py"),
        line=50,
        label=TaintLabel.SINK,
    )


@pytest.fixture
def sample_finding(sample_source: TaintSpec, sample_sink: TaintSpec) -> Finding:
    """Create a sample finding."""
    return Finding(
        vulnerability_type="SQL_INJECTION",
        severity="high",
        description="SQL injection vulnerability",
        source=sample_source,
        sink=sample_sink,
    )


@pytest.fixture
def verified_finding(sample_finding: Finding) -> Finding:
    """Create a verified finding."""
    sample_finding.verification = VerificationResult(
        verdict=Verdict.TRUE_POSITIVE,
        confidence=0.9,
        attacker_exploitable=True,
        attacker_input="'; DROP TABLE users; --",
        attacker_trace="Input passed to query without sanitization",
        attacker_impact="Database compromise",
        attacker_reasoning="Input flows directly to query",
        defender_safe=False,
        defender_lines=[],
        defender_sanitization=None,
        defender_reasoning="No sanitization found",
        judge_reasoning="Clear vulnerability",
    )
    return sample_finding


@pytest.fixture
def false_positive_finding() -> Finding:
    """Create a false positive finding with different source/sink."""
    # Use different source and sink for different fingerprint
    source = TaintSpec(
        method="get_params",
        file_path=Path("src/params.py"),
        line=20,
        label=TaintLabel.SOURCE,
    )
    sink = TaintSpec(
        method="run_command",
        file_path=Path("src/exec.py"),
        line=100,
        label=TaintLabel.SINK,
    )
    finding = Finding(
        vulnerability_type="COMMAND_INJECTION",
        severity="high",
        description="Command injection (false positive)",
        source=source,
        sink=sink,
    )
    finding.verification = VerificationResult(
        verdict=Verdict.FALSE_POSITIVE,
        confidence=0.85,
        attacker_exploitable=False,
        attacker_input=None,
        attacker_trace=None,
        attacker_impact=None,
        attacker_reasoning="Input is sanitized",
        defender_safe=True,
        defender_lines=[25],
        defender_sanitization="Parameterized query used",
        defender_reasoning="Parameterized query used",
        judge_reasoning="Safe code pattern",
    )
    return finding


class TestBaselineConfig:
    """Test BaselineConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = BaselineConfig()

        assert config.use_file_path is True
        assert config.use_line_number is False
        assert config.use_vulnerability_type is True
        assert config.use_method_names is True
        assert config.ignore_false_positives is True

    def test_custom_config(self):
        """Should accept custom values."""
        config = BaselineConfig(
            use_line_number=True,
            ignore_false_positives=False,
        )

        assert config.use_line_number is True
        assert config.ignore_false_positives is False


class TestBaselineEntry:
    """Test BaselineEntry."""

    def test_create_entry(self):
        """Should create entry with defaults."""
        entry = BaselineEntry(
            fingerprint="abc123",
            vulnerability_type="SQL_INJECTION",
            file_path="src/db.py",
        )

        assert entry.fingerprint == "abc123"
        assert entry.vulnerability_type == "SQL_INJECTION"
        assert entry.file_path == "src/db.py"
        assert entry.status == "active"
        assert entry.severity == "unknown"

    def test_entry_to_dict(self):
        """Should serialize to dictionary."""
        entry = BaselineEntry(
            fingerprint="abc123",
            vulnerability_type="SQL_INJECTION",
            file_path="src/db.py",
            source_method="get_input",
            sink_method="execute",
            severity="high",
        )

        data = entry.to_dict()

        assert data["fingerprint"] == "abc123"
        assert data["vulnerability_type"] == "SQL_INJECTION"
        assert data["file_path"] == "src/db.py"
        assert data["source_method"] == "get_input"
        assert data["sink_method"] == "execute"
        assert data["severity"] == "high"
        assert "first_seen" in data
        assert "last_seen" in data

    def test_entry_from_dict(self):
        """Should deserialize from dictionary."""
        data = {
            "fingerprint": "abc123",
            "vulnerability_type": "SQL_INJECTION",
            "file_path": "src/db.py",
            "source_method": "get_input",
            "sink_method": "execute",
            "severity": "high",
            "status": "resolved",
            "first_seen": "2024-01-01T00:00:00+00:00",
            "last_seen": "2024-01-02T00:00:00+00:00",
        }

        entry = BaselineEntry.from_dict(data)

        assert entry.fingerprint == "abc123"
        assert entry.vulnerability_type == "SQL_INJECTION"
        assert entry.status == "resolved"

    def test_entry_roundtrip(self):
        """Should survive serialization roundtrip."""
        original = BaselineEntry(
            fingerprint="xyz789",
            vulnerability_type="XSS",
            file_path="src/template.py",
            source_method="get_param",
            sink_method="render",
            severity="medium",
            metadata={"extra": "info"},
        )

        data = original.to_dict()
        restored = BaselineEntry.from_dict(data)

        assert restored.fingerprint == original.fingerprint
        assert restored.vulnerability_type == original.vulnerability_type
        assert restored.file_path == original.file_path
        assert restored.source_method == original.source_method
        assert restored.sink_method == original.sink_method
        assert restored.severity == original.severity
        assert restored.metadata == original.metadata


class TestBaseline:
    """Test Baseline."""

    def test_create_baseline(self):
        """Should create baseline with defaults."""
        baseline = Baseline(name="test", repository="my-repo")

        assert baseline.name == "test"
        assert baseline.repository == "my-repo"
        assert baseline.count == 0
        assert baseline.version == "1.0"

    def test_add_entry(self):
        """Should add entries."""
        baseline = Baseline(name="test", repository="my-repo")
        entry = BaselineEntry(
            fingerprint="abc123",
            vulnerability_type="SQL_INJECTION",
            file_path="src/db.py",
        )

        baseline.add_entry(entry)

        assert baseline.count == 1
        assert baseline.has_entry("abc123")

    def test_get_entry(self):
        """Should retrieve entry by fingerprint."""
        baseline = Baseline(name="test", repository="my-repo")
        entry = BaselineEntry(
            fingerprint="abc123",
            vulnerability_type="SQL_INJECTION",
            file_path="src/db.py",
        )
        baseline.add_entry(entry)

        retrieved = baseline.get_entry("abc123")

        assert retrieved is not None
        assert retrieved.fingerprint == "abc123"

    def test_get_nonexistent_entry(self):
        """Should return None for missing fingerprint."""
        baseline = Baseline(name="test", repository="my-repo")

        result = baseline.get_entry("nonexistent")

        assert result is None

    def test_remove_entry(self):
        """Should remove entry."""
        baseline = Baseline(name="test", repository="my-repo")
        entry = BaselineEntry(
            fingerprint="abc123",
            vulnerability_type="SQL_INJECTION",
            file_path="src/db.py",
        )
        baseline.add_entry(entry)

        result = baseline.remove_entry("abc123")

        assert result is True
        assert baseline.count == 0
        assert not baseline.has_entry("abc123")

    def test_remove_nonexistent(self):
        """Should return False when removing nonexistent."""
        baseline = Baseline(name="test", repository="my-repo")

        result = baseline.remove_entry("nonexistent")

        assert result is False

    def test_active_count(self):
        """Should count only active entries."""
        baseline = Baseline(name="test", repository="my-repo")
        baseline.add_entry(BaselineEntry(
            fingerprint="a",
            vulnerability_type="SQL_INJECTION",
            file_path="a.py",
            status="active",
        ))
        baseline.add_entry(BaselineEntry(
            fingerprint="b",
            vulnerability_type="XSS",
            file_path="b.py",
            status="resolved",
        ))
        baseline.add_entry(BaselineEntry(
            fingerprint="c",
            vulnerability_type="RCE",
            file_path="c.py",
            status="active",
        ))

        assert baseline.count == 3
        assert baseline.active_count == 2

    def test_baseline_to_dict(self):
        """Should serialize baseline."""
        baseline = Baseline(name="test", repository="my-repo")
        baseline.add_entry(BaselineEntry(
            fingerprint="abc123",
            vulnerability_type="SQL_INJECTION",
            file_path="src/db.py",
        ))

        data = baseline.to_dict()

        assert data["name"] == "test"
        assert data["repository"] == "my-repo"
        assert "abc123" in data["entries"]

    def test_baseline_from_dict(self):
        """Should deserialize baseline."""
        data = {
            "name": "test",
            "repository": "my-repo",
            "version": "1.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "updated_at": "2024-01-02T00:00:00+00:00",
            "entries": {
                "abc123": {
                    "fingerprint": "abc123",
                    "vulnerability_type": "SQL_INJECTION",
                    "file_path": "src/db.py",
                    "first_seen": "2024-01-01T00:00:00+00:00",
                    "last_seen": "2024-01-01T00:00:00+00:00",
                }
            },
        }

        baseline = Baseline.from_dict(data)

        assert baseline.name == "test"
        assert baseline.repository == "my-repo"
        assert baseline.count == 1

    def test_save_and_load(self):
        """Should save and load from file."""
        baseline = Baseline(name="test", repository="my-repo")
        baseline.add_entry(BaselineEntry(
            fingerprint="abc123",
            vulnerability_type="SQL_INJECTION",
            file_path="src/db.py",
        ))

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)

        try:
            baseline.save(path)
            loaded = Baseline.load(path)

            assert loaded.name == baseline.name
            assert loaded.repository == baseline.repository
            assert loaded.count == baseline.count
            assert loaded.has_entry("abc123")
        finally:
            path.unlink()


class TestBaselineDiff:
    """Test BaselineDiff."""

    def test_empty_diff(self):
        """Should handle empty diff."""
        diff = BaselineDiff()

        assert diff.new_count == 0
        assert diff.existing_count == 0
        assert diff.resolved_count == 0
        assert diff.has_new is False

    def test_diff_counts(self, sample_finding: Finding):
        """Should calculate counts correctly."""
        diff = BaselineDiff(
            new_findings=[sample_finding, sample_finding],
            existing_findings=[sample_finding],
            resolved_fingerprints=["a", "b", "c"],
        )

        assert diff.new_count == 2
        assert diff.existing_count == 1
        assert diff.resolved_count == 3
        assert diff.has_new is True


class TestBaselineManager:
    """Test BaselineManager."""

    def test_create_manager(self):
        """Should create manager with defaults."""
        manager = BaselineManager()

        assert manager.config is not None
        assert manager.config.use_file_path is True

    def test_create_with_config(self):
        """Should accept custom config."""
        config = BaselineConfig(use_line_number=True)
        manager = BaselineManager(config=config)

        assert manager.config.use_line_number is True


class TestFingerprinting:
    """Test fingerprint generation."""

    def test_fingerprint_basic(self, sample_finding: Finding):
        """Should generate fingerprint."""
        manager = BaselineManager()
        fingerprint = manager.fingerprint(sample_finding)

        assert len(fingerprint) == 16  # SHA256 truncated to 16 chars
        assert fingerprint.isalnum()

    def test_fingerprint_deterministic(self, sample_finding: Finding):
        """Should generate same fingerprint for same finding."""
        manager = BaselineManager()
        fp1 = manager.fingerprint(sample_finding)
        fp2 = manager.fingerprint(sample_finding)

        assert fp1 == fp2

    def test_fingerprint_different_for_different_type(
        self, sample_source: TaintSpec, sample_sink: TaintSpec
    ):
        """Should generate different fingerprint for different vulnerability type."""
        manager = BaselineManager()
        finding1 = Finding(
            vulnerability_type="SQL_INJECTION",
            severity="high",
            description="SQL injection",
            source=sample_source,
            sink=sample_sink,
        )
        finding2 = Finding(
            vulnerability_type="XSS",
            severity="high",
            description="XSS",
            source=sample_source,
            sink=sample_sink,
        )

        fp1 = manager.fingerprint(finding1)
        fp2 = manager.fingerprint(finding2)

        assert fp1 != fp2

    def test_fingerprint_without_line_number(self, sample_finding: Finding):
        """Should not include line number by default."""
        config = BaselineConfig(use_line_number=False)
        manager = BaselineManager(config=config)

        # Modify line number
        original_fp = manager.fingerprint(sample_finding)
        sample_finding.sink.line = 999
        modified_fp = manager.fingerprint(sample_finding)

        assert original_fp == modified_fp

    def test_fingerprint_with_line_number(self, sample_finding: Finding):
        """Should include line number when configured."""
        config = BaselineConfig(use_line_number=True)
        manager = BaselineManager(config=config)

        original_fp = manager.fingerprint(sample_finding)
        original_line = sample_finding.sink.line
        sample_finding.sink.line = 999
        modified_fp = manager.fingerprint(sample_finding)

        assert original_fp != modified_fp

        # Restore
        sample_finding.sink.line = original_line


class TestCreateBaseline:
    """Test baseline creation from findings."""

    def test_create_from_findings(
        self, sample_finding: Finding, verified_finding: Finding
    ):
        """Should create baseline from findings."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding, verified_finding],
        )

        assert baseline.name == "test"
        assert baseline.repository == "my-repo"
        assert baseline.count >= 1

    def test_create_ignores_false_positives(
        self, sample_finding: Finding, false_positive_finding: Finding
    ):
        """Should ignore false positives by default."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding, false_positive_finding],
        )

        # Only one finding should be added (false positive ignored)
        assert baseline.count == 1

    def test_create_includes_false_positives_when_configured(
        self, sample_finding: Finding, false_positive_finding: Finding
    ):
        """Should include false positives when configured."""
        config = BaselineConfig(ignore_false_positives=False)
        manager = BaselineManager(config=config)
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding, false_positive_finding],
        )

        # Both findings should be added
        assert baseline.count == 2

    def test_create_with_metadata(self, sample_finding: Finding):
        """Should include finding metadata in entry."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding],
        )

        # Find the entry
        entry = list(baseline.entries.values())[0]
        assert entry.vulnerability_type == "SQL_INJECTION"
        assert entry.source_method == "get_user_input"
        assert entry.sink_method == "execute_query"


class TestCompareBaseline:
    """Test comparing findings against baseline."""

    def test_compare_identifies_new(self, sample_finding: Finding):
        """Should identify new findings."""
        manager = BaselineManager()
        baseline = Baseline(name="test", repository="my-repo")  # Empty baseline

        diff = manager.compare([sample_finding], baseline)

        assert diff.new_count == 1
        assert diff.existing_count == 0

    def test_compare_identifies_existing(self, sample_finding: Finding):
        """Should identify existing findings."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding],
        )

        diff = manager.compare([sample_finding], baseline)

        assert diff.new_count == 0
        assert diff.existing_count == 1

    def test_compare_identifies_resolved(self, sample_finding: Finding):
        """Should identify resolved findings."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding],
        )

        # Compare with empty findings list
        diff = manager.compare([], baseline)

        assert diff.resolved_count == 1

    def test_compare_mixed(
        self, sample_finding: Finding, sample_source: TaintSpec, sample_sink: TaintSpec
    ):
        """Should handle mix of new, existing, and resolved."""
        manager = BaselineManager()

        # Create baseline with one finding
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding],
        )

        # Create a different finding
        new_finding = Finding(
            vulnerability_type="XSS",
            severity="medium",
            description="XSS vulnerability",
            source=sample_source,
            sink=sample_sink,
        )

        # Compare with both existing and new
        diff = manager.compare([sample_finding, new_finding], baseline)

        assert diff.existing_count == 1
        assert diff.new_count == 1


class TestUpdateBaseline:
    """Test updating baselines."""

    def test_update_adds_new_findings(
        self, sample_finding: Finding, sample_source: TaintSpec, sample_sink: TaintSpec
    ):
        """Should add new findings to baseline."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding],
        )
        original_count = baseline.count

        # Create new finding
        new_finding = Finding(
            vulnerability_type="XSS",
            severity="medium",
            description="XSS vulnerability",
            source=sample_source,
            sink=sample_sink,
        )

        updated = manager.update_baseline(
            baseline,
            [sample_finding, new_finding],
        )

        assert updated.count == original_count + 1

    def test_update_marks_resolved(self, sample_finding: Finding):
        """Should mark missing findings as resolved."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding],
        )

        # Get fingerprint
        fp = manager.fingerprint(sample_finding)

        # Update with empty list
        updated = manager.update_baseline(baseline, [])

        entry = updated.get_entry(fp)
        assert entry is not None
        assert entry.status == "resolved"

    def test_update_preserves_when_not_marking_resolved(self, sample_finding: Finding):
        """Should preserve status when not marking resolved."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding],
        )

        fp = manager.fingerprint(sample_finding)

        # Update with empty list but don't mark resolved
        updated = manager.update_baseline(baseline, [], mark_resolved=False)

        entry = updated.get_entry(fp)
        assert entry is not None
        assert entry.status == "active"

    def test_update_reactivates_resolved(
        self, sample_finding: Finding, sample_source: TaintSpec, sample_sink: TaintSpec
    ):
        """Should reactivate resolved findings if they reappear."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding],
        )

        fp = manager.fingerprint(sample_finding)

        # Mark as resolved
        manager.update_baseline(baseline, [])
        assert baseline.get_entry(fp).status == "resolved"

        # Reappear
        manager.update_baseline(baseline, [sample_finding])
        assert baseline.get_entry(fp).status == "active"


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_findings_list(self):
        """Should handle empty findings list."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[],
        )

        assert baseline.count == 0

    def test_finding_without_source(self, sample_sink: TaintSpec):
        """Should handle finding without source."""
        manager = BaselineManager()
        finding = Finding(
            vulnerability_type="HARDCODED_SECRET",
            severity="high",
            description="Hardcoded password",
            sink=sample_sink,
        )

        fingerprint = manager.fingerprint(finding)
        assert len(fingerprint) == 16

    def test_finding_without_sink(self, sample_source: TaintSpec):
        """Should handle finding without sink."""
        manager = BaselineManager()
        finding = Finding(
            vulnerability_type="INFO_LEAK",
            severity="low",
            description="Information disclosure",
            source=sample_source,
        )

        fingerprint = manager.fingerprint(finding)
        assert len(fingerprint) == 16

    def test_duplicate_fingerprints(self, sample_finding: Finding):
        """Should handle duplicate fingerprints in baseline."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="test",
            repository="my-repo",
            findings=[sample_finding, sample_finding],  # Same finding twice
        )

        # Should only have one entry
        assert baseline.count == 1
