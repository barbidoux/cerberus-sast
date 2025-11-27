"""
Tests for Spec Writer.

TDD: Write tests first, then implement to make them pass.
"""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cerberus.inference.spec_writer import (
    SpecWriter,
    SpecWriterConfig,
)
from cerberus.models.base import TaintLabel
from cerberus.models.spec import DynamicSpec, TaintSpec


@pytest.fixture
def sample_spec() -> DynamicSpec:
    """Create a sample DynamicSpec."""
    spec = DynamicSpec(
        repository="test-repo",
        generated_at=datetime.now(timezone.utc),
    )
    spec.add_source(TaintSpec(
        method="get_user_input",
        file_path=Path("/app/handlers.py"),
        line=10,
        label=TaintLabel.SOURCE,
        confidence=0.95,
        reason="Reads user input",
        vulnerability_types=["CWE-89", "CWE-79"],
    ))
    spec.add_sink(TaintSpec(
        method="execute_query",
        file_path=Path("/app/database.py"),
        line=25,
        label=TaintLabel.SINK,
        confidence=0.9,
        reason="Executes SQL",
        vulnerability_types=["CWE-89"],
    ))
    spec.add_sanitizer(TaintSpec(
        method="escape_html",
        file_path=Path("/app/utils.py"),
        line=5,
        label=TaintLabel.SANITIZER,
        confidence=0.85,
        reason="Escapes HTML",
        vulnerability_types=["CWE-79"],
    ))
    return spec


@pytest.fixture
def temp_dir():
    """Create a temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestSpecWriterConfig:
    """Test SpecWriterConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = SpecWriterConfig()
        assert config.output_filename == "context_rules.json"
        assert config.pretty_print is True
        assert config.backup_existing is True

    def test_custom_config(self):
        """Should accept custom values."""
        config = SpecWriterConfig(
            output_filename="custom_rules.json",
            pretty_print=False,
            backup_existing=False,
        )
        assert config.output_filename == "custom_rules.json"
        assert config.pretty_print is False


class TestSpecWriter:
    """Test SpecWriter class."""

    def test_create_writer(self):
        """Should create writer instance."""
        writer = SpecWriter()
        assert writer is not None

    def test_create_writer_with_config(self):
        """Should accept custom configuration."""
        config = SpecWriterConfig(pretty_print=False)
        writer = SpecWriter(config=config)
        assert writer.config.pretty_print is False

    def test_write_to_file(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should write spec to file."""
        writer = SpecWriter()
        output_path = writer.write(sample_spec, temp_dir)

        assert output_path.exists()
        assert output_path.name == "context_rules.json"

    def test_writes_valid_json(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should write valid JSON."""
        writer = SpecWriter()
        output_path = writer.write(sample_spec, temp_dir)

        with open(output_path) as f:
            data = json.load(f)

        assert isinstance(data, dict)
        assert "sources" in data
        assert "sinks" in data
        assert "sanitizers" in data

    def test_includes_all_specs(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should include all specs in output."""
        writer = SpecWriter()
        output_path = writer.write(sample_spec, temp_dir)

        with open(output_path) as f:
            data = json.load(f)

        assert len(data["sources"]) == 1
        assert len(data["sinks"]) == 1
        assert len(data["sanitizers"]) == 1

    def test_includes_metadata(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should include metadata in output."""
        writer = SpecWriter()
        output_path = writer.write(sample_spec, temp_dir)

        with open(output_path) as f:
            data = json.load(f)

        assert "repository" in data
        assert "generated_at" in data
        assert "version" in data

    def test_custom_output_filename(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should use custom output filename."""
        config = SpecWriterConfig(output_filename="my_rules.json")
        writer = SpecWriter(config=config)
        output_path = writer.write(sample_spec, temp_dir)

        assert output_path.name == "my_rules.json"


class TestSpecWriterBackup:
    """Test backup functionality."""

    def test_creates_backup_when_exists(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should backup existing file."""
        config = SpecWriterConfig(backup_existing=True)
        writer = SpecWriter(config=config)

        # Write initial file
        writer.write(sample_spec, temp_dir)

        # Modify spec
        sample_spec.add_source(TaintSpec(
            method="another_source",
            file_path=Path("/app/new.py"),
            line=1,
            label=TaintLabel.SOURCE,
            confidence=0.8,
        ))

        # Write again
        writer.write(sample_spec, temp_dir)

        # Check for backup
        backups = list(temp_dir.glob("context_rules.*.backup.json"))
        assert len(backups) >= 1

    def test_no_backup_when_disabled(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should not backup when disabled."""
        config = SpecWriterConfig(backup_existing=False)
        writer = SpecWriter(config=config)

        # Write twice
        writer.write(sample_spec, temp_dir)
        writer.write(sample_spec, temp_dir)

        # Should not have backups
        backups = list(temp_dir.glob("*.backup.json"))
        assert len(backups) == 0


class TestSpecWriterMerge:
    """Test merging with existing specs."""

    def test_merge_with_existing(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should merge with existing specs."""
        writer = SpecWriter()

        # Write initial spec
        writer.write(sample_spec, temp_dir)

        # Create new spec with additional items
        new_spec = DynamicSpec(repository="test-repo")
        new_spec.add_source(TaintSpec(
            method="new_source",
            file_path=Path("/app/new.py"),
            line=1,
            label=TaintLabel.SOURCE,
            confidence=0.9,
        ))

        # Merge and write
        output_path = writer.write(new_spec, temp_dir, merge_existing=True)

        with open(output_path) as f:
            data = json.load(f)

        # Should have both original and new sources
        assert len(data["sources"]) == 2

    def test_merge_deduplicates(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should deduplicate when merging."""
        writer = SpecWriter()

        # Write initial spec
        writer.write(sample_spec, temp_dir)

        # Try to add same source again
        same_spec = DynamicSpec(repository="test-repo")
        same_spec.add_source(TaintSpec(
            method="get_user_input",
            file_path=Path("/app/handlers.py"),
            line=10,
            label=TaintLabel.SOURCE,
            confidence=0.95,
        ))

        # Merge and write
        output_path = writer.write(same_spec, temp_dir, merge_existing=True)

        with open(output_path) as f:
            data = json.load(f)

        # Should not have duplicate
        assert len(data["sources"]) == 1


class TestSpecWriterLoad:
    """Test loading specs from file."""

    def test_load_from_file(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should load spec from file."""
        writer = SpecWriter()
        output_path = writer.write(sample_spec, temp_dir)

        loaded_spec = writer.load(output_path)

        assert isinstance(loaded_spec, DynamicSpec)
        assert len(loaded_spec.sources) == 1
        assert len(loaded_spec.sinks) == 1

    def test_load_nonexistent_returns_empty(self, temp_dir: Path):
        """Should return empty spec for nonexistent file."""
        writer = SpecWriter()
        loaded_spec = writer.load(temp_dir / "nonexistent.json")

        assert isinstance(loaded_spec, DynamicSpec)
        assert loaded_spec.total_specs == 0


class TestSpecWriterFormat:
    """Test output format."""

    def test_pretty_print(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should pretty print when configured."""
        config = SpecWriterConfig(pretty_print=True)
        writer = SpecWriter(config=config)
        output_path = writer.write(sample_spec, temp_dir)

        content = output_path.read_text()
        # Pretty print has newlines and indentation
        assert "\n" in content
        assert "  " in content

    def test_compact_format(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should use compact format when configured."""
        config = SpecWriterConfig(pretty_print=False)
        writer = SpecWriter(config=config)
        output_path = writer.write(sample_spec, temp_dir)

        content = output_path.read_text()
        # Compact format has no extra whitespace
        lines = [l for l in content.split("\n") if l.strip()]
        assert len(lines) == 1  # All on one line


class TestSpecWriterValidation:
    """Test spec validation."""

    def test_validates_output(self, sample_spec: DynamicSpec, temp_dir: Path):
        """Should produce valid spec that can be reloaded."""
        writer = SpecWriter()
        output_path = writer.write(sample_spec, temp_dir)

        # Should be able to reload
        loaded = writer.load(output_path)

        assert loaded.sources[0].method == "get_user_input"
        assert loaded.sinks[0].method == "execute_query"
        assert loaded.sanitizers[0].method == "escape_html"
