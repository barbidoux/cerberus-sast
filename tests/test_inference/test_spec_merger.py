"""Tests for the spec merger."""

from __future__ import annotations

from pathlib import Path

import pytest

from cerberus.models.base import TaintLabel
from cerberus.models.spec import DynamicSpec, TaintSpec
from cerberus.verification.feedback import SpecUpdate
from cerberus.inference.spec_merger import (
    MergeConfig,
    MergeResult,
    SpecMerger,
    create_spec_from_feedback,
)


@pytest.fixture
def base_spec() -> DynamicSpec:
    """Create a base dynamic spec."""
    return DynamicSpec(
        sources=[
            TaintSpec(
                method="get_input",
                file_path=Path("src/input.py"),
                line=10,
                label=TaintLabel.SOURCE,
            ),
        ],
        sinks=[
            TaintSpec(
                method="execute",
                file_path=Path("src/db.py"),
                line=50,
                label=TaintLabel.SINK,
            ),
        ],
        sanitizers=[],
    )


@pytest.fixture
def sample_update() -> SpecUpdate:
    """Create a sample spec update."""
    return SpecUpdate(
        sanitizers=[
            TaintSpec(
                method="sanitize_input",
                file_path=Path("src/utils.py"),
                line=25,
                label=TaintLabel.SANITIZER,
                confidence=0.9,
            ),
        ],
    )


class TestMergeConfig:
    """Test MergeConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = MergeConfig()

        assert config.deduplicate_by_method is True
        assert config.deduplicate_by_location is True
        assert config.min_confidence_sanitizers == 0.5

    def test_custom_config(self):
        """Should accept custom values."""
        config = MergeConfig(
            min_confidence_sanitizers=0.8,
            max_sanitizers=10,
        )

        assert config.min_confidence_sanitizers == 0.8
        assert config.max_sanitizers == 10


class TestMergeResult:
    """Test MergeResult."""

    def test_total_added(self, base_spec: DynamicSpec):
        """Should calculate total added."""
        result = MergeResult(
            merged_spec=base_spec,
            sanitizers_added=2,
            sources_added=1,
            sinks_added=0,
        )

        assert result.total_added == 3

    def test_has_changes_true(self, base_spec: DynamicSpec):
        """Should detect changes."""
        result = MergeResult(
            merged_spec=base_spec,
            sanitizers_added=1,
        )

        assert result.has_changes is True

    def test_has_changes_false(self, base_spec: DynamicSpec):
        """Should detect no changes."""
        result = MergeResult(merged_spec=base_spec)

        assert result.has_changes is False


class TestSpecMerger:
    """Test SpecMerger."""

    def test_create_merger(self):
        """Should create merger with defaults."""
        merger = SpecMerger()

        assert merger.config is not None

    def test_create_with_config(self):
        """Should accept custom config."""
        config = MergeConfig(min_confidence_sanitizers=0.9)
        merger = SpecMerger(config=config)

        assert merger.config.min_confidence_sanitizers == 0.9


class TestMergeSanitizers:
    """Test merging sanitizers."""

    def test_merge_adds_sanitizers(
        self,
        base_spec: DynamicSpec,
        sample_update: SpecUpdate,
    ):
        """Should add new sanitizers."""
        merger = SpecMerger()
        result = merger.merge(base_spec, sample_update)

        assert result.sanitizers_added == 1
        assert len(result.merged_spec.sanitizers) == 1

    def test_merge_skips_duplicates_by_method(
        self,
        base_spec: DynamicSpec,
    ):
        """Should skip duplicate by method name."""
        # Add a sanitizer
        base_spec.sanitizers.append(TaintSpec(
            method="existing_sanitizer",
            file_path=Path("src/utils.py"),
            line=10,
            label=TaintLabel.SANITIZER,
        ))

        # Try to add the same method
        update = SpecUpdate(
            sanitizers=[
                TaintSpec(
                    method="existing_sanitizer",
                    file_path=Path("other/file.py"),
                    line=99,
                    label=TaintLabel.SANITIZER,
                ),
            ]
        )

        merger = SpecMerger()
        result = merger.merge(base_spec, update)

        assert result.sanitizers_added == 0
        assert result.duplicates_skipped == 1

    def test_merge_skips_duplicates_by_location(
        self,
        base_spec: DynamicSpec,
    ):
        """Should skip duplicate by location."""
        # Add a sanitizer
        base_spec.sanitizers.append(TaintSpec(
            method="sanitizer1",
            file_path=Path("src/utils.py"),
            line=10,
            label=TaintLabel.SANITIZER,
        ))

        # Try to add at the same location
        update = SpecUpdate(
            sanitizers=[
                TaintSpec(
                    method="different_name",
                    file_path=Path("src/utils.py"),
                    line=10,
                    label=TaintLabel.SANITIZER,
                ),
            ]
        )

        merger = SpecMerger()
        result = merger.merge(base_spec, update)

        assert result.sanitizers_added == 0
        assert result.duplicates_skipped == 1

    def test_merge_filters_low_confidence(
        self,
        base_spec: DynamicSpec,
    ):
        """Should skip low confidence specs."""
        update = SpecUpdate(
            sanitizers=[
                TaintSpec(
                    method="low_conf_sanitizer",
                    file_path=Path("src/utils.py"),
                    line=25,
                    label=TaintLabel.SANITIZER,
                    confidence=0.3,  # Below default threshold
                ),
            ]
        )

        merger = SpecMerger()
        result = merger.merge(base_spec, update)

        assert result.sanitizers_added == 0
        assert result.low_confidence_skipped == 1

    def test_merge_respects_limit(
        self,
        base_spec: DynamicSpec,
    ):
        """Should respect max sanitizers limit."""
        update = SpecUpdate(
            sanitizers=[
                TaintSpec(
                    method=f"sanitizer_{i}",
                    file_path=Path(f"src/utils_{i}.py"),
                    line=i,
                    label=TaintLabel.SANITIZER,
                )
                for i in range(10)
            ]
        )

        config = MergeConfig(max_sanitizers=3)
        merger = SpecMerger(config=config)
        result = merger.merge(base_spec, update)

        assert result.sanitizers_added == 3
        assert len(result.merged_spec.sanitizers) == 3


class TestMergeSources:
    """Test merging sources."""

    def test_merge_adds_sources(self, base_spec: DynamicSpec):
        """Should add new sources."""
        update = SpecUpdate(
            sources=[
                TaintSpec(
                    method="new_source",
                    file_path=Path("src/api.py"),
                    line=30,
                    label=TaintLabel.SOURCE,
                ),
            ]
        )

        merger = SpecMerger()
        result = merger.merge(base_spec, update)

        assert result.sources_added == 1
        assert len(result.merged_spec.sources) == 2


class TestMergeSinks:
    """Test merging sinks."""

    def test_merge_adds_sinks(self, base_spec: DynamicSpec):
        """Should add new sinks."""
        update = SpecUpdate(
            sinks=[
                TaintSpec(
                    method="new_sink",
                    file_path=Path("src/output.py"),
                    line=40,
                    label=TaintLabel.SINK,
                ),
            ]
        )

        merger = SpecMerger()
        result = merger.merge(base_spec, update)

        assert result.sinks_added == 1
        assert len(result.merged_spec.sinks) == 2


class TestMergeMultiple:
    """Test merging multiple updates."""

    def test_merge_multiple_updates(self, base_spec: DynamicSpec):
        """Should merge multiple updates sequentially."""
        updates = [
            SpecUpdate(
                sanitizers=[
                    TaintSpec(
                        method="sanitizer_1",
                        file_path=Path("src/utils.py"),
                        line=10,
                        label=TaintLabel.SANITIZER,
                    ),
                ]
            ),
            SpecUpdate(
                sanitizers=[
                    TaintSpec(
                        method="sanitizer_2",
                        file_path=Path("src/utils.py"),
                        line=20,
                        label=TaintLabel.SANITIZER,
                    ),
                ]
            ),
        ]

        merger = SpecMerger()
        result = merger.merge_multiple(base_spec, updates)

        assert result.sanitizers_added == 2
        assert len(result.merged_spec.sanitizers) == 2

    def test_merge_multiple_accumulates_skipped(self, base_spec: DynamicSpec):
        """Should accumulate skipped counts across updates."""
        # Add a sanitizer first
        base_spec.sanitizers.append(TaintSpec(
            method="existing",
            file_path=Path("src/utils.py"),
            line=10,
            label=TaintLabel.SANITIZER,
        ))

        # Try to add duplicates
        updates = [
            SpecUpdate(
                sanitizers=[
                    TaintSpec(method="existing", file_path=Path("a.py"), line=1, label=TaintLabel.SANITIZER),
                ]
            ),
            SpecUpdate(
                sanitizers=[
                    TaintSpec(method="existing", file_path=Path("b.py"), line=2, label=TaintLabel.SANITIZER),
                ]
            ),
        ]

        merger = SpecMerger()
        result = merger.merge_multiple(base_spec, updates)

        assert result.duplicates_skipped == 2


class TestConvenienceFunction:
    """Test the convenience function."""

    def test_create_spec_from_feedback(
        self,
        base_spec: DynamicSpec,
        sample_update: SpecUpdate,
    ):
        """Should merge using convenience function."""
        merged, result = create_spec_from_feedback(base_spec, sample_update)

        assert len(merged.sanitizers) == 1
        assert result.sanitizers_added == 1

    def test_create_spec_with_config(
        self,
        base_spec: DynamicSpec,
        sample_update: SpecUpdate,
    ):
        """Should accept config in convenience function."""
        config = MergeConfig(min_confidence_sanitizers=0.95)
        merged, result = create_spec_from_feedback(base_spec, sample_update, config)

        # 0.9 confidence is below 0.95 threshold
        assert result.sanitizers_added == 0


class TestEdgeCases:
    """Test edge cases."""

    def test_merge_empty_update(self, base_spec: DynamicSpec):
        """Should handle empty updates."""
        update = SpecUpdate()

        merger = SpecMerger()
        result = merger.merge(base_spec, update)

        assert result.total_added == 0
        assert result.has_changes is False

    def test_merge_empty_base(self):
        """Should handle empty base spec."""
        base = DynamicSpec(sources=[], sinks=[], sanitizers=[])
        update = SpecUpdate(
            sanitizers=[
                TaintSpec(
                    method="sanitizer",
                    file_path=Path("src/utils.py"),
                    line=10,
                    label=TaintLabel.SANITIZER,
                ),
            ]
        )

        merger = SpecMerger()
        result = merger.merge(base, update)

        assert result.sanitizers_added == 1

    def test_merge_preserves_original(self, base_spec: DynamicSpec):
        """Should not lose existing specs."""
        original_source_count = len(base_spec.sources)
        original_sink_count = len(base_spec.sinks)

        update = SpecUpdate(
            sanitizers=[
                TaintSpec(
                    method="new_sanitizer",
                    file_path=Path("src/utils.py"),
                    line=10,
                    label=TaintLabel.SANITIZER,
                ),
            ]
        )

        merger = SpecMerger()
        result = merger.merge(base_spec, update)

        assert len(result.merged_spec.sources) == original_source_count
        assert len(result.merged_spec.sinks) == original_sink_count
