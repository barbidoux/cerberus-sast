"""
Spec Merger for Feedback Loop Integration.

Merges SpecUpdates from the Verification phase back into
the DynamicSpec for improved detection accuracy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cerberus.models.base import TaintLabel
from cerberus.models.spec import DynamicSpec, TaintSpec
from cerberus.verification.feedback import SpecUpdate


@dataclass
class MergeConfig:
    """Configuration for spec merging."""

    # Deduplication settings
    deduplicate_by_method: bool = True
    deduplicate_by_location: bool = True

    # Confidence thresholds
    min_confidence_sanitizers: float = 0.5
    min_confidence_sources: float = 0.6
    min_confidence_sinks: float = 0.6

    # Limits
    max_sanitizers: Optional[int] = None
    max_sources: Optional[int] = None
    max_sinks: Optional[int] = None


@dataclass
class MergeResult:
    """Result of merging specs."""

    merged_spec: DynamicSpec
    sanitizers_added: int = 0
    sources_added: int = 0
    sinks_added: int = 0
    duplicates_skipped: int = 0
    low_confidence_skipped: int = 0

    @property
    def total_added(self) -> int:
        """Total specs added."""
        return self.sanitizers_added + self.sources_added + self.sinks_added

    @property
    def has_changes(self) -> bool:
        """Check if any changes were made."""
        return self.total_added > 0


class SpecMerger:
    """
    Merges SpecUpdates into DynamicSpec.

    Handles:
    - Deduplication (avoid adding duplicate specs)
    - Confidence filtering (skip low confidence specs)
    - Limits (cap total number of each type)
    """

    def __init__(self, config: Optional[MergeConfig] = None) -> None:
        """
        Initialize the spec merger.

        Args:
            config: Merge configuration.
        """
        self.config = config or MergeConfig()

    def merge(
        self,
        base_spec: DynamicSpec,
        updates: SpecUpdate,
    ) -> MergeResult:
        """
        Merge spec updates into base spec.

        Args:
            base_spec: The original dynamic spec.
            updates: Updates to merge in.

        Returns:
            MergeResult with merged spec and statistics.
        """
        result = MergeResult(merged_spec=base_spec)

        # Merge sanitizers
        sanitizer_stats = self._merge_specs(
            existing=base_spec.sanitizers,
            updates=updates.sanitizers,
            min_confidence=self.config.min_confidence_sanitizers,
            max_count=self.config.max_sanitizers,
        )
        result.sanitizers_added = sanitizer_stats["added"]
        result.duplicates_skipped += sanitizer_stats["duplicates"]
        result.low_confidence_skipped += sanitizer_stats["low_confidence"]

        # Merge sources
        source_stats = self._merge_specs(
            existing=base_spec.sources,
            updates=updates.sources,
            min_confidence=self.config.min_confidence_sources,
            max_count=self.config.max_sources,
        )
        result.sources_added = source_stats["added"]
        result.duplicates_skipped += source_stats["duplicates"]
        result.low_confidence_skipped += source_stats["low_confidence"]

        # Merge sinks
        sink_stats = self._merge_specs(
            existing=base_spec.sinks,
            updates=updates.sinks,
            min_confidence=self.config.min_confidence_sinks,
            max_count=self.config.max_sinks,
        )
        result.sinks_added = sink_stats["added"]
        result.duplicates_skipped += sink_stats["duplicates"]
        result.low_confidence_skipped += sink_stats["low_confidence"]

        return result

    def _merge_specs(
        self,
        existing: list[TaintSpec],
        updates: list[TaintSpec],
        min_confidence: float,
        max_count: Optional[int],
    ) -> dict[str, int]:
        """
        Merge a list of spec updates into existing specs.

        Args:
            existing: Existing spec list (will be modified in place).
            updates: Updates to add.
            min_confidence: Minimum confidence threshold.
            max_count: Maximum number of specs to keep.

        Returns:
            Dictionary with add statistics.
        """
        stats = {"added": 0, "duplicates": 0, "low_confidence": 0}

        for update in updates:
            # Check confidence threshold
            confidence = getattr(update, 'confidence', 1.0) or 1.0
            if confidence < min_confidence:
                stats["low_confidence"] += 1
                continue

            # Check for duplicates
            if self._is_duplicate(existing, update):
                stats["duplicates"] += 1
                continue

            # Check limit
            if max_count is not None and len(existing) >= max_count:
                break

            # Add the update
            existing.append(update)
            stats["added"] += 1

        return stats

    def _is_duplicate(self, existing: list[TaintSpec], candidate: TaintSpec) -> bool:
        """
        Check if a spec is a duplicate of an existing one.

        Args:
            existing: List of existing specs.
            candidate: Candidate spec to check.

        Returns:
            True if duplicate, False otherwise.
        """
        for spec in existing:
            # Check method name
            if self.config.deduplicate_by_method:
                if spec.method == candidate.method:
                    return True

            # Check location (file + line)
            if self.config.deduplicate_by_location:
                if (spec.file_path == candidate.file_path and
                    spec.line == candidate.line):
                    return True

        return False

    def merge_multiple(
        self,
        base_spec: DynamicSpec,
        updates_list: list[SpecUpdate],
    ) -> MergeResult:
        """
        Merge multiple updates sequentially.

        Args:
            base_spec: The original dynamic spec.
            updates_list: List of updates to merge.

        Returns:
            Combined MergeResult.
        """
        combined_result = MergeResult(merged_spec=base_spec)

        for updates in updates_list:
            result = self.merge(combined_result.merged_spec, updates)
            combined_result.sanitizers_added += result.sanitizers_added
            combined_result.sources_added += result.sources_added
            combined_result.sinks_added += result.sinks_added
            combined_result.duplicates_skipped += result.duplicates_skipped
            combined_result.low_confidence_skipped += result.low_confidence_skipped

        return combined_result


def create_spec_from_feedback(
    original_spec: DynamicSpec,
    updates: SpecUpdate,
    config: Optional[MergeConfig] = None,
) -> tuple[DynamicSpec, MergeResult]:
    """
    Convenience function to merge feedback into a spec.

    Args:
        original_spec: Original dynamic spec.
        updates: Updates from verification feedback.
        config: Optional merge configuration.

    Returns:
        Tuple of (merged spec, merge result).
    """
    merger = SpecMerger(config=config)
    result = merger.merge(original_spec, updates)
    return result.merged_spec, result
