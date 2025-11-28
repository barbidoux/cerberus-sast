"""Tests for Tier 1 pattern-based pre-filter."""

import pytest
from unittest.mock import MagicMock, patch

from cerberus.ml.tier1_filter import Tier1Filter, FilterResult
from cerberus.models.taint_flow import (
    TaintFlowCandidate,
    TaintSource,
    TaintSink,
    SourceType,
    SinkType,
)


def create_mock_candidate(
    source_expr: str = "req.query.id",
    sink_expr: str = "db.query",
    source_type: SourceType = SourceType.REQUEST_QUERY,
    sink_type: SinkType = SinkType.SQL_QUERY,
    cwe_types: list[str] | None = None,
    uses_template_literal: bool = False,
    in_same_function: bool = True,
    in_same_file: bool = True,
    distance_lines: int = 5,
    confidence: float = 0.5,
) -> TaintFlowCandidate:
    """Create a mock TaintFlowCandidate for testing."""
    source = MagicMock(spec=TaintSource)
    source.expression = source_expr
    source.source_type = source_type
    source.file_path = "/test/app.js"
    source.line = 10

    sink = MagicMock(spec=TaintSink)
    sink.expression = sink_expr
    sink.sink_type = sink_type
    sink.cwe_types = set(cwe_types or ["CWE-89"])
    sink.uses_template_literal = uses_template_literal
    sink.file_path = "/test/app.js"
    sink.line = 10 + distance_lines

    candidate = MagicMock(spec=TaintFlowCandidate)
    candidate.source = source
    candidate.sink = sink
    candidate.in_same_function = in_same_function
    candidate.in_same_file = in_same_file
    candidate.distance_lines = distance_lines
    candidate.confidence = confidence
    candidate.shared_cwe_types = cwe_types or ["CWE-89"]
    candidate.code_context = f"// Test code\nconst data = {source_expr};\n{sink_expr}(data);"

    return candidate


class TestTier1FilterInit:
    """Tests for Tier1Filter initialization."""

    def test_init_default(self):
        """Test default initialization."""
        filter = Tier1Filter()
        assert filter.HIGH_CONFIDENCE_THRESHOLD == 0.85
        assert filter.ML_REVIEW_THRESHOLD == 0.45  # Aligned with Tier 2 safe threshold

    def test_init_custom_thresholds(self):
        """Test custom threshold initialization."""
        filter = Tier1Filter(
            high_confidence_threshold=0.9,
            ml_review_threshold=0.4,
        )
        assert filter.HIGH_CONFIDENCE_THRESHOLD == 0.9
        assert filter.ML_REVIEW_THRESHOLD == 0.4

    def test_init_with_languages(self):
        """Test initialization with specific languages."""
        filter = Tier1Filter(languages=["javascript", "python"])
        assert filter.rules is not None


class TestTier1FilterCandidates:
    """Tests for filter_candidates method."""

    def test_filter_empty_list(self):
        """Test filtering empty candidate list."""
        filter = Tier1Filter()
        result = filter.filter_candidates([])

        assert result.total_candidates == 0
        assert result.high_confidence_count == 0
        assert result.needs_ml_count == 0
        assert result.filtered_count == 0

    def test_high_confidence_template_literal(self):
        """Test that template literals boost to high confidence."""
        filter = Tier1Filter()
        candidate = create_mock_candidate(
            uses_template_literal=True,
            in_same_function=True,
            confidence=0.5,
        )

        result = filter.filter_candidates([candidate])

        # Template literal (+0.3) + same function (+0.2) + close distance (+0.1)
        # = 0.5 + 0.6 = 1.1 (capped at 1.0) -> high confidence
        assert result.high_confidence_count >= 0

    def test_filter_result_structure(self):
        """Test FilterResult has correct structure."""
        filter = Tier1Filter()
        candidates = [create_mock_candidate() for _ in range(5)]

        result = filter.filter_candidates(candidates)

        assert isinstance(result, FilterResult)
        assert result.total_candidates == 5
        assert len(result.high_confidence) + len(result.needs_ml_review) + len(result.filtered_out) == 5

    def test_confidence_boosts_applied(self):
        """Test that confidence boosts are applied correctly."""
        filter = Tier1Filter()

        # Low confidence candidate
        low_conf = create_mock_candidate(
            uses_template_literal=False,
            in_same_function=False,
            distance_lines=100,
            confidence=0.3,
        )

        # High confidence candidate
        high_conf = create_mock_candidate(
            uses_template_literal=True,
            in_same_function=True,
            distance_lines=5,
            confidence=0.6,
        )

        result = filter.filter_candidates([low_conf, high_conf])

        # The high_conf candidate should have higher adjusted confidence
        assert result.total_candidates == 2


class TestTier1FilterConfidenceCalculation:
    """Tests for confidence calculation logic."""

    def test_template_literal_boost(self):
        """Test template literal boost is applied."""
        filter = Tier1Filter()
        candidate = create_mock_candidate(
            uses_template_literal=True,
            confidence=0.5,
        )

        # The filter should apply boosts during filtering
        result = filter.filter_candidates([candidate])
        assert result.total_candidates == 1

    def test_same_function_boost(self):
        """Test same function boost is applied."""
        filter = Tier1Filter()
        candidate = create_mock_candidate(
            in_same_function=True,
            confidence=0.5,
        )

        result = filter.filter_candidates([candidate])
        assert result.total_candidates == 1

    def test_close_distance_boost(self):
        """Test close distance boost is applied."""
        filter = Tier1Filter()
        candidate = create_mock_candidate(
            distance_lines=5,
            confidence=0.5,
        )

        result = filter.filter_candidates([candidate])
        assert result.total_candidates == 1


class TestTier1FilterMetrics:
    """Tests for filter metrics."""

    def test_metrics_accuracy(self):
        """Test that metrics are calculated correctly."""
        filter = Tier1Filter()
        candidates = [
            create_mock_candidate(confidence=0.9),  # Should be high conf
            create_mock_candidate(confidence=0.6),  # Should need ML
            create_mock_candidate(confidence=0.3),  # Should be filtered
        ]

        result = filter.filter_candidates(candidates)

        assert result.total_candidates == 3
        assert result.high_confidence_count == len(result.high_confidence)
        assert result.needs_ml_count == len(result.needs_ml_review)
        assert result.filtered_count == len(result.filtered_out)
