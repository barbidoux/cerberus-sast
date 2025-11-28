"""Tests for CodeBERT classifier."""

import pytest
from unittest.mock import MagicMock, patch

from cerberus.ml.codebert_classifier import (
    CodeBERTClassifier,
    ClassificationResult,
)
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
    source.source_type = SourceType.REQUEST_QUERY
    source.file_path = "/test/app.js"
    source.line = 10

    sink = MagicMock(spec=TaintSink)
    sink.expression = sink_expr
    sink.sink_type = SinkType.SQL_QUERY
    sink.cwe_types = set(cwe_types or ["CWE-89"])
    sink.uses_template_literal = uses_template_literal
    sink.file_path = "/test/app.js"
    sink.line = 10 + distance_lines
    # Extract callee from expression (e.g., "db.query(...)" -> "query")
    sink.callee = sink_expr.split("(")[0].split(".")[-1] if "(" in sink_expr else sink_expr

    candidate = MagicMock(spec=TaintFlowCandidate)
    candidate.source = source
    candidate.sink = sink
    candidate.in_same_function = in_same_function
    candidate.in_same_file = in_same_file
    candidate.distance_lines = distance_lines
    candidate.confidence = confidence
    candidate.shared_cwe_types = cwe_types or ["CWE-89"]
    candidate.code_context = ""

    return candidate


class TestCodeBERTClassifierInit:
    """Tests for CodeBERTClassifier initialization."""

    def test_init_default(self):
        """Test default initialization uses fallback mode."""
        classifier = CodeBERTClassifier()

        # Without PyTorch installed, should use fallback
        assert classifier._use_fallback is True

    def test_init_custom_thresholds(self):
        """Test custom threshold initialization."""
        classifier = CodeBERTClassifier(
            vulnerable_threshold=0.9,
            safe_threshold=0.1,
        )

        assert classifier.VULNERABLE_THRESHOLD == 0.9
        assert classifier.SAFE_THRESHOLD == 0.1

    def test_is_available(self):
        """Test is_available returns correct status."""
        classifier = CodeBERTClassifier()

        # Should return False when using fallback
        assert classifier.is_available() is False

    def test_get_device(self):
        """Test get_device returns device info."""
        classifier = CodeBERTClassifier()

        device = classifier.get_device()
        assert "cpu" in device.lower()

    def test_get_metrics(self):
        """Test get_metrics returns configuration."""
        classifier = CodeBERTClassifier()

        metrics = classifier.get_metrics()
        assert "model_available" in metrics
        assert "device" in metrics
        assert "vulnerable_threshold" in metrics
        assert "safe_threshold" in metrics


class TestCodeBERTClassifierClassify:
    """Tests for classify methods."""

    def test_classify_single_candidate(self):
        """Test classifying a single candidate."""
        classifier = CodeBERTClassifier()
        candidate = create_mock_candidate()

        result = classifier.classify(candidate)

        assert isinstance(result, ClassificationResult)
        assert result.candidate == candidate
        assert 0.0 <= result.confidence <= 1.0
        assert result.decision in ("vulnerable", "safe", "uncertain")

    def test_classify_batch_empty(self):
        """Test classifying empty batch."""
        classifier = CodeBERTClassifier()

        results = classifier.classify_batch([])

        assert results == []

    def test_classify_batch_multiple(self):
        """Test classifying multiple candidates."""
        classifier = CodeBERTClassifier()
        candidates = [create_mock_candidate() for _ in range(5)]

        results = classifier.classify_batch(candidates)

        assert len(results) == 5
        assert all(isinstance(r, ClassificationResult) for r in results)


class TestCodeBERTClassifierHeuristic:
    """Tests for heuristic classification logic."""

    def test_heuristic_high_risk_boost(self):
        """Test high-risk patterns boost confidence."""
        classifier = CodeBERTClassifier()

        # High-risk candidate
        high_risk = create_mock_candidate(
            uses_template_literal=True,
            in_same_function=True,
            distance_lines=5,
            cwe_types=["CWE-78"],  # Command injection
            confidence=0.5,
        )

        result = classifier.classify(high_risk)

        # Should have boosted confidence
        assert result.confidence > 0.5

    def test_heuristic_safe_patterns_reduce(self):
        """Test safe patterns reduce confidence."""
        classifier = CodeBERTClassifier()

        # Safe candidate (logger sink)
        safe = create_mock_candidate(
            sink_expr="console.log",
            uses_template_literal=False,
            in_same_function=False,
            in_same_file=False,
            distance_lines=200,
            confidence=0.5,
        )

        result = classifier.classify(safe)

        # Should have reduced confidence
        assert result.confidence < 0.5

    def test_heuristic_cross_file_penalty(self):
        """Test cross-file flows get penalty."""
        classifier = CodeBERTClassifier()

        cross_file = create_mock_candidate(
            in_same_file=False,
            in_same_function=False,
            distance_lines=150,  # Long distance to trigger penalty
            confidence=0.5,
        )

        result = classifier.classify(cross_file)

        # Should have reduced confidence due to:
        # - cross-file: -0.2
        # - distance > 100: -0.3
        # - no high-risk indicators: -0.2
        # Total: 0.5 - 0.7 = capped at 0.0
        assert result.confidence < 0.5


class TestCodeBERTClassifierDecision:
    """Tests for decision thresholds."""

    def test_decision_vulnerable(self):
        """Test vulnerable decision for high confidence."""
        classifier = CodeBERTClassifier(
            vulnerable_threshold=0.75,
            safe_threshold=0.45,
        )

        decision = classifier._decide(0.8)
        assert decision == "vulnerable"

    def test_decision_safe(self):
        """Test safe decision for low confidence."""
        classifier = CodeBERTClassifier(
            vulnerable_threshold=0.75,
            safe_threshold=0.45,
        )

        decision = classifier._decide(0.3)
        assert decision == "safe"

    def test_decision_uncertain(self):
        """Test uncertain decision for middle confidence."""
        classifier = CodeBERTClassifier(
            vulnerable_threshold=0.75,
            safe_threshold=0.45,
        )

        decision = classifier._decide(0.6)
        assert decision == "uncertain"

    def test_decision_boundary_vulnerable(self):
        """Test boundary case for vulnerable threshold."""
        classifier = CodeBERTClassifier(
            vulnerable_threshold=0.75,
            safe_threshold=0.45,
        )

        decision = classifier._decide(0.75)
        assert decision == "vulnerable"

    def test_decision_boundary_safe(self):
        """Test boundary case for safe threshold."""
        classifier = CodeBERTClassifier(
            vulnerable_threshold=0.75,
            safe_threshold=0.45,
        )

        decision = classifier._decide(0.45)
        assert decision == "safe"


class TestClassificationResult:
    """Tests for ClassificationResult dataclass."""

    def test_result_creation(self):
        """Test ClassificationResult can be created."""
        candidate = create_mock_candidate()

        result = ClassificationResult(
            candidate=candidate,
            confidence=0.75,
            decision="vulnerable",
            reasoning="Test reasoning",
        )

        assert result.candidate == candidate
        assert result.confidence == 0.75
        assert result.decision == "vulnerable"
        assert result.reasoning == "Test reasoning"

    def test_result_default_reasoning(self):
        """Test ClassificationResult with default reasoning."""
        candidate = create_mock_candidate()

        result = ClassificationResult(
            candidate=candidate,
            confidence=0.5,
            decision="uncertain",
        )

        assert result.reasoning is None
