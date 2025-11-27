"""
Tests for LLM Classifier.

TDD: Write tests first, then implement to make them pass.
"""

from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cerberus.inference.candidate_extractor import Candidate, CandidateType
from cerberus.inference.classifier import (
    ClassificationResult,
    LLMClassifier,
    ClassifierConfig,
)
from cerberus.llm.providers.models import LLMResponse
from cerberus.models.base import SymbolType, TaintLabel
from cerberus.models.repo_map import Symbol
from cerberus.models.spec import TaintSpec


@pytest.fixture
def sample_candidate() -> Candidate:
    """Create a sample candidate for testing."""
    return Candidate(
        symbol=Symbol(
            name="get_user_input",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/handlers.py"),
            line=10,
            signature="def get_user_input(request):",
        ),
        candidate_type=CandidateType.SOURCE,
        score=0.8,
        reason="Name pattern matches source heuristic",
    )


@pytest.fixture
def sample_sink_candidate() -> Candidate:
    """Create a sample sink candidate."""
    return Candidate(
        symbol=Symbol(
            name="execute_query",
            type=SymbolType.FUNCTION,
            file_path=Path("/app/database.py"),
            line=25,
            signature="def execute_query(sql, params=None):",
        ),
        candidate_type=CandidateType.SINK,
        score=0.9,
        reason="Name pattern matches sink heuristic",
    )


def make_llm_response(content: str) -> LLMResponse:
    """Helper to create LLMResponse with correct parameters."""
    return LLMResponse(
        content=content,
        model="test-model",
        provider="test",
        input_tokens=100,
        output_tokens=50,
        finish_reason="stop",
    )


@pytest.fixture
def mock_llm_response() -> LLMResponse:
    """Create a mock LLM response with classification."""
    return make_llm_response('''{
            "label": "SOURCE",
            "confidence": 0.95,
            "reason": "This function reads user input from HTTP request parameters",
            "vulnerability_types": ["CWE-89", "CWE-79"]
        }''')


class TestClassificationResult:
    """Test ClassificationResult dataclass."""

    def test_create_result(self):
        """Should create classification result."""
        result = ClassificationResult(
            candidate=Candidate(
                symbol=Symbol(
                    name="func",
                    type=SymbolType.FUNCTION,
                    file_path=Path("/test.py"),
                    line=1,
                ),
                candidate_type=CandidateType.SOURCE,
                score=0.8,
            ),
            confirmed=True,
            label=TaintLabel.SOURCE,
            confidence=0.95,
            reason="Reads from request",
            vulnerability_types=["CWE-89"],
        )
        assert result.confirmed is True
        assert result.label == TaintLabel.SOURCE
        assert result.confidence == 0.95

    def test_to_taint_spec(self):
        """Should convert to TaintSpec when confirmed."""
        candidate = Candidate(
            symbol=Symbol(
                name="get_input",
                type=SymbolType.FUNCTION,
                file_path=Path("/app/api.py"),
                line=15,
            ),
            candidate_type=CandidateType.SOURCE,
            score=0.8,
        )
        result = ClassificationResult(
            candidate=candidate,
            confirmed=True,
            label=TaintLabel.SOURCE,
            confidence=0.9,
            reason="Reads user input",
            vulnerability_types=["CWE-79"],
        )

        spec = result.to_taint_spec()

        assert isinstance(spec, TaintSpec)
        assert spec.method == "get_input"
        assert spec.label == TaintLabel.SOURCE
        assert spec.confidence == 0.9
        assert "CWE-79" in spec.vulnerability_types

    def test_to_taint_spec_returns_none_when_not_confirmed(self):
        """Should return None when not confirmed."""
        result = ClassificationResult(
            candidate=Candidate(
                symbol=Symbol(
                    name="func",
                    type=SymbolType.FUNCTION,
                    file_path=Path("/test.py"),
                    line=1,
                ),
                candidate_type=CandidateType.SOURCE,
                score=0.5,
            ),
            confirmed=False,
            label=TaintLabel.NONE,
            confidence=0.3,
            reason="Not a source",
        )

        assert result.to_taint_spec() is None


class TestClassifierConfig:
    """Test ClassifierConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = ClassifierConfig()
        assert config.min_confidence > 0.0
        assert config.batch_size > 0
        assert config.include_code_context is True

    def test_custom_config(self):
        """Should accept custom values."""
        config = ClassifierConfig(
            min_confidence=0.8,
            batch_size=5,
            include_code_context=False,
        )
        assert config.min_confidence == 0.8
        assert config.batch_size == 5
        assert config.include_code_context is False


class TestLLMClassifier:
    """Test LLMClassifier class."""

    def test_create_classifier(self):
        """Should create classifier instance."""
        classifier = LLMClassifier()
        assert classifier is not None

    def test_create_classifier_with_config(self):
        """Should accept custom configuration."""
        config = ClassifierConfig(min_confidence=0.9)
        classifier = LLMClassifier(config=config)
        assert classifier.config.min_confidence == 0.9

    @pytest.mark.asyncio
    async def test_classify_candidate(
        self,
        sample_candidate: Candidate,
        mock_llm_response: LLMResponse,
    ):
        """Should classify a single candidate."""
        classifier = LLMClassifier()

        # Mock the LLM gateway
        with patch.object(classifier, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_llm_response

            result = await classifier.classify(sample_candidate)

            assert isinstance(result, ClassificationResult)
            assert result.label == TaintLabel.SOURCE
            assert result.confidence == 0.95
            mock_call.assert_called_once()

    @pytest.mark.asyncio
    async def test_classify_confirms_matching_type(
        self,
        sample_candidate: Candidate,
        mock_llm_response: LLMResponse,
    ):
        """Should confirm when LLM agrees with heuristic."""
        classifier = LLMClassifier()

        with patch.object(classifier, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_llm_response

            result = await classifier.classify(sample_candidate)

            # Candidate type is SOURCE, LLM says SOURCE
            assert result.confirmed is True

    @pytest.mark.asyncio
    async def test_classify_rejects_non_matching_type(
        self,
        sample_candidate: Candidate,
    ):
        """Should not confirm when LLM disagrees with heuristic."""
        classifier = LLMClassifier()

        # LLM says NONE instead of SOURCE
        mock_response = make_llm_response(
            '{"label": "NONE", "confidence": 0.8, "reason": "Just a helper", "vulnerability_types": []}'
        )

        with patch.object(classifier, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_response

            result = await classifier.classify(sample_candidate)

            assert result.confirmed is False
            assert result.label == TaintLabel.NONE

    @pytest.mark.asyncio
    async def test_classify_handles_low_confidence(
        self,
        sample_candidate: Candidate,
    ):
        """Should not confirm when confidence is below threshold."""
        config = ClassifierConfig(min_confidence=0.8)
        classifier = LLMClassifier(config=config)

        # LLM response with low confidence
        mock_response = make_llm_response(
            '{"label": "SOURCE", "confidence": 0.6, "reason": "Maybe a source", "vulnerability_types": []}'
        )

        with patch.object(classifier, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_response

            result = await classifier.classify(sample_candidate)

            # Below min_confidence, so not confirmed
            assert result.confirmed is False

    @pytest.mark.asyncio
    async def test_classify_batch(
        self,
        sample_candidate: Candidate,
        sample_sink_candidate: Candidate,
    ):
        """Should classify multiple candidates."""
        classifier = LLMClassifier()

        source_response = make_llm_response(
            '{"label": "SOURCE", "confidence": 0.9, "reason": "Source", "vulnerability_types": ["CWE-89"]}'
        )
        sink_response = make_llm_response(
            '{"label": "SINK", "confidence": 0.95, "reason": "Sink", "vulnerability_types": ["CWE-89"]}'
        )

        with patch.object(classifier, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.side_effect = [source_response, sink_response]

            results = await classifier.classify_batch([sample_candidate, sample_sink_candidate])

            assert len(results) == 2
            assert results[0].label == TaintLabel.SOURCE
            assert results[1].label == TaintLabel.SINK

    @pytest.mark.asyncio
    async def test_classify_handles_llm_error(
        self,
        sample_candidate: Candidate,
    ):
        """Should handle LLM errors gracefully."""
        classifier = LLMClassifier()

        with patch.object(classifier, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.side_effect = Exception("LLM unavailable")

            result = await classifier.classify(sample_candidate)

            assert result.confirmed is False
            assert "error" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_classify_parses_malformed_response(
        self,
        sample_candidate: Candidate,
    ):
        """Should handle malformed LLM responses."""
        classifier = LLMClassifier()

        # Malformed JSON response
        mock_response = make_llm_response("This is not valid JSON")

        with patch.object(classifier, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_response

            result = await classifier.classify(sample_candidate)

            # Should still return a result, just not confirmed
            assert isinstance(result, ClassificationResult)
            assert result.confirmed is False


class TestClassifierWithCodeContext:
    """Test classifier with code context extraction."""

    @pytest.mark.asyncio
    async def test_includes_code_context_when_configured(
        self,
        sample_candidate: Candidate,
        mock_llm_response: LLMResponse,
    ):
        """Should include code context in prompt when configured."""
        config = ClassifierConfig(include_code_context=True)
        classifier = LLMClassifier(config=config)

        with patch.object(classifier, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_llm_response

            await classifier.classify(sample_candidate, code_snippet="def get_user_input(request):\n    return request.args")

            # Check that code was included in the call
            call_args = mock_call.call_args
            assert call_args is not None


class TestClassifierStatistics:
    """Test classifier statistics tracking."""

    @pytest.mark.asyncio
    async def test_tracks_classification_stats(
        self,
        sample_candidate: Candidate,
        mock_llm_response: LLMResponse,
    ):
        """Should track classification statistics."""
        classifier = LLMClassifier()

        with patch.object(classifier, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_llm_response

            await classifier.classify(sample_candidate)

            stats = classifier.get_stats()
            assert "total_classifications" in stats
            assert stats["total_classifications"] == 1

    @pytest.mark.asyncio
    async def test_tracks_confirmed_count(
        self,
        sample_candidate: Candidate,
        mock_llm_response: LLMResponse,
    ):
        """Should track confirmed classification count."""
        classifier = LLMClassifier()

        with patch.object(classifier, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_llm_response

            await classifier.classify(sample_candidate)

            stats = classifier.get_stats()
            assert stats["confirmed_count"] == 1


class TestMultiLabelClassification:
    """Test multi-label classification (when candidate type is uncertain)."""

    @pytest.mark.asyncio
    async def test_classify_multi_label(self, sample_candidate: Candidate):
        """Should support multi-label classification mode."""
        classifier = LLMClassifier()

        # Response that identifies multiple potential labels
        mock_response = make_llm_response(
            '{"label": "SOURCE", "confidence": 0.9, "reason": "Reads input", "vulnerability_types": ["CWE-89"]}'
        )

        with patch.object(classifier, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_response

            result = await classifier.classify_any(sample_candidate)

            assert isinstance(result, ClassificationResult)
            assert result.label in [TaintLabel.SOURCE, TaintLabel.SINK, TaintLabel.SANITIZER, TaintLabel.PROPAGATOR, TaintLabel.NONE]
